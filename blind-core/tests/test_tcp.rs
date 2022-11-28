use std::{time::SystemTime, io::{BufReader, BufWriter, Write, Read}, net::{TcpListener, TcpStream}, thread, str::FromStr};

use bitcoin::{EcdsaSighashType, util::sighash::SighashCache, Txid, Address, secp256k1::Secp256k1, PublicKey, PrivateKey, hashes::hex::ToHex};
use blind_core::{bitcoin_rpc::Client, rsohc, transaction::{new_unsigned_transaction_funding_template, new_unsigned_transaction_timeout, new_unsigned_transaction_aed, new_unsigned_transaction_split_delivery}, channel::{ChannelUser, ChannelBlind}, hub::{ChannelSender, ChannelTumbler, ChannelReceiver}, encoder::encode_mpc_all, script::{new_split_delivery_script, new_commitment_script}};
use class_group::primitives::cl_dl_public_setup::{CLGroup, sample_prime_by_length};
use curv::{BigInt, arithmetic::Zero, elliptic::curves::{secp256_k1::{Secp256k1Point, Secp256k1Scalar}, ECPoint, ECScalar}};
use fancy_garbling::{circuit::Circuit, twopac::semihonest::{Evaluator, Garbler}, encode_boolean, decode_boolean, FancyInput};
use ocelot::ot::{NaorPinkasReceiver, NaorPinkasSender};
use scuttlebutt::{AesRng, TrackChannel};
use sha2::{Digest, Sha256};
use testcontainers::{images::coblox_bitcoincore::{BitcoinCoreImageArgs, BitcoinCore}, RunnableImage, clients};

const ADDRESS_SNDR: &str = "127.0.0.1:7070";
const ADDRESS_TMBL: &str = "127.0.0.1:7071";
const ADDRESS_RECV: &str = "127.0.0.1:7072";

#[test]
fn test_latency() {
    let listener = TcpListener::bind(ADDRESS_SNDR).unwrap();
    let time_total = SystemTime::now();
    let _ = std::thread::spawn(move || {
        let mut stream_r = listener.accept().unwrap().0;
        let time_write = SystemTime::now();
        stream_r.write(&[1u8]).unwrap();
        stream_r.flush().unwrap();
        println!("Write: {} ms", time_write.elapsed().unwrap().as_millis());
    });
    let mut stream_s = TcpStream::connect(ADDRESS_SNDR).unwrap();
    stream_s.read(&mut [0; 1]).unwrap();
    println!("Total: {} ms", time_total.elapsed().unwrap().as_millis());
}

fn run_circuit(circ: &mut Circuit, gb_inputs: Vec<u16>, ev_inputs: Vec<u16>) -> Result<Vec<u16>,()> {
    let circ_ = circ.clone();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let stream_st = TcpListener::bind(ADDRESS_SNDR).unwrap().accept().unwrap().0;
        stream_st.set_nodelay(true).unwrap();

        let channel = TrackChannel::new(
            BufReader::with_capacity(256000, stream_st.try_clone().unwrap()),
            BufWriter::with_capacity(256000, stream_st)
        );

        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb = Garbler::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasSender>::new(channel, rng).unwrap();
        println!(
            "Garbler :: Initialization: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let xs = gb.encode_many(&gb_inputs, &vec![2; n_gb_inputs]).unwrap();
        let ys = gb.receive_many(&vec![2; n_ev_inputs]).unwrap();
        println!(
            "Garbler :: Encoding inputs: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Garbler :: Network traffic read {} KB",
            gb.get_channel().kilobytes_read()
        );
        println!(
            "Garbler :: Network traffic wrote {} KB",
            gb.get_channel().kilobytes_written()
        );
        let start = SystemTime::now();
        circ_.eval(&mut gb, &xs, &ys).unwrap();
        println!(
            "Garbler :: Circuit garbling: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Garbler :: Network traffic read {} KB",
            gb.get_channel().kilobytes_read()
        );
        println!(
            "Garbler :: Network traffic wrote {} KB",
            gb.get_channel().kilobytes_written()
        );
    });
    thread::sleep(std::time::Duration::from_millis(200));
    let stream_sr = TcpStream::connect(ADDRESS_SNDR).unwrap();
    stream_sr.set_nodelay(true).unwrap();

    let channel = TrackChannel::new(
        BufReader::with_capacity(256000, stream_sr.try_clone().unwrap()),
        BufWriter::with_capacity(256000, stream_sr)
    );

    let rng = AesRng::new();
    let start = SystemTime::now();
    let mut ev = Evaluator::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasReceiver>::new(channel, rng).unwrap();
    println!(
        "Evaluator :: Initialization: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let xs = ev.receive_many(&vec![2; n_gb_inputs]).unwrap();
    let ys = ev.encode_many(&ev_inputs, &vec![2; n_ev_inputs]).unwrap();
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let result = circ.eval(&mut ev, &xs, &ys).unwrap();
    println!(
        "Evaluator :: Circuit evaluation: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    handle.join().unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis() - 200);
    return result.ok_or(());
}

#[test]
fn test_gc_all() {
    let dummy_txid: Txid = Txid::from_str("2df0ce8b422af8aa1a0ea5cf3f2db50d33a9355281897d1193fedbbda6e41c07").unwrap();
    let dummy_addr_user: Address = Address::from_str("bcrt1qxzgp4utr352vp7rq79k97q6nuf6c3emyrumz68").unwrap();
    let dummy_addr_blnd: Address = Address::from_str("bcrt1qun5x7r2ft88gdxltjfjl3m3n6537ps8sypfttm").unwrap();

    let secp = Secp256k1::default();
    let sk_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
    let sk_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
    let pk_sig_user = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_user.clone(), bitcoin::Network::Regtest));
    let pk_sig_blnd = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_blnd.clone(), bitcoin::Network::Regtest));

    let commitment_amount = 60_0000_0000_u64;
    let transfer_amount = 20_0000_0000_u64;
    let payback_amount_user = 19_9980_0000_u64;
    let payback_amount_blnd = 19_9980_0000_u64;
    let fee = 10_0000;
    
    let secp = Secp256k1::default();
    let rev_cred_user = PrivateKey::new(
        Secp256k1Scalar::random().underlying_ref().clone().unwrap().0,
        bitcoin::Network::Regtest
    );
    let rev_cred_blnd = PrivateKey::new(
        Secp256k1Scalar::random().underlying_ref().clone().unwrap().0,
        bitcoin::Network::Regtest
    );
    let sk_pub_user = PrivateKey::new(
        Secp256k1Scalar::random().underlying_ref().clone().unwrap().0,
        bitcoin::Network::Regtest
    );
    let sk_pub_blnd = PrivateKey::new(
        Secp256k1Scalar::random().underlying_ref().clone().unwrap().0,
        bitcoin::Network::Regtest
    );

    let commitment_script = new_commitment_script(
        2,
        4,
        &pk_sig_user,
        &pk_sig_blnd,
        &sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_user.to_bytes())).try_into().unwrap(),
        &sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_blnd.to_bytes())).try_into().unwrap(),
        &sk_pub_user.public_key(&secp),
        &sk_pub_blnd.public_key(&secp)
    );

    let split_script = new_split_delivery_script(&pk_sig_user, &pk_sig_blnd);

    let split_transaction = new_unsigned_transaction_split_delivery(
        &dummy_txid,
        0,
        transfer_amount,
        payback_amount_user,
        payback_amount_blnd,
        &split_script,
        &dummy_addr_user,
        &dummy_addr_blnd,
        2
    );

    let aed_transaction = new_unsigned_transaction_aed(
        &split_transaction.txid(),
        0,
        transfer_amount-fee,
        &dummy_addr_blnd
    );

    let timeout_transaction = new_unsigned_transaction_timeout(
        &split_transaction.txid(),
        0,
        transfer_amount-fee,
        &dummy_addr_blnd,
        5
    );

    let encoded_all = encode_mpc_all(
        &split_transaction,
        &aed_transaction,
        &timeout_transaction,
        &commitment_script,
        &split_script,
        commitment_amount,
        fee
    ).unwrap();

    let split_sighash = Sha256::digest(&Sha256::digest(&
        [
            &encoded_all[000..350],
            Sha256::digest(&Sha256::digest(&[
                &encoded_all[741..749],
                &encoded_all[606..641],
                &encoded_all[749..757],
                &encoded_all[641..664],
                &encoded_all[757..765],
                &encoded_all[664..687]
            ].concat())).as_slice(),
            &encoded_all[350..358]
        ].concat()
    ));

    let split_sighash_comp = SighashCache::new(&split_transaction).segwit_signature_hash(
        0,
        &commitment_script,
        60_0000_0000,
        EcdsaSighashType::All
    ).unwrap();

    assert_eq!(&split_sighash.as_slice(), &split_sighash_comp.to_vec());

    let aed_sighash = Sha256::digest(&Sha256::digest(&
        [
            &encoded_all[358..362],
            &Sha256::digest(&Sha256::digest([
                split_transaction.txid().as_ref(),
                &encoded_all[394..398]
            ].concat())),
            &encoded_all[362..394],
            split_transaction.txid().as_ref(),
            &encoded_all[394..470],
            &encoded_all[741..749],
            &encoded_all[470..474],
            &Sha256::digest(&Sha256::digest([
                &19_9990_0000_u64.to_le_bytes(),
                &encoded_all[687..710]
            ].concat())),
            &encoded_all[474..482]
        ].concat()
    ));

    let aed_sighash_comp = SighashCache::new(&aed_transaction).segwit_signature_hash(
        0,
        &split_script,
        20_0000_0000,
        EcdsaSighashType::All
    ).unwrap();

    assert_eq!(&aed_sighash.as_slice(), &aed_sighash_comp.to_vec());

    let timeout_sighash = Sha256::digest(&Sha256::digest(&
        [
            &encoded_all[482..486],
            &Sha256::digest(&Sha256::digest([
                split_transaction.txid().as_ref(),
                &encoded_all[518..522]
            ].concat())),
            &encoded_all[486..518],
            split_transaction.txid().as_ref(),
            &encoded_all[518..594],
            &encoded_all[741..749],
            &encoded_all[594..598],
            &Sha256::digest(&Sha256::digest([
                &19_9990_0000_u64.to_le_bytes(),
                &encoded_all[710..733]
            ].concat())),
            &encoded_all[598..606]
        ].concat()
    ));

    let timeout_sighash_comp = SighashCache::new(&timeout_transaction).segwit_signature_hash(
        0,
        &split_script,
        20_0000_0000,
        EcdsaSighashType::All
    ).unwrap();

    assert_eq!(&timeout_sighash.as_slice(), &timeout_sighash_comp.to_vec());
    
    let reader = BufReader::with_capacity(256000, std::fs::File::open(
        "circuit/zk_all.circ"
    ).unwrap());
    let mut circ: Circuit = bincode::deserialize_from(reader).unwrap();
    // let mut circ = Circuit::parse("circuit/zk_all.pp.bristol").unwrap();
    let data = encoded_all.to_hex();
    let rslt = [
        split_sighash.as_slice(),
        // &split_transaction.txid().to_vec(),
        aed_sighash.as_slice(),
        timeout_sighash.as_slice()
    ].concat().to_hex();
    
    let result = run_circuit(
        &mut circ,
        vec![],
        encode_boolean(&data, true).unwrap(),
    ).unwrap();
    // dbg!(decode_boolean(&result, true).unwrap());
    assert_eq!(decode_boolean(&result, true).unwrap(), rslt);
}

#[test]
fn test_channel_hub_reduced() {
    let docker = clients::Cli::default();
    let mut bitcoin_args = BitcoinCoreImageArgs::default();
    bitcoin_args.accept_non_std_txn = Some(true);
    let bitcoin_daemon = docker.run(RunnableImage::from(
        (BitcoinCore::default(), bitcoin_args)
    ));
    let bitcoin_auth = &bitcoin_daemon.image_args().rpc_auth;
    let bitcoin_base_url = format!("http://{}:{}@localhost:{}", bitcoin_auth.username(), bitcoin_auth.password(), bitcoin_daemon.get_host_port_ipv4(18443)).to_owned();
    let bitcoin_cli_sender = Client::new(&bitcoin_base_url);
    let bitcoin_cli_tumbler = Client::new(&bitcoin_base_url);
    let bitcoin_cli_receiver = Client::new(&bitcoin_base_url);
    let bitcoin_cli = Client::new(&bitcoin_base_url);

    // Initialize a meaningless address
    let address_null = "bcrt1q50cp8mzc0tqjuj0yyvp0hgekuuc33zrn9wd7rg";

    // Initialize the wallets for sender and tumbler
    let wallet_sender = bitcoin_cli_sender.create_wallet("liquid_sender").unwrap();
    let wallet_tumbler = bitcoin_cli_tumbler.create_wallet("liquid_tumbler").unwrap();
    let wallet_receiver = bitcoin_cli_receiver.create_wallet("liquid_receiver").unwrap();

    // Initialize the money for each parties
    bitcoin_cli_sender.mine(1, &wallet_sender.get_new_address().unwrap()).unwrap();
    bitcoin_cli_tumbler.mine(2, &wallet_tumbler.get_new_address().unwrap()).unwrap();
    bitcoin_cli_receiver.mine(1, &wallet_receiver.get_new_address().unwrap()).unwrap();
    bitcoin_cli.mine(100, address_null).unwrap();

    let circ_parse_time = SystemTime::now();
    let reader = BufReader::with_capacity(256000, std::fs::File::open(
        "circuit/zk_all.circ"
    ).unwrap());
    let circ_all_sender: Circuit = bincode::deserialize_from(reader).unwrap();    
    let circ_all_tumbler = circ_all_sender.clone();
    let circ_all_receiver = circ_all_sender.clone();
    let reader = BufReader::with_capacity(256000, std::fs::File::open(
        "circuit/zk_split_final.circ"
    ).unwrap());
    let circ_split_final_sender: Circuit = bincode::deserialize_from(reader).unwrap();    
    let circ_split_final_tumbler = circ_split_final_sender.clone();
    let circ_split_final_receiver = circ_split_final_sender.clone();
    println!(
        "Circuit parse time: {} ms",
        circ_parse_time.elapsed().unwrap().as_millis()
    );

    let sk_rsohc = rsohc::SecretKey::new();
    let pk_rsohc = rsohc::PublicKey::from_sk(&sk_rsohc);
    let pk_rsohc_sender = pk_rsohc.clone();
    let pk_rsohc_receiver = pk_rsohc.clone();

    let clgroup = CLGroup::new_from_setup(&3845, &BigInt::zero(), &sample_prime_by_length(800));
    let (clsk_tumbler, clpk_tumbler) = clgroup.keygen();
    
    let (
        clgroup_sender,
        clgroup_tumbler,
        clgroup_receiver
    ) = (clgroup.clone(), clgroup.clone(), clgroup);
    let (
        clpk_tumbler_sender,
        clpk_tumbler_receiver
    ) = (clpk_tumbler.clone(), clpk_tumbler.clone());

    let split_return_amount_init = 29_9980_0000_u64;
    let transfer_amount = 20_0000_0000_u64;
    let fee_amount = 10_0000_u64;

    let time_total = SystemTime::now();

    let handler_sender = std::thread::spawn(move || {
        let stream_st = TcpListener::bind(ADDRESS_SNDR).unwrap().accept().unwrap().0;
        thread::sleep(std::time::Duration::from_millis(600));
        let stream_sr = TcpStream::connect(ADDRESS_RECV).unwrap();

        let mut sender_channel_tumbler = TrackChannel::new(
            BufReader::with_capacity(256000, stream_st.try_clone().unwrap()),
            BufWriter::with_capacity(256000, stream_st)
        );

        let mut sender_channel_receiver = TrackChannel::new(
            BufReader::with_capacity(256000, stream_sr.try_clone().unwrap()),
            BufWriter::with_capacity(256000, stream_sr)
        );

        let funding_template_sender = new_unsigned_transaction_funding_template(
            address_null,
            &bitcoin_cli_sender,
            &wallet_sender,
            30_0000_0000
        ).unwrap();

        let mut blind_channel = ChannelUser::new(
            &mut sender_channel_tumbler,
            bitcoin::Network::Regtest,
            &wallet_sender,
            funding_template_sender,
            60_0000_0000,
            59_9980_0000,
            split_return_amount_init,
            8,
            16,
            5
        ).unwrap();

        let (sender, commitment_transfer_amount_randomness) = ChannelSender::channel_reigster(
            &mut sender_channel_tumbler,
            &mut sender_channel_receiver,
            clgroup_sender,
            clpk_tumbler_sender,
            &pk_rsohc_sender,
            transfer_amount
        ).unwrap();

        // For measuring locking money time only
        let timer = SystemTime::now();
        let mut blind_channel_lock = blind_channel.clone();
        let rng = AesRng::new();
        let mut ev = Evaluator::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasReceiver>::new(sender_channel_tumbler, rng).unwrap();
        blind_channel_lock.make_transfer(
            &circ_all_sender,
            &mut ev,
            blind_core::channel::ChannelUserRole::Payer,
            transfer_amount,
            split_return_amount_init - transfer_amount,
            split_return_amount_init,
            &Secp256k1Point::generator(),
            fee_amount,
            bitcoin::Network::Regtest,
            &commitment_transfer_amount_randomness,
            &blind_channel.commitment_amount_user_randomness.sub(&commitment_transfer_amount_randomness),
            &blind_channel.commitment_amount_blnd_randomness.clone()
        ).unwrap();
        let mut sender_channel_tumbler = ev.channel;
        println!("Sender  :: locksend: {} ms", timer.elapsed().unwrap().as_millis());

        println!("Register transfer: {}", sender_channel_tumbler.total_kilobytes() + sender_channel_receiver.total_kilobytes());
        
        let (
            statement,
            state,
            commitment_transfer_amount_randomness
        ) = sender.channel_solve_part1(
            &mut sender_channel_tumbler,
            &mut sender_channel_receiver,
        ).unwrap();

        let rng = AesRng::new();
        let mut ev = Evaluator::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasReceiver>::new(sender_channel_tumbler, rng).unwrap();
        blind_channel.make_transfer(
            &circ_all_sender,
            &mut ev,
            blind_core::channel::ChannelUserRole::Payer,
            transfer_amount,
            split_return_amount_init - transfer_amount,
            split_return_amount_init,
            &statement,
            fee_amount,
            bitcoin::Network::Regtest,
            &commitment_transfer_amount_randomness,
            &blind_channel.commitment_amount_user_randomness.sub(&commitment_transfer_amount_randomness),
            &blind_channel.commitment_amount_blnd_randomness.clone()
        ).unwrap();
        
        let mut sender_channel_tumbler = ev.channel;

        let witness = sender.channel_solve_part2(
            &mut sender_channel_tumbler,
            &mut sender_channel_receiver,
            state
        ).unwrap();

        let rng = AesRng::new();
        let mut ev = Evaluator::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasReceiver>::new(sender_channel_tumbler, rng).unwrap();
        blind_channel.reduce(
            &circ_split_final_sender,
            &mut ev,
            bitcoin::Network::Regtest,
            split_return_amount_init - transfer_amount,
            split_return_amount_init + transfer_amount,
            &blind_channel.commitment_amount_user_randomness.sub(&commitment_transfer_amount_randomness),
            &blind_channel.commitment_amount_blnd_randomness.add(&commitment_transfer_amount_randomness)
        ).unwrap();

        let sender_channel_tumbler = ev.channel;

        if statement != Secp256k1Point::generator_mul(&witness) {
            panic!("witness not match statement")
        }

        match blind_channel.status {
            blind_core::channel::ChannelStatus::SplitDeliv { .. } => panic!("invalid status"),
            blind_core::channel::ChannelStatus::SplitFinal {
                commitment_transaction,
                split_transaction,
                ..
            } => {
                bitcoin_cli_sender.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&commitment_transaction)).unwrap();
                bitcoin_cli_sender.mine(10, address_null).unwrap();
                bitcoin_cli_sender.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&split_transaction)).unwrap();
                bitcoin_cli_sender.mine(10, address_null).unwrap();
            }
        };

        println!("Sender  : tranfer size: {}",
            sender_channel_tumbler.total_kilobytes() + sender_channel_receiver.total_kilobytes()
        );
    });

    let handler_tumbler = std::thread::spawn(move || {
        thread::sleep(std::time::Duration::from_millis(200));
        let stream_ts = TcpStream::connect(ADDRESS_SNDR).unwrap();
        let stream_tr = TcpListener::bind(ADDRESS_TMBL).unwrap().accept().unwrap().0;

        let mut tumbler_channel_sender = TrackChannel::new(
            BufReader::with_capacity(256000, stream_ts.try_clone().unwrap()),
            BufWriter::with_capacity(256000, stream_ts)
        );

        let mut tumbler_channel_receiver = TrackChannel::new(
            BufReader::with_capacity(256000, stream_tr.try_clone().unwrap()),
            BufWriter::with_capacity(256000, stream_tr)
        );

        let funding_template_blnd_sender = new_unsigned_transaction_funding_template(
            address_null,
            &bitcoin_cli_tumbler,
            &wallet_tumbler,
            30_0000_0000
        ).unwrap();

        let mut blind_channel_sender = ChannelBlind::new(
            &mut tumbler_channel_sender,
            bitcoin::Network::Regtest,
            &wallet_tumbler,
            funding_template_blnd_sender,
            60_0000_0000,
            59_9980_0000,
            split_return_amount_init,
            8,
            16,
            5
        ).unwrap();
        
        bitcoin_cli_tumbler.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&blind_channel_sender.params.funding_transaction)).unwrap();
        bitcoin_cli_tumbler.mine(3, &address_null).unwrap();

        let funding_template_blnd_receiver = new_unsigned_transaction_funding_template(
            address_null,
            &bitcoin_cli_tumbler,
            &wallet_tumbler,
            30_0000_0000
        ).unwrap();

        let mut blind_channel_receiver = ChannelBlind::new(
            &mut tumbler_channel_receiver,
            bitcoin::Network::Regtest,
            &wallet_tumbler,
            funding_template_blnd_receiver,
            60_0000_0000,
            59_9980_0000,
            split_return_amount_init,
            8,
            16,
            5
        ).unwrap();

        bitcoin_cli_tumbler.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&blind_channel_receiver.params.funding_transaction)).unwrap();
        bitcoin_cli_tumbler.mine(10, &address_null).unwrap();

        // let mut garbler_sender = Garbler::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasSender>::new(chan_blnd, rng).unwrap();

        let tumbler = ChannelTumbler::new(
            sk_rsohc,
            pk_rsohc,
            clgroup_tumbler,
            clsk_tumbler,
            clpk_tumbler
        );
        let commitment_transfer_amount_sender = tumbler.channel_register(&mut tumbler_channel_sender).unwrap();

        // For measuring locking money time only
        let timer = SystemTime::now();
        let mut blind_channel_sender_lock = blind_channel_sender.clone();
        let rng = AesRng::new();
        let mut gb_sender = Garbler::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasSender>::new(tumbler_channel_sender, rng).unwrap();
        blind_channel_sender_lock.make_transfer(
            &circ_all_tumbler,
            &mut gb_sender,
            blind_core::channel::ChannelUserRole::Payer,
            &Secp256k1Point::generator(),
            10_0000,
            bitcoin::Network::Regtest,
            &commitment_transfer_amount_sender,
            &blind_channel_sender.commitment_amount_user.sub_point(&commitment_transfer_amount_sender),
            &blind_channel_sender.commitment_amount_blnd.clone()
        ).unwrap();
        let mut tumbler_channel_sender = gb_sender.channel;
        println!("Tumbler :: locksend: {} ms", timer.elapsed().unwrap().as_millis());

        println!("Tumbler :: Transfer:: Register :: {}", tumbler_channel_sender.total_kilobytes() + tumbler_channel_receiver.total_kilobytes());
        let checkpoint = tumbler_channel_sender.total_kilobytes() + tumbler_channel_receiver.total_kilobytes();

        let (
            statement_receiver,
            commitment_transfer_amount_receiver
        ) = tumbler.channel_promiese(
            &mut tumbler_channel_receiver,
        ).unwrap();

        let timer = SystemTime::now();
        let rng = AesRng::new();
        let mut gb_receiver = Garbler::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasSender>::new(tumbler_channel_receiver, rng).unwrap();
        blind_channel_receiver.make_transfer(
            &circ_all_tumbler,
            &mut gb_receiver,
            blind_core::channel::ChannelUserRole::Payee,
            &statement_receiver,
            10_0000,
            bitcoin::Network::Regtest,
            &commitment_transfer_amount_receiver,
            &blind_channel_receiver.commitment_amount_user.clone(),
            &blind_channel_receiver.commitment_amount_blnd.sub_point(&commitment_transfer_amount_receiver)
        ).unwrap();

        let tumbler_channel_receiver = gb_receiver.channel;
        
        println!("Tumbler :: Transfer:: Promise  :: {}", tumbler_channel_sender.total_kilobytes() + tumbler_channel_receiver.total_kilobytes()  - checkpoint);
        let checkpoint = tumbler_channel_sender.total_kilobytes() + tumbler_channel_receiver.total_kilobytes();

        println!("Tumbler :: pay_recv: {} ms", timer.elapsed().unwrap().as_millis());

        let (
            statement_sender,
            witness,
            commitment_transfer_amount_sender
        ) = tumbler.channel_solve_part1(
            &mut tumbler_channel_sender,
        ).unwrap();

        let timer = SystemTime::now();
        let rng = AesRng::new();
        let mut gb_sender = Garbler::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasSender>::new(tumbler_channel_sender, rng).unwrap();
        blind_channel_sender.make_transfer(
            &circ_all_tumbler,
            &mut gb_sender,
            blind_core::channel::ChannelUserRole::Payer,
            &statement_sender,
            10_0000,
            bitcoin::Network::Regtest,
            &commitment_transfer_amount_sender,
            &blind_channel_sender.commitment_amount_user.sub_point(&commitment_transfer_amount_sender),
            &blind_channel_sender.commitment_amount_blnd.clone()
        ).unwrap();
        let mut tumbler_channel_sender = gb_sender.channel;
        println!("Tumbler :: pay_tmbl: {} ms", timer.elapsed().unwrap().as_millis());

        tumbler.channel_solve_part2(
            &mut tumbler_channel_sender,
            &witness
        ).unwrap();

        blind_channel_sender.complete_aed_trnasaction(&witness).unwrap();

        println!("Tumbler :: Transfer:: Solver   :: {}", tumbler_channel_sender.total_kilobytes() + tumbler_channel_receiver.total_kilobytes() - checkpoint);
        let checkpoint = tumbler_channel_sender.total_kilobytes() + tumbler_channel_receiver.total_kilobytes();

        let timer = SystemTime::now();
        let rng = AesRng::new();
        let mut gb_sender = Garbler::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasSender>::new(tumbler_channel_sender, rng).unwrap();
        blind_channel_sender.reduce(
            &circ_split_final_tumbler,
            &mut gb_sender,
            bitcoin::Network::Regtest,
            &blind_channel_sender.commitment_amount_user.sub_point(&commitment_transfer_amount_sender),
            &blind_channel_sender.commitment_amount_blnd.add_point(&commitment_transfer_amount_sender)
        ).unwrap();
        println!("Tumbler :: red_tmbl: {} ms", timer.elapsed().unwrap().as_millis());

        let timer = SystemTime::now();
        let rng = AesRng::new();
        let mut gb_receiver = Garbler::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasSender>::new(tumbler_channel_receiver, rng).unwrap();
        blind_channel_receiver.reduce(
            &circ_split_final_tumbler,
            &mut gb_receiver,
            bitcoin::Network::Regtest,
            &blind_channel_receiver.commitment_amount_user.add_point(&commitment_transfer_amount_receiver),
            &blind_channel_receiver.commitment_amount_blnd.sub_point(&commitment_transfer_amount_receiver)
        ).unwrap();
        println!("Tumbler :: red_recv: {} ms", timer.elapsed().unwrap().as_millis());            
        
        let tumbler_channel_sender = gb_sender.channel;
        let tumbler_channel_receiver = gb_receiver.channel;

        println!("Tumbler :: Transfer:: Open     :: {}", tumbler_channel_sender.total_kilobytes() + tumbler_channel_receiver.total_kilobytes() - checkpoint);

        println!("Tumbler : tranfer size: {}",
            tumbler_channel_sender.total_kilobytes() + tumbler_channel_receiver.total_kilobytes()
        );
    });

    let handler_receiver= std::thread::spawn(move || {
        thread::sleep(std::time::Duration::from_millis(400));
        let stream_rt = TcpStream::connect(ADDRESS_TMBL).unwrap();
        let stream_rs = TcpListener::bind(ADDRESS_RECV).unwrap().accept().unwrap().0;

        let mut receiver_channel_sender = TrackChannel::new(
            BufReader::with_capacity(256000, stream_rs.try_clone().unwrap()),
            BufWriter::with_capacity(256000, stream_rs)
        );

        let mut receiver_channel_tumbler = TrackChannel::new(
            BufReader::with_capacity(256000, stream_rt.try_clone().unwrap()),
            BufWriter::with_capacity(256000, stream_rt)
        );

        let funding_template = new_unsigned_transaction_funding_template(
            address_null,
            &bitcoin_cli_receiver,
            &wallet_receiver,
            30_0000_0000
        ).unwrap();

        let mut blind_channel = ChannelUser::new(
            &mut receiver_channel_tumbler,
            bitcoin::Network::Regtest,
            &wallet_receiver,
            funding_template,
            60_0000_0000,
            59_9980_0000,
            split_return_amount_init,
            8,
            16,
            5
        ).unwrap();

        let receiver = ChannelReceiver::channel_register(
            &mut receiver_channel_sender,
            &pk_rsohc_receiver,
            clgroup_receiver,
        ).unwrap();

        let (statement, rsohc_statement_rand) = receiver.channel_promise(
            &mut receiver_channel_tumbler,
            &mut receiver_channel_sender,
            &clpk_tumbler_receiver,
        ).unwrap();

        let rng = AesRng::new();
        let mut ev = Evaluator::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasReceiver>::new(receiver_channel_tumbler, rng).unwrap();
        blind_channel.make_transfer(
            &circ_all_receiver,
            &mut ev,
            blind_core::channel::ChannelUserRole::Payee,
            transfer_amount,
            split_return_amount_init,
            split_return_amount_init - transfer_amount,
            &statement,
            10_0000,
            bitcoin::Network::Regtest,
            &receiver.get_amount_commitment_randomness(),
            &blind_channel.commitment_amount_user_randomness.clone(),
            &blind_channel.commitment_amount_blnd_randomness.sub(&receiver.get_amount_commitment_randomness())
        ).unwrap();
        let receiver_channel_tumbler = ev.channel;

        let witness = receiver.channel_solve(
            &mut receiver_channel_sender,
            &rsohc_statement_rand
        ).unwrap();

        assert_eq!(
            statement,
            Secp256k1Point::generator_mul(&witness)
        );

        blind_channel.complete_aed_trnasaction(&witness).unwrap();
        
        let rng = AesRng::new();
        let mut ev = Evaluator::<TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, AesRng, NaorPinkasReceiver>::new(receiver_channel_tumbler, rng).unwrap();
        blind_channel.reduce(
            &circ_split_final_receiver,
            &mut ev,
            bitcoin::Network::Regtest,
            split_return_amount_init + transfer_amount,
            split_return_amount_init - transfer_amount, 
            &blind_channel.commitment_amount_user_randomness.add(&receiver.get_amount_commitment_randomness()),
            &blind_channel.commitment_amount_blnd_randomness.sub(&receiver.get_amount_commitment_randomness())
        ).unwrap();
        let receiver_channel_tumbler = ev.channel;

        println!("Receiver: tranfer size: {}",
            receiver_channel_sender.total_kilobytes() + receiver_channel_tumbler.total_kilobytes()
        );
    });

    handler_sender.join().unwrap();
    handler_tumbler.join().unwrap();
    handler_receiver.join().unwrap();

    println!("Total: {} ms", time_total.elapsed().unwrap().as_millis() - 600);

}