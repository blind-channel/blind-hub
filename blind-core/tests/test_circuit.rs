use bitcoin::{Txid, Address, secp256k1::Secp256k1, PublicKey, PrivateKey, util::sighash::SighashCache, EcdsaSighashType, hashes::hex::ToHex};
use blind_core::{script::{new_commitment_script, new_split_delivery_script}, transaction::{new_unsigned_transaction_split_delivery, new_unsigned_transaction_aed, new_unsigned_transaction_timeout}, encoder::encode_mpc_all};
use curv::elliptic::curves::{secp256_k1::Secp256k1Scalar, ECScalar};
use fancy_garbling::{
    circuit::Circuit,
    twopac::semihonest::{Evaluator, Garbler},
    FancyInput, decode_boolean, encode_boolean,
};
use ocelot::ot::{NaorPinkasReceiver as OtReceiver, NaorPinkasSender as OtSender};
use scuttlebutt::{AesRng, TrackUnixChannel, TrackChannel};
use sha2::{Digest, Sha256};
use std::{time::SystemTime, io::{BufReader, BufWriter}, os::unix::net::UnixStream, str::FromStr};

fn run_circuit(circ: &mut Circuit, gb_inputs: Vec<u16>, ev_inputs: Vec<u16>) -> Result<Vec<u16>,()> {
    let circ_ = circ.clone();
    let (tx, rx) = UnixStream::pair().unwrap();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let sender = TrackChannel::new(BufReader::new(tx.try_clone().unwrap()), BufWriter::new(tx));
        let mut gb = Garbler::<TrackUnixChannel, AesRng, OtSender>::new(sender, rng).unwrap();
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
    let rng = AesRng::new();
    let start = SystemTime::now();
    let receiver = TrackChannel::new(BufReader::new(rx.try_clone().unwrap()), BufWriter::new(rx));
    let mut ev = Evaluator::<TrackUnixChannel, AesRng, OtReceiver>::new(receiver, rng).unwrap();
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
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());
    return result.ok_or(());
}

// #[test]
// fn test_split_txid() {
//     let mut circ = Circuit::parse("circuit/txid_split.pp.bristol").unwrap();
//     let transaction = "0200000001071ce4a6bddbfe93117d89815235a9330db52d3fcfa50e1aaaf82a428bcef02d0000000000020000000300ca9a3b000000002200206757084395e86d627a9e135ece2fc047cdf0be86e4aa093aac1ebda7833c0ac280ba953e0000000016001430901af1638d14c0f860f16c5f0353e27588e7640094357700000000160014e4e86f0d4959ce869beb9265f8ee33d523e0c0f000000000";
//     let out = "ee631ac552ffa52a380a880784a4ebe068bc75b771d12045a07f20265acfa274";
//     let result = run_circuit(
//         &mut circ,
//         vec![],
//         encode_boolean(&transaction, true).unwrap(),
//     ).unwrap();
//     // dbg!(decode_boolean(&result, true).unwrap());
//     assert_eq!(decode_boolean(&result, true).unwrap(), out);
// }

#[test]
fn test_aes256(){
    let reader = BufReader::new(std::fs::File::open(
        "circuit/aes256.circ"
    ).unwrap());
    let mut circ: Circuit = bincode::deserialize_from(reader).unwrap();
    // let mut circ = Circuit::parse("circuit/aes256.pp.bristol").unwrap();
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let msg = "00112233445566778899aabbccddeeff";
    let out = "8ea2b7ca516745bfeafc49904b496089";
    let result = run_circuit(
        &mut circ,
        encode_boolean(&key, true).unwrap(),
        encode_boolean(&msg, true).unwrap()
    ).unwrap();
    // dbg!(decode_boolean(&result, true).unwrap());
    assert_eq!(decode_boolean(&result, true).unwrap(), out);
}

#[test]
fn test_sha256(){
    let reader = BufReader::new(std::fs::File::open(
        "circuit/sha256.circ"
    ).unwrap());
    let mut circ: Circuit = bincode::deserialize_from(reader).unwrap();
    // let mut circ = Circuit::parse("circuit/sha256.pp.bristol").unwrap();
    let data = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeeff80000000000000000000000000000180";
    let init = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
    let rslt = "110a7585fc26c396520879d7319edb89a7fa5d70c558855d172f0c9bbe97d9ca";
    let result = run_circuit(
        &mut circ,
        encode_boolean(&data, true).unwrap(),
        encode_boolean(&init, true).unwrap()
    ).unwrap();
    // dbg!(decode_boolean(&result, true).unwrap());
    assert_eq!(decode_boolean(&result, true).unwrap(), rslt);
}

#[test]
fn test_split_delivery() {
    let reader = BufReader::new(std::fs::File::open(
        "circuit/zk_split_delivery.circ"
    ).unwrap());
    let mut circ: Circuit = bincode::deserialize_from(reader).unwrap();
    // let mut circ = Circuit::parse("circuit/zk_split.pp.bristol").unwrap();
    let transaction = "02000000c2a6b065357b3b2737bd5cfbd7137f926f393daee4931ec1e77dc0a1a5d0a3fbf9e00e3113f3bfd7653e049d899e5f3c917d020780128ff686e37ce215ab74fe071ce4a6bddbfe93117d89815235a9330db52d3fcfa50e1aaaf82a428bcef02d00000000e921036e3037a9ef1fcd77966fe3efc81fe2e5b5dc5f39ff5b9ac569aacb15b235d461ac7c2102e2464853254d438950492b8417a33084734c3efc75e7d1c7912b1f3e70c80722ac636352b26d67210274287bd1286c5903ef595ca4ea8cbf26c97713e17d64bb251299eef2624ea243ac63aa20455777def3e452f467c4a25911e9e41cea1c96636ca5e2c32285ece2765b6b5588756754b2756868676321037514b7ceadcec7901a2c75e026c9b54036b489ce297bcef7b2977b5a2d789d28adaa206c102d517826ea96bbe4e60e6a6465ba93c046b85e7610af285d31e146d774ee8875676a686851c0ae9d650100000002000000000000000100000000ca9a3b000000002200208c56a3148b5ce7ab618726a63bba890fc4b2ac0624c496d582e112db487b338080ba953e0000000016001430901af1638d14c0f860f16c5f0353e27588e7640094357700000000160014e4e86f0d4959ce869beb9265f8ee33d523e0c0f0";
    let out = "00ca9a3b0000000080ba953e000000000094357700000000d595535da5d134949a93b23dcb22f722f4f305d81ca5c43b6c0e17106385573525866f71597b9bb2e6b7bfb63e4752578c734679b1abc7a8b2ea9f1e6b12bc2e";
    let result = run_circuit(
        &mut circ,
        vec![],
        encode_boolean(&transaction, true).unwrap(),
    ).unwrap();
    // dbg!(decode_boolean(&result, true).unwrap());
    assert_eq!(decode_boolean(&result, true).unwrap(), out);
}

#[test]
fn test_split_final() {
    let reader = BufReader::new(std::fs::File::open(
        "circuit/zk_split_final.circ"
    ).unwrap());
    let mut circ: Circuit = bincode::deserialize_from(reader).unwrap();
    // let mut circ = Circuit::parse("circuit/zk_split_final.pp.bristol").unwrap();
    let transaction = "02000000c2a6b065357b3b2737bd5cfbd7137f926f393daee4931ec1e77dc0a1a5d0a3fb18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198071ce4a6bddbfe93117d89815235a9330db52d3fcfa50e1aaaf82a428bcef02d00000000e92103a1ebb5088069447e0e6b1d1a637c57a2efdc0f83425d39c5dbd29ec2fc08c445ac7c2102e0ea02f6948da06fb08151bc18b8c85eb5be512f945b4cd90b6ee268617b5234ac636352b16d672102e0596a7aeaaf1562dd66dff7d23d43de9bd7e7cfda439e6f45936702d84abc1bac63aa208cada82fe6b21adf44e07447d16c469a8254969d2baecc646f71c7e943538f2188756754b1756868676321039e939510cd5feeac952c0d863f93947421b12bb3625d6421bf9c0b9e1689657badaa208229c0c58503fe25fae8aec227f2d2f076dffaa3c4878d58c7b51545e76b0d168875676a68685100bca06501000000feffffff020000000100000016001430901af1638d14c0f860f16c5f0353e27588e764160014e4e86f0d4959ce869beb9265f8ee33d523e0c0f0c01a68ee00000000c086327700000000";
    let out = "2eb1fc74653c7412d401fa0d1315e0557312dbe5e24e555e781f82c25613a622";
    let result = run_circuit(
        &mut circ,
        vec![],
        encode_boolean(&transaction, true).unwrap(),
    ).unwrap();
    // dbg!(decode_boolean(&result, true).unwrap());
    assert_eq!(decode_boolean(&result, true).unwrap(), out);
}

#[test]
fn test_aed_txout(){
    let reader = BufReader::new(std::fs::File::open(
        "circuit/zk_aed_timeout.circ"
    ).unwrap());
    let mut circ: Circuit = bincode::deserialize_from(reader).unwrap();
    // let mut circ = Circuit::parse("circuit/zk_aed_timeout.pp.bristol").unwrap();
    let data = "02000000c2a6b065357b3b2737bd5cfbd7137f926f393daee4931ec1e77dc0a1a5d0a3fb3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044071ce4a6bddbfe93117d89815235a9330db52d3fcfa50e1aaaf82a428bcef02d0000000047522103e5941a17146d830f7be9097122f848e6017b117baf375500ca1fa300b5de826221021b26d3a3aabf81c4d2bf8ee49aefb92fb96cee8a0dc6c78dfd48490708769b8f52aec0ae9d6501000000ffffffff000000000100000000ca9a3b00000000160014e4e86f0d4959ce869beb9265f8ee33d523e0c0f0";
    let rslt = "619f58d8715e3d275e4859e5f3c4fc608994f5b5a0cef536ab77fa6ca2ed6785";
    assert_eq!(encode_boolean(&data, true).unwrap()[1016..1272], encode_boolean("071ce4a6bddbfe93117d89815235a9330db52d3fcfa50e1aaaf82a428bcef02d", true).unwrap());
    assert_eq!(encode_boolean(&data, true).unwrap()[0984..1016], encode_boolean("00000000", true).unwrap());
    dbg!(decode_boolean(&encode_boolean(&data, true).unwrap()[0984..1272], true).unwrap());
    let result = run_circuit(
        &mut circ,
        vec![],
        encode_boolean(&data, true).unwrap(),
    ).unwrap();
    // dbg!(decode_boolean(&result, true).unwrap());
    assert_eq!(decode_boolean(&result, true).unwrap(), rslt);
}

#[test]
fn test_all() {
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
    
    let reader = BufReader::new(std::fs::File::open(
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
fn test_all_sat() {
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
    
    let reader = BufReader::new(std::fs::File::open(
        "circuit/zk_sat_all.circ"
    ).unwrap());
    let mut circ: Circuit = bincode::deserialize_from(reader).unwrap();
    // let mut circ = Circuit::parse("circuit/zk_sat_all.pp.bristol").unwrap();
    let data = [
        encoded_all.as_slice(),
        split_sighash.as_slice(),
        // &split_transaction.txid().to_vec(),
        aed_sighash.as_slice(),
        timeout_sighash.as_slice(),
    ].concat().to_hex();

    // let encoded = encode_boolean(&data, true).unwrap();
    // print!("{{");
    // for i in 0..(encoded.len() - 2560){
    //     if i % 64 == 0{
    //         println!()
    //     }
    //     print!("{}, ", encoded[i]);
    // }
    // println!("}}");
    // print!("{{");
    // for i in 0..2560 {
    //     if i % 64 == 0{
    //         println!()
    //     }
    //     print!("{}, ", encoded[encoded.len() - 2560 + i]);
    // }
    // println!("}}");

    let result = run_circuit(
        &mut circ,
        vec![],
        encode_boolean(&data, true).unwrap(),
    ).unwrap();
    // dbg!(decode_boolean(&result, true).unwrap());
    assert_eq!(&result, &[1u16]);
}

// #[test]
// fn write_circuit_serialized() {
//     let circuit_dir = std::fs::read_dir("./circuit").unwrap();
//     for file in circuit_dir{
//         let filename = file.unwrap().file_name().to_str().unwrap().to_owned();
//         if !filename.ends_with(".pp.bristol") {
//             continue;
//         }
//         let path_bristol = format!("circuit/{}", filename);
//         let path_binary = format!("circuit/{}", filename.replace(".pp.bristol", ".circ"));
//         let circ = Circuit::parse(&path_bristol).unwrap();
//         let writer =  BufWriter::new(std::fs::File::create(path_binary).unwrap());
//         bincode::serialize_into(writer, &circ).unwrap();
//     }
// }