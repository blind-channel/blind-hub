use bitcoin::{secp256k1::{SecretKey, Secp256k1, ecdsa::Signature}, PublicKey, Transaction, consensus, Script, hashes::hex::FromHex, Address, Network, Txid};
use curv::elliptic::curves::{secp256_k1::Secp256k1Scalar, ECScalar};
use scuttlebutt::AbstractChannel;

use crate::{ecdsa::AdaptorSignature, bitcoin_rpc::Wallet, transaction::{new_unsigned_transaction_split_delivery, new_unsigned_transaction_aed, new_unsigned_transaction_timeout}, script::new_split_delivery_script};

mod user;
mod blind;

pub use user::ChannelUser;
pub use blind::ChannelBlind;

pub trait FundingSigner {
    fn sign_transaction(&self, funding_transaction: Transaction) -> anyhow::Result<Transaction>;
}

impl FundingSigner for () {
    fn sign_transaction(&self, funding_transaction: Transaction) -> anyhow::Result<Transaction> {
        Ok(funding_transaction)
    }
}

impl FundingSigner for Wallet {
    fn sign_transaction(&self, funding_transaction: Transaction) -> anyhow::Result<Transaction> {
        let unsigned_tx = consensus::encode::serialize_hex(&funding_transaction);
        let signed_tx = self.sign_raw_transaction(&unsigned_tx)?;
        Ok(
            consensus::deserialize(&Vec::<u8>::from_hex(&signed_tx)?)?
        )
    }
}

pub(crate) trait Transferable 
where Self: Sized{
    fn write_channel<C: AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()>;
    fn read_channel<C: AbstractChannel>(chan: &mut C) -> anyhow::Result<Self>;
}

#[derive(Clone)]
pub enum ChannelUserRole{
    Payer,
    Payee
}

impl ChannelUserRole {
    fn aed_address(
        &self,
        network: Network,
        pk_user: &ChannelPK,
        pk_blnd: &ChannelPK
    ) -> anyhow::Result<Address> {
        let target = &match self {
            ChannelUserRole::Payer => pk_blnd.pk_sig,
            ChannelUserRole::Payee => pk_user.pk_sig,
        };
        Address::p2wpkh(target, network).map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn timeout_address(
        &self,
        network: Network,
        pk_user: &ChannelPK,
        pk_blnd: &ChannelPK
    ) -> anyhow::Result<Address> {
        let target = &match self {
            ChannelUserRole::Payer => pk_user.pk_sig,
            ChannelUserRole::Payee => pk_blnd.pk_sig,
        };
        Address::p2wpkh(target, network).map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    // fn pay_user_transaction<'a, 'b, 'c>(&self, aed_transaction: &'a Transaction, timeout_transaction: &'b Transaction) -> &'c Transaction 
    // where
    //     'a: 'c,
    //     'b: 'c
    // {
    //     match self {
    //         ChannelUserRole::Payer => timeout_transaction,
    //         ChannelUserRole::Payee => aed_transaction,
    //     }
    // }

    // fn pay_blnd_transaction<'a, 'b, 'c>(&self, aed_transaction: &'a Transaction, timeout_transaction: &'b Transaction) -> &'c Transaction 
    // where
    //     'a: 'c,
    //     'b: 'c
    // {
    //     match self {
    //         ChannelUserRole::Payer => aed_transaction,
    //         ChannelUserRole::Payee => timeout_transaction,
    //     }
    // }
}

#[derive(Clone)]
pub struct ChannelSK {
    sk_sig: SecretKey,
    sk_pub: SecretKey
}

impl ChannelSK {
    pub fn new() -> Self {
        let sk_sig = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let sk_pub = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();

        Self { sk_sig, sk_pub }
    }
}

#[derive(Clone)]
pub struct ChannelPK {
    pk_sig: PublicKey,
    pk_pub: PublicKey
}

impl ChannelPK {
    pub fn from_sk(chan_sk: &ChannelSK) -> Self {
        let secp = Secp256k1::default();
        let pk_sig = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &&chan_sk.sk_sig));
        let pk_pub = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &&chan_sk.sk_pub));

        Self { pk_sig, pk_pub }
    }
}

impl Transferable for Transaction {
    fn write_channel<C: AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded = consensus::encode::serialize(&self);
        chan.write_usize(encoded.len())?;
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: AbstractChannel>(chan: &mut C) -> anyhow::Result<Transaction> {
        let encoded_len = chan.read_usize()?;
        let mut encoded = vec![0u8; encoded_len];
        chan.read_bytes(&mut encoded)?;
        Ok(consensus::deserialize(&encoded)?)
    }
}

impl Transferable for PublicKey {
    fn write_channel<C: AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded = self.to_bytes();
        chan.write_usize(encoded.len())?;
        chan.write_bytes(&encoded)?;
        Ok(())
    }
    
    fn read_channel<C: AbstractChannel>(chan: &mut C) -> anyhow::Result<PublicKey> {
        let encoded_len = chan.read_usize()?;
        let mut encoded = vec![0u8; encoded_len];
        chan.read_bytes(&mut encoded)?;
        Ok(PublicKey::from_slice(&encoded)?)
    }
}

impl Transferable for Signature {
    fn write_channel<C: AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded = self.serialize_compact();
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: AbstractChannel>(chan: &mut C) -> anyhow::Result<Signature> {
        let mut encoded = [0u8; 64];
        chan.read_bytes(&mut encoded)?;
        Ok(Signature::from_compact(&encoded)?)
    }
}

impl Transferable for AdaptorSignature {
    fn write_channel<C: AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded = self.serialize();
        chan.write_bytes(&encoded)?;
        Ok(())
    }
    
    fn read_channel<C: AbstractChannel>(chan: &mut C) -> anyhow::Result<AdaptorSignature> {
        let mut encoded = [0u8;195];
        chan.read_bytes(&mut encoded)?;
        AdaptorSignature::deserialize(&encoded)
    }
}

impl Transferable for ChannelPK{
    fn write_channel<C: AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        self.pk_sig.write_channel(chan)?;
        self.pk_pub.write_channel(chan)?;

        Ok(())
    }

    fn read_channel<C: AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let pk_sig = PublicKey::read_channel(chan)?;
        let pk_pub = PublicKey::read_channel(chan)?;
        Ok(Self{
            pk_sig,
            pk_pub
        })
    }
}

impl Transferable for SecretKey {
    fn write_channel<C: AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        chan.write_bytes(&self.secret_bytes())?;
        Ok(())
    }

    fn read_channel<C: AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8;32];
        chan.read_bytes(&mut encoded)?;
        Ok(Self::from_slice(&encoded)?)
    }
}

#[derive(Clone)]
pub enum ChannelStatus {
    SplitFinal{
        rev_cred_this: SecretKey,
        rev_hash_other: [u8;32],
        commitment_transaction: Transaction,
        commitment_transaction_presig_other: AdaptorSignature,
        split_transaction: Transaction
    },
    SplitDeliv{
        user_role: ChannelUserRole,
        rev_cred_this: SecretKey,
        rev_hash_other: [u8;32],
        commitment_transaction: Transaction,
        commitment_transaction_presig_other: AdaptorSignature,
        split_script: Script,
        split_transaction: Transaction,
        aed_transaction_sighash: [u8;32],
        aed_transaction_presig: Option<AdaptorSignature>,
        aed_transaction: Transaction,
        timeout_transaction: Option<Transaction>,
    }
}

#[derive(Clone)]
pub struct ChannelParams {
    pub funding_transaction: Transaction,
    funding_script: Script,
    commitment_output_amount: u64,
    commitment_timelock_relative_split: u32,
    commitment_timelock_relative_punish: u32,
    timeout_sequence: u32
}

struct DeliveryTransactionPack {
    pub(crate) split_script: Script,
    pub(crate) split_transaction: Transaction,
    pub(crate) aed_transaction: Transaction,
    pub(crate) timeout_transaction: Transaction
}

impl DeliveryTransactionPack {
    fn build(
        user_role: &ChannelUserRole,
        pk_user: &ChannelPK,
        pk_blnd: &ChannelPK,
        network: bitcoin::Network,
        commitment_transaction_txid: &Txid,
        commitment_timelock_abs_split: u32,
        split_transfer_amount: u64,
        split_payback_amount_user: u64,
        split_payback_amount_blnd: u64,
        transfer_output_amount: u64,
        timeout_sequence: u32
    ) -> anyhow::Result<Self> {
        let split_script = new_split_delivery_script(&pk_user.pk_sig, &pk_blnd.pk_sig);
        let split_transaction = new_unsigned_transaction_split_delivery(
            commitment_transaction_txid,
            0,
            split_transfer_amount,
            split_payback_amount_user,
            split_payback_amount_blnd,
            &split_script,
            &Address::p2wpkh(&pk_user.pk_sig, network)?,
            &Address::p2wpkh(&pk_blnd.pk_sig, network)?,
            commitment_timelock_abs_split
        );
        let aed_transaction = new_unsigned_transaction_aed(
            &split_transaction.txid(),
            0,
            transfer_output_amount,
            &user_role.aed_address(network, &pk_user, &pk_blnd)?
        );
        let timeout_transaction = new_unsigned_transaction_timeout(
            &split_transaction.txid(),
            0,
            transfer_output_amount,
            &user_role.timeout_address(network, &pk_user, &pk_blnd)?,
            timeout_sequence
        );
        Ok(Self{ split_script, split_transaction, aed_transaction, timeout_transaction })
    }
}

#[cfg(test)]
mod tests {
    use std::{time::SystemTime, io::BufReader};

    use bitcoin::{consensus::{encode::serialize_hex, self}, hashes::hex::{ToHex, FromHex}, Transaction, secp256k1::ecdsa::Signature};
    use curv::elliptic::curves::{secp256_k1::{Secp256k1Point, Secp256k1Scalar}, ECPoint, ECScalar, bls12_381::scalar::FieldScalar};
    use fancy_garbling::{circuit::Circuit, twopac::semihonest::{Garbler, Evaluator}};
    use ocelot::ot::{NaorPinkasSender, NaorPinkasReceiver};
    use scuttlebutt::{TrackUnixChannel, AesRng, track_unix_channel_pair};
    use testcontainers::{clients, images::coblox_bitcoincore::{BitcoinCoreImageArgs, BitcoinCore}, RunnableImage};

    use crate::{bitcoin_rpc::Client, transaction::new_unsigned_transaction_funding_template, channel::Transferable, rsohc::commit};

    use super::{ChannelUser, ChannelBlind};

    #[test]
    fn test_channel_extraction() {
        let docker = clients::Cli::default();
        let mut bitcoin_args = BitcoinCoreImageArgs::default();
        bitcoin_args.accept_non_std_txn = Some(true);
        let bitcoin_daemon = docker.run(RunnableImage::from(
            (BitcoinCore::default(), bitcoin_args)
        ));
        let bitcoin_auth = &bitcoin_daemon.image_args().rpc_auth;
        let bitcoin_base_url = format!("http://{}:{}@localhost:{}", bitcoin_auth.username(), bitcoin_auth.password(), bitcoin_daemon.get_host_port_ipv4(18443)).to_owned();
        let bitcoin_cli_user = Client::new(&bitcoin_base_url);
        let bitcoin_cli_blnd = Client::new(&bitcoin_base_url);
        let bitcoin_cli = Client::new(&bitcoin_base_url);

        // Initialize a meaningless address
        let address_null = "bcrt1q50cp8mzc0tqjuj0yyvp0hgekuuc33zrn9wd7rg";

        // Initialize the wallets for sender and tumbler
        let wallet_user = bitcoin_cli_user.create_wallet("liquid_user").unwrap();
        let wallet_blnd = bitcoin_cli_blnd.create_wallet("liquid_blnd").unwrap();

        // Initialize the money for each parties
        bitcoin_cli_user.mine(1, &wallet_user.get_new_address().unwrap()).unwrap();
        bitcoin_cli_blnd.mine(1, &wallet_blnd.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(100, address_null).unwrap();

        let (mut chan_user, mut chan_blnd) = track_unix_channel_pair();

        let handle_user = std::thread::spawn(move || {
            let funding_template_user = new_unsigned_transaction_funding_template(
                address_null,
                &bitcoin_cli_user,
                &wallet_user,
                30_0000_0000
            ).unwrap();

            let blind_channel = ChannelUser::new(
                &mut chan_user,
                bitcoin::Network::Regtest,
                &wallet_user,
                funding_template_user,
                60_0000_0000,
                59_9980_0000,
                29_9980_0000,
                8,
                16,
                5
            ).unwrap();

            bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&blind_channel.params.funding_transaction)).unwrap();

            bitcoin_cli.send_raw_transaction(
                &serialize_hex(&blind_channel.params.funding_transaction)
            ).unwrap();

            bitcoin_cli.send_raw_transaction(
                &serialize_hex(match &blind_channel.status{
                    super::ChannelStatus::SplitFinal{commitment_transaction, ..} => commitment_transaction,
                    _ => panic!("expect split transaction to be final"),
                })
            ).unwrap();

            bitcoin_cli_user.mine(10, &address_null).unwrap();

            bitcoin_cli.send_raw_transaction(
                &serialize_hex(match &blind_channel.status{
                    super::ChannelStatus::SplitFinal{split_transaction, ..} => split_transaction,
                    _ => panic!("expect split transaction to be final"),
                })
            ).unwrap();
        });

        let handle_blnd = std::thread::spawn(move || {
            let funding_template_blnd = new_unsigned_transaction_funding_template(
                address_null,
                &bitcoin_cli_blnd,
                &wallet_blnd,
                30_0000_0000
            ).unwrap();

            let blind_channel = ChannelBlind::new(
                &mut chan_blnd,
                bitcoin::Network::Regtest,
                &wallet_blnd,
                funding_template_blnd,
                60_0000_0000,
                59_9980_0000,
                29_9980_0000,
                8,
                16,
                5
            ).unwrap();


            loop{
                std::thread::sleep(std::time::Duration::from_micros(200));
                let raw = bitcoin_cli_blnd.get_raw_transaction(
                    &match &blind_channel.status{
                        super::ChannelStatus::SplitFinal{commitment_transaction, ..} => commitment_transaction.txid().to_hex(),
                        _ => panic!("expect split transaction to be final"),
                    }
                );
                if raw.is_ok() {
                    let commitment_transaction_real = consensus::deserialize::<Transaction>(
                        &Vec::<u8>::from_hex(&raw.unwrap()).unwrap()
                    ).unwrap();
                    let commitment_presig_adatption = commitment_transaction_real.input[0].witness.to_vec()[2].clone();
                    let commitment_presig_adatption = Signature::from_der(&commitment_presig_adatption[..commitment_presig_adatption.len() - 1]).unwrap();
                    let sk_pub_user = match &blind_channel.status{
                        super::ChannelStatus::SplitFinal{commitment_transaction_presig_other: commitment_presig_other, ..} => commitment_presig_other,
                        _ => panic!("expect split transaction to be final"),
                    }.extract(
                        &commitment_presig_adatption,
                        &Secp256k1Point::from_underlying(Some(curv::elliptic::curves::secp256_k1::PK(blind_channel.pk_user.pk_pub.inner)))
                    ).unwrap();
                    assert_eq!(
                        Secp256k1Point::from_underlying(Some(curv::elliptic::curves::secp256_k1::PK(blind_channel.pk_user.pk_pub.inner))),
                        Secp256k1Point::generator_mul(&sk_pub_user)
                    );
                    break;
                }
            }
        });

        handle_user.join().unwrap();
        handle_blnd.join().unwrap();
    }

    #[test]
    fn test_channel_update_user_to_blnd_timeout() {
        let docker = clients::Cli::default();
        let mut bitcoin_args = BitcoinCoreImageArgs::default();
        bitcoin_args.accept_non_std_txn = Some(true);
        let bitcoin_daemon = docker.run(RunnableImage::from(
            (BitcoinCore::default(), bitcoin_args)
        ));
        let bitcoin_auth = &bitcoin_daemon.image_args().rpc_auth;
        let bitcoin_base_url = format!("http://{}:{}@localhost:{}", bitcoin_auth.username(), bitcoin_auth.password(), bitcoin_daemon.get_host_port_ipv4(18443)).to_owned();
        let bitcoin_cli_user = Client::new(&bitcoin_base_url);
        let bitcoin_cli_blnd = Client::new(&bitcoin_base_url);
        let bitcoin_cli = Client::new(&bitcoin_base_url);

        // Initialize a meaningless address
        let address_null = "bcrt1q50cp8mzc0tqjuj0yyvp0hgekuuc33zrn9wd7rg";

        // Initialize the wallets for sender and tumbler
        let wallet_user = bitcoin_cli_user.create_wallet("liquid_user").unwrap();
        let wallet_blnd = bitcoin_cli_blnd.create_wallet("liquid_blnd").unwrap();

        // Initialize the money for each parties
        bitcoin_cli_user.mine(1, &wallet_user.get_new_address().unwrap()).unwrap();
        bitcoin_cli_blnd.mine(1, &wallet_blnd.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(100, address_null).unwrap();

        let circ_parse_time = SystemTime::now();
        let reader = BufReader::new(std::fs::File::open(
            "circuit/zk_all.circ"
        ).unwrap());
        let circ_user: Circuit = bincode::deserialize_from(reader).unwrap();    
        let circ_blnd = circ_user.clone();
        println!(
            "Circuit parse time: {} ms",
            circ_parse_time.elapsed().unwrap().as_millis()
        );

        let (mut chan_user, mut chan_blnd) = track_unix_channel_pair();

        let transfer_amount = 20_0000_0000_u64;
        let payback_amount_user = 19_9980_0000_u64;
        let payback_amount_blnd = 19_9990_0000_u64;
        let fee_amount = 10_0000_u64;
        let (
            commitment_transfer_amount,
            commitment_transfer_amount_randomness
        ) = commit(&FieldScalar::from_bigint(&transfer_amount.into()));
        let (
            commitment_payback_amount_user,
            commitment_payback_amount_user_randomness
        ) = commit(&FieldScalar::from_bigint(&payback_amount_user.into()));
        let (
            commitment_payback_amount_blnd,
            commitment_payback_amount_blnd_randomness
        ) = commit(&FieldScalar::from_bigint(&payback_amount_blnd.into()));
        let puzzle_witness = Secp256k1Scalar::from_bigint(&1024.into());
        let puzzle_statement = Secp256k1Point::generator_mul(&puzzle_witness);
        let (
            puzzle_statement_user,
            puzzle_statement_blnd
        ) = (puzzle_statement.clone(), puzzle_statement);

        let handle_user = std::thread::spawn(move || {
            let funding_template_user = new_unsigned_transaction_funding_template(
                address_null,
                &bitcoin_cli_user,
                &wallet_user,
                30_0000_0000
            ).unwrap();

            let mut blind_channel = ChannelUser::new(
                &mut chan_user,
                bitcoin::Network::Regtest,
                &wallet_user,
                funding_template_user,
                60_0000_0000,
                59_9980_0000,
                29_9980_0000,
                8,
                16,
                5
            ).unwrap();

            bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&blind_channel.params.funding_transaction)).unwrap();

            bitcoin_cli_user.mine(10, &address_null).unwrap();

            let rng = AesRng::new();
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(chan_user, rng).unwrap();

            blind_channel.make_transfer(
                &circ_user,
                &mut ev,
                crate::channel::ChannelUserRole::Payer,
                transfer_amount,
                payback_amount_user,
                payback_amount_blnd,
                &puzzle_statement_user,
                fee_amount,
                bitcoin::Network::Regtest,
                &commitment_transfer_amount_randomness,
                &commitment_payback_amount_user_randomness,
                &commitment_payback_amount_blnd_randomness
            ).unwrap();

            match blind_channel.status {
                crate::channel::ChannelStatus::SplitFinal { .. } => panic!("invalid status"),
                crate::channel::ChannelStatus::SplitDeliv {
                    commitment_transaction,
                    split_transaction,
                    timeout_transaction,
                    ..
                } => {
                    let timeout_transaction = timeout_transaction.unwrap();
                    bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&commitment_transaction)).unwrap();
                    bitcoin_cli_user.mine(10, address_null).unwrap();
                    bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&split_transaction)).unwrap();
                    assert!(bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&timeout_transaction)).is_err());
                    bitcoin_cli_user.mine(blind_channel.params.timeout_sequence.into(), address_null).unwrap();
                    bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&timeout_transaction)).unwrap();
                    bitcoin_cli_user.mine(10, address_null).unwrap();
                }
            };
        });

        let handle_blnd = std::thread::spawn(move || {
            let funding_template_blnd = new_unsigned_transaction_funding_template(
                address_null,
                &bitcoin_cli_blnd,
                &wallet_blnd,
                30_0000_0000
            ).unwrap();

            let mut blind_channel = ChannelBlind::new(
                &mut chan_blnd,
                bitcoin::Network::Regtest,
                &wallet_blnd,
                funding_template_blnd,
                60_0000_0000,
                59_9980_0000,
                29_9980_0000,
                8,
                16,
                5
            ).unwrap();

            let rng = AesRng::new();
            let mut gb = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(chan_blnd, rng).unwrap();
        
            blind_channel.make_transfer(
                &circ_blnd,
                &mut gb,
                crate::channel::ChannelUserRole::Payer,
                &puzzle_statement_blnd,
                fee_amount,
                bitcoin::Network::Regtest,
                &commitment_transfer_amount,
                &commitment_payback_amount_user,
                &commitment_payback_amount_blnd
            ).unwrap();
        });

        handle_user.join().unwrap();
        handle_blnd.join().unwrap();
    }

    #[test]
    fn test_channel_update_blnd_to_user_aed() {
        let docker = clients::Cli::default();
        let mut bitcoin_args = BitcoinCoreImageArgs::default();
        bitcoin_args.accept_non_std_txn = Some(true);
        let bitcoin_daemon = docker.run(RunnableImage::from(
            (BitcoinCore::default(), bitcoin_args)
        ));
        let bitcoin_auth = &bitcoin_daemon.image_args().rpc_auth;
        let bitcoin_base_url = format!("http://{}:{}@localhost:{}", bitcoin_auth.username(), bitcoin_auth.password(), bitcoin_daemon.get_host_port_ipv4(18443)).to_owned();
        let bitcoin_cli_user = Client::new(&bitcoin_base_url);
        let bitcoin_cli_blnd = Client::new(&bitcoin_base_url);
        let bitcoin_cli = Client::new(&bitcoin_base_url);

        // Initialize a meaningless address
        let address_null = "bcrt1q50cp8mzc0tqjuj0yyvp0hgekuuc33zrn9wd7rg";

        // Initialize the wallets for sender and tumbler
        let wallet_user = bitcoin_cli_user.create_wallet("liquid_user").unwrap();
        let wallet_blnd = bitcoin_cli_blnd.create_wallet("liquid_blnd").unwrap();

        // Initialize the money for each parties
        bitcoin_cli_user.mine(1, &wallet_user.get_new_address().unwrap()).unwrap();
        bitcoin_cli_blnd.mine(1, &wallet_blnd.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(100, address_null).unwrap();

        let circ_parse_time = SystemTime::now();
        let reader = BufReader::new(std::fs::File::open(
            "circuit/zk_all.circ"
        ).unwrap());
        let circ_user: Circuit = bincode::deserialize_from(reader).unwrap();    
        let circ_blnd = circ_user.clone();
        println!(
            "Circuit parse time: {} ms",
            circ_parse_time.elapsed().unwrap().as_millis()
        );

        let (mut chan_user, mut chan_blnd) = track_unix_channel_pair();

        let transfer_amount = 20_0000_0000_u64;
        let payback_amount_user = 19_9980_0000_u64;
        let payback_amount_blnd = 19_9990_0000_u64;
        let fee_amount = 10_0000_u64;
        let (
            commitment_transfer_amount,
            commitment_transfer_amount_randomness
        ) = commit(&FieldScalar::from_bigint(&transfer_amount.into()));
        let (
            commitment_payback_amount_user,
            commitment_payback_amount_user_randomness
        ) = commit(&FieldScalar::from_bigint(&payback_amount_user.into()));
        let (
            commitment_payback_amount_blnd,
            commitment_payback_amount_blnd_randomness
        ) = commit(&FieldScalar::from_bigint(&payback_amount_blnd.into()));
        let puzzle_witness = Secp256k1Scalar::from_bigint(&1024.into());
        let puzzle_statement = Secp256k1Point::generator_mul(&puzzle_witness);
        let (
            puzzle_statement_user,
            puzzle_statement_blnd
        ) = (puzzle_statement.clone(), puzzle_statement);

        let handle_user = std::thread::spawn(move || {
            let funding_template_user = new_unsigned_transaction_funding_template(
                address_null,
                &bitcoin_cli_user,
                &wallet_user,
                30_0000_0000
            ).unwrap();

            let mut blind_channel = ChannelUser::new(
                &mut chan_user,
                bitcoin::Network::Regtest,
                &wallet_user,
                funding_template_user,
                60_0000_0000,
                59_9980_0000,
                29_9980_0000,
                8,
                16,
                5
            ).unwrap();

            bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&blind_channel.params.funding_transaction)).unwrap();

            bitcoin_cli_user.mine(10, &address_null).unwrap();

            let rng = AesRng::new();
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(chan_user, rng).unwrap();

            blind_channel.make_transfer(
                &circ_user,
                &mut ev,
                crate::channel::ChannelUserRole::Payee,
                transfer_amount,
                payback_amount_user,
                payback_amount_blnd,
                &puzzle_statement_user,
                fee_amount,
                bitcoin::Network::Regtest,
                &commitment_transfer_amount_randomness,
                &commitment_payback_amount_user_randomness,
                &commitment_payback_amount_blnd_randomness
            ).unwrap();


            blind_channel.complete_aed_trnasaction(&puzzle_witness).unwrap();
            match blind_channel.status {
                crate::channel::ChannelStatus::SplitFinal { .. } => panic!("invalid status"),
                crate::channel::ChannelStatus::SplitDeliv {
                    commitment_transaction,
                    split_transaction,
                    aed_transaction,
                    ..
                } => {
                    bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&commitment_transaction)).unwrap();
                    bitcoin_cli_user.mine(10, address_null).unwrap();
                    bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&split_transaction)).unwrap();
                    bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&aed_transaction)).unwrap();
                    bitcoin_cli_user.mine(10, address_null).unwrap();
                }
            };
        });

        let handle_blnd = std::thread::spawn(move || {
            let funding_template_blnd = new_unsigned_transaction_funding_template(
                address_null,
                &bitcoin_cli_blnd,
                &wallet_blnd,
                30_0000_0000
            ).unwrap();

            let mut blind_channel = ChannelBlind::new(
                &mut chan_blnd,
                bitcoin::Network::Regtest,
                &wallet_blnd,
                funding_template_blnd,
                60_0000_0000,
                59_9980_0000,
                29_9980_0000,
                8,
                16,
                5
            ).unwrap();

            let rng = AesRng::new();
            let mut gb = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(chan_blnd, rng).unwrap();
        
            blind_channel.make_transfer(
                &circ_blnd,
                &mut gb,
                crate::channel::ChannelUserRole::Payee,
                &puzzle_statement_blnd,
                fee_amount,
                bitcoin::Network::Regtest,
                &commitment_transfer_amount,
                &commitment_payback_amount_user,
                &commitment_payback_amount_blnd
            ).unwrap();
        });

        handle_user.join().unwrap();
        handle_blnd.join().unwrap();
    }

    #[test]
    fn test_channel_update_user_to_blnd_aed() {
        let docker = clients::Cli::default();
        let mut bitcoin_args = BitcoinCoreImageArgs::default();
        bitcoin_args.accept_non_std_txn = Some(true);
        let bitcoin_daemon = docker.run(RunnableImage::from(
            (BitcoinCore::default(), bitcoin_args)
        ));
        let bitcoin_auth = &bitcoin_daemon.image_args().rpc_auth;
        let bitcoin_base_url = format!("http://{}:{}@localhost:{}", bitcoin_auth.username(), bitcoin_auth.password(), bitcoin_daemon.get_host_port_ipv4(18443)).to_owned();
        let bitcoin_cli_user = Client::new(&bitcoin_base_url);
        let bitcoin_cli_blnd = Client::new(&bitcoin_base_url);
        let bitcoin_cli = Client::new(&bitcoin_base_url);

        // Initialize a meaningless address
        let address_null = "bcrt1q50cp8mzc0tqjuj0yyvp0hgekuuc33zrn9wd7rg";

        // Initialize the wallets for sender and tumbler
        let wallet_user = bitcoin_cli_user.create_wallet("liquid_user").unwrap();
        let wallet_blnd = bitcoin_cli_blnd.create_wallet("liquid_blnd").unwrap();

        // Initialize the money for each parties
        bitcoin_cli_user.mine(1, &wallet_user.get_new_address().unwrap()).unwrap();
        bitcoin_cli_blnd.mine(1, &wallet_blnd.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(100, address_null).unwrap();

        let circ_parse_time = SystemTime::now();
        let reader = BufReader::new(std::fs::File::open(
            "circuit/zk_all.circ"
        ).unwrap());
        let circ_user: Circuit = bincode::deserialize_from(reader).unwrap();    
        let circ_blnd = circ_user.clone();
        println!(
            "Circuit parse time: {} ms",
            circ_parse_time.elapsed().unwrap().as_millis()
        );

        let (mut chan_user, mut chan_blnd) = track_unix_channel_pair();

        let transfer_amount = 20_0000_0000_u64;
        let payback_amount_user = 19_9980_0000_u64;
        let payback_amount_blnd = 19_9990_0000_u64;
        let fee_amount = 10_0000_u64;
        let (
            commitment_transfer_amount,
            commitment_transfer_amount_randomness
        ) = commit(&FieldScalar::from_bigint(&transfer_amount.into()));
        let (
            commitment_payback_amount_user,
            commitment_payback_amount_user_randomness
        ) = commit(&FieldScalar::from_bigint(&payback_amount_user.into()));
        let (
            commitment_payback_amount_blnd,
            commitment_payback_amount_blnd_randomness
        ) = commit(&FieldScalar::from_bigint(&payback_amount_blnd.into()));
        let puzzle_witness = Secp256k1Scalar::from_bigint(&1024.into());
        let puzzle_statement = Secp256k1Point::generator_mul(&puzzle_witness);
        let (
            puzzle_statement_user,
            puzzle_statement_blnd
        ) = (puzzle_statement.clone(), puzzle_statement);

        let handle_user = std::thread::spawn(move || {
            let funding_template_user = new_unsigned_transaction_funding_template(
                address_null,
                &bitcoin_cli_user,
                &wallet_user,
                30_0000_0000
            ).unwrap();

            let mut blind_channel = ChannelUser::new(
                &mut chan_user,
                bitcoin::Network::Regtest,
                &wallet_user,
                funding_template_user,
                60_0000_0000,
                59_9980_0000,
                29_9980_0000,
                8,
                16,
                5
            ).unwrap();

            bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&blind_channel.params.funding_transaction)).unwrap();

            bitcoin_cli_user.mine(10, &address_null).unwrap();

            let rng = AesRng::new();
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(chan_user, rng).unwrap();

            blind_channel.make_transfer(
                &circ_user,
                &mut ev,
                crate::channel::ChannelUserRole::Payer,
                transfer_amount,
                payback_amount_user,
                payback_amount_blnd,
                &puzzle_statement_user,
                fee_amount,
                bitcoin::Network::Regtest,
                &commitment_transfer_amount_randomness,
                &commitment_payback_amount_user_randomness,
                &commitment_payback_amount_blnd_randomness
            ).unwrap();

            match blind_channel.status {
                crate::channel::ChannelStatus::SplitFinal { .. } => panic!("invalid status"),
                crate::channel::ChannelStatus::SplitDeliv {
                    commitment_transaction,
                    split_transaction,
                    ..
                } => {
                    bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&commitment_transaction)).unwrap();
                    bitcoin_cli_user.mine(10, address_null).unwrap();
                    bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&split_transaction)).unwrap();
                    bitcoin_cli_user.mine(10, address_null).unwrap();

                    // You can't fetch the transaction with pure bitcoin rpc, but with libbitcoin?
                    // https://bitcoin.stackexchange.com/questions/61794/bitcoin-rpc-how-to-find-the-transaction-that-spends-a-txo
                    let mut chan_user = ev.channel;
                    split_transaction.write_channel(&mut chan_user).unwrap();
                }
            };
        });

        let handle_blnd = std::thread::spawn(move || {
            let funding_template_blnd = new_unsigned_transaction_funding_template(
                address_null,
                &bitcoin_cli_blnd,
                &wallet_blnd,
                30_0000_0000
            ).unwrap();

            let mut blind_channel = ChannelBlind::new(
                &mut chan_blnd,
                bitcoin::Network::Regtest,
                &wallet_blnd,
                funding_template_blnd,
                60_0000_0000,
                59_9980_0000,
                29_9980_0000,
                8,
                16,
                5
            ).unwrap();

            let rng = AesRng::new();
            let mut gb = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(chan_blnd, rng).unwrap();
        
            blind_channel.make_transfer(
                &circ_blnd,
                &mut gb,
                crate::channel::ChannelUserRole::Payer,
                &puzzle_statement_blnd,
                fee_amount,
                bitcoin::Network::Regtest,
                &commitment_transfer_amount,
                &commitment_payback_amount_user,
                &commitment_payback_amount_blnd
            ).unwrap();

            blind_channel.complete_aed_trnasaction(&puzzle_witness).unwrap();

            match &mut blind_channel.status {
                crate::channel::ChannelStatus::SplitFinal { .. } => panic!("invalid status"),
                crate::channel::ChannelStatus::SplitDeliv {
                    aed_transaction,
                    ..
                } => {
                    // Assume we find the split transaction in blockchain
                    let mut chan_blnd = gb.channel;
                    let split_transaction = Transaction::read_channel(&mut chan_blnd).unwrap();
                    loop {
                        std::thread::sleep(std::time::Duration::from_micros(200));
                        let raw = bitcoin_cli_blnd.get_raw_transaction(
                            &split_transaction.txid().to_hex()
                        );
                        if raw.is_ok() {
                            aed_transaction.input[0].previous_output.txid = split_transaction.txid();
                            aed_transaction.output[0].value = split_transaction.output[0].value - 10_0000;
                            bitcoin_cli_blnd.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&aed_transaction)).unwrap();
                            bitcoin_cli_blnd.mine(10, address_null).unwrap();
                            break;
                        }
                    }
                }
            };
        });

        handle_user.join().unwrap();
        handle_blnd.join().unwrap();
    }

    #[test]
    fn test_channel_update_blnd_to_user_timeout() {
        let docker = clients::Cli::default();
        let mut bitcoin_args = BitcoinCoreImageArgs::default();
        bitcoin_args.accept_non_std_txn = Some(true);
        let bitcoin_daemon = docker.run(RunnableImage::from(
            (BitcoinCore::default(), bitcoin_args)
        ));
        let bitcoin_auth = &bitcoin_daemon.image_args().rpc_auth;
        let bitcoin_base_url = format!("http://{}:{}@localhost:{}", bitcoin_auth.username(), bitcoin_auth.password(), bitcoin_daemon.get_host_port_ipv4(18443)).to_owned();
        let bitcoin_cli_user = Client::new(&bitcoin_base_url);
        let bitcoin_cli_blnd = Client::new(&bitcoin_base_url);
        let bitcoin_cli = Client::new(&bitcoin_base_url);

        // Initialize a meaningless address
        let address_null = "bcrt1q50cp8mzc0tqjuj0yyvp0hgekuuc33zrn9wd7rg";

        // Initialize the wallets for sender and tumbler
        let wallet_user = bitcoin_cli_user.create_wallet("liquid_user").unwrap();
        let wallet_blnd = bitcoin_cli_blnd.create_wallet("liquid_blnd").unwrap();

        // Initialize the money for each parties
        bitcoin_cli_user.mine(1, &wallet_user.get_new_address().unwrap()).unwrap();
        bitcoin_cli_blnd.mine(1, &wallet_blnd.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(100, address_null).unwrap();

        let circ_parse_time = SystemTime::now();
        let reader = BufReader::new(std::fs::File::open(
            "circuit/zk_all.circ"
        ).unwrap());
        let circ_user: Circuit = bincode::deserialize_from(reader).unwrap();    
        let circ_blnd = circ_user.clone();
        println!(
            "Circuit parse time: {} ms",
            circ_parse_time.elapsed().unwrap().as_millis()
        );

        let (mut chan_user, mut chan_blnd) = track_unix_channel_pair();

        let transfer_amount = 20_0000_0000_u64;
        let payback_amount_user = 19_9980_0000_u64;
        let payback_amount_blnd = 19_9990_0000_u64;
        let fee_amount = 10_0000_u64;
        let (
            commitment_transfer_amount,
            commitment_transfer_amount_randomness
        ) = commit(&FieldScalar::from_bigint(&transfer_amount.into()));
        let (
            commitment_payback_amount_user,
            commitment_payback_amount_user_randomness
        ) = commit(&FieldScalar::from_bigint(&payback_amount_user.into()));
        let (
            commitment_payback_amount_blnd,
            commitment_payback_amount_blnd_randomness
        ) = commit(&FieldScalar::from_bigint(&payback_amount_blnd.into()));
        let puzzle_witness = Secp256k1Scalar::from_bigint(&1024.into());
        let puzzle_statement = Secp256k1Point::generator_mul(&puzzle_witness);
        let (
            puzzle_statement_user,
            puzzle_statement_blnd
        ) = (puzzle_statement.clone(), puzzle_statement);

        let handle_user = std::thread::spawn(move || {
            let funding_template_user = new_unsigned_transaction_funding_template(
                address_null,
                &bitcoin_cli_user,
                &wallet_user,
                30_0000_0000
            ).unwrap();

            let mut blind_channel = ChannelUser::new(
                &mut chan_user,
                bitcoin::Network::Regtest,
                &wallet_user,
                funding_template_user,
                60_0000_0000,
                59_9980_0000,
                29_9980_0000,
                8,
                16,
                5
            ).unwrap();

            bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&blind_channel.params.funding_transaction)).unwrap();

            bitcoin_cli_user.mine(10, &address_null).unwrap();

            let rng = AesRng::new();
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(chan_user, rng).unwrap();

            blind_channel.make_transfer(
                &circ_user,
                &mut ev,
                crate::channel::ChannelUserRole::Payee,
                transfer_amount,
                payback_amount_user,
                payback_amount_blnd,
                &puzzle_statement_user,
                fee_amount,
                bitcoin::Network::Regtest,
                &commitment_transfer_amount_randomness,
                &commitment_payback_amount_user_randomness,
                &commitment_payback_amount_blnd_randomness
            ).unwrap();


            match blind_channel.status {
                crate::channel::ChannelStatus::SplitFinal { .. } => panic!("invalid status"),
                crate::channel::ChannelStatus::SplitDeliv {
                    commitment_transaction,
                    split_transaction,
                    ..
                } => {
                    bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&commitment_transaction)).unwrap();
                    bitcoin_cli_user.mine(10, address_null).unwrap();
                    bitcoin_cli_user.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&split_transaction)).unwrap();
                    bitcoin_cli_user.mine(10, address_null).unwrap();
                    
                    // You can't fetch the transaction with pure bitcoin rpc, but with libbitcoin?
                    // https://bitcoin.stackexchange.com/questions/61794/bitcoin-rpc-how-to-find-the-transaction-that-spends-a-txo
                    let mut chan_user = ev.channel;
                    split_transaction.write_channel(&mut chan_user).unwrap();
                }
            };
        });

        let handle_blnd = std::thread::spawn(move || {
            let funding_template_blnd = new_unsigned_transaction_funding_template(
                address_null,
                &bitcoin_cli_blnd,
                &wallet_blnd,
                30_0000_0000
            ).unwrap();

            let mut blind_channel = ChannelBlind::new(
                &mut chan_blnd,
                bitcoin::Network::Regtest,
                &wallet_blnd,
                funding_template_blnd,
                60_0000_0000,
                59_9980_0000,
                29_9980_0000,
                8,
                16,
                5
            ).unwrap();

            let rng = AesRng::new();
            let mut gb = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(chan_blnd, rng).unwrap();
        
            blind_channel.make_transfer(
                &circ_blnd,
                &mut gb,
                crate::channel::ChannelUserRole::Payee,
                &puzzle_statement_blnd,
                fee_amount,
                bitcoin::Network::Regtest,
                &commitment_transfer_amount,
                &commitment_payback_amount_user,
                &commitment_payback_amount_blnd
            ).unwrap();

            match blind_channel.status {
                crate::channel::ChannelStatus::SplitFinal { .. } => panic!("invalid status"),
                crate::channel::ChannelStatus::SplitDeliv {
                    timeout_transaction,
                    ..
                } => {
                    // Assume we find the split transaction in blockchain
                    let mut chan_blnd = gb.channel;
                    let split_transaction = Transaction::read_channel(&mut chan_blnd).unwrap();
                    let mut timeout_transaction = timeout_transaction.clone().unwrap();
                    loop {
                        std::thread::sleep(std::time::Duration::from_micros(200));
                        let raw = bitcoin_cli_blnd.get_raw_transaction(
                            &split_transaction.txid().to_hex()
                        );
                        if raw.is_ok() {
                            timeout_transaction.input[0].previous_output.txid = split_transaction.txid();
                            timeout_transaction.output[0].value = split_transaction.output[0].value - 10_0000;
                            bitcoin_cli_blnd.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&timeout_transaction)).unwrap();
                            bitcoin_cli_blnd.mine(10, address_null).unwrap();
                            break;
                        }
                    }
                }
            };
        });

        handle_user.join().unwrap();
        handle_blnd.join().unwrap();
    }
}