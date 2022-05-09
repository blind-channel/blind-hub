use bitcoin::{Script, Transaction, Txid, TxIn, OutPoint, Witness, TxOut, Address, Amount, consensus, hashes::hex::FromHex, util::sighash::SighashCache, EcdsaSighashType, secp256k1::{Message, Secp256k1, ecdsa::Signature, SecretKey}};

use crate::bitcoin_rpc::{Wallet, Client};

pub fn new_unsigned_transaction_funding_template(
    address_null: &str,
    cli: &Client,
    wallet: &Wallet,
    amount: u64
)-> anyhow::Result<Transaction>{
    let template = cli.create_raw_transaction(address_null, &Amount::from_sat(amount))?;
    let template = wallet.funding_raw_transaction(&template)?;
    let changepos = template.changepos;

    let mut template = consensus::deserialize::<Transaction>(&Vec::<u8>::from_hex(&template.hex)?)?;
    Ok(Transaction {
        output: {
            if changepos >= 0{
                vec![template.output.remove(changepos as usize)]
            } else {
                Vec::new()
            }
        },
        ..template
    })
}

pub fn new_unsigned_transcation_funding(
    funding_template_user: Transaction,
    funding_template_blnd: Transaction,
    output_amount: u64,
    funding_script: &Script
) -> Transaction{
    let mut funding_transaction = funding_template_user;
    funding_transaction.input.extend(funding_template_blnd.input);
    funding_transaction.output.extend(funding_template_blnd.output);
    funding_transaction.output.insert(
        0,
        TxOut { value: output_amount, script_pubkey: funding_script.to_v0_p2wsh() }
    );
    funding_transaction
}

pub fn sign_transaction_funding(
    transaction: &Transaction,
    wallet: &Wallet,
) -> anyhow::Result<Transaction>{
    let tx = wallet.sign_raw_transaction(&consensus::encode::serialize_hex(&transaction))?;
    Ok(consensus::deserialize::<Transaction>(&Vec::<u8>::from_hex(&tx)?)?)
}

pub fn compose_transaction_funding(
    funding_part_user: Transaction,
    funding_part_blnd: Transaction,
) -> anyhow::Result<Transaction>{
    Ok(Transaction {
        input: funding_part_user.input.into_iter().zip(funding_part_blnd.input.into_iter()).map(
            |(in_user, in_blnd)|{
                if in_user.previous_output != in_blnd.previous_output {
                    return Err(anyhow::anyhow!("input not match"))
                }
                if !in_user.witness.is_empty(){
                    Ok(in_user)
                } else if !in_blnd.witness.is_empty(){
                    Ok(in_blnd)
                } else {
                    Err(anyhow::anyhow!("not all inputs are signed"))
                }
            }
        ).collect::<anyhow::Result<_>>()?,
        ..funding_part_user
    })
}

pub fn new_unsigned_transcation_commitement(
    funding_transaction_txid: &Txid,
    funding_transaction_vout: u32,
    output_amount: u64,
    commitment_script: &Script
) -> Transaction{
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn{
                previous_output: OutPoint{
                    txid: funding_transaction_txid.clone(),
                    vout: funding_transaction_vout,
                },
                script_sig: Script::new(),
                sequence: 0xFFFFFFFF,
                witness: Witness::new(),
            }
        ],
        output: vec![
            TxOut{
                value: output_amount,
                script_pubkey: commitment_script.to_v0_p2wsh(),
            }
        ]
    }
}

pub fn sign_transaction(
    transaction: &Transaction,
    input_amount: u64,
    sk: &SecretKey,
    script: &Script
) -> anyhow::Result<Signature>{
    let secp = Secp256k1::default();
    let mut transaction_hash = SighashCache::new(transaction);
    let transaction_sighash = transaction_hash.segwit_signature_hash(
        0,
        &script,
        Amount::from_sat(input_amount).as_sat(),
        EcdsaSighashType::All
    )?;
    Ok(secp.sign_ecdsa_low_r(&Message::from_slice(&transaction_sighash)?, sk))
}

pub fn compose_transaction_multisig(
    mut transaction: Transaction,
    sig_user: Signature,
    sig_blnd: Signature,
    script_multisig: &Script
) -> Transaction{
    transaction.input[0].witness.push(&[]);
    transaction.input[0].witness.push(&[sig_user.serialize_der().as_ref(), &[1u8]].concat());
    transaction.input[0].witness.push(&[sig_blnd.serialize_der().as_ref(), &[1u8]].concat());
    transaction.input[0].witness.push(&script_multisig.as_bytes());
    transaction
}

pub fn new_unsigned_transaction_split_final(
    commitment_transaction_txid: &Txid,
    commitment_transaction_vout: u32,
    payback_user_amount: u64,
    payback_blnd_amount: u64,
    addr_user: &Address,
    addr_blnd: &Address,
    relative_timelock: u32,
) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn{
                previous_output: OutPoint{
                    txid: commitment_transaction_txid.clone(),
                    vout: commitment_transaction_vout,
                },
                script_sig: Script::new(),
                sequence: relative_timelock,
                witness: Witness::new(),
            }
        ],
        output: vec![
            TxOut{
                value: payback_user_amount,
                script_pubkey: addr_user.script_pubkey(),
            },
            TxOut{
                value: payback_blnd_amount,
                script_pubkey: addr_blnd.script_pubkey(),
            }
        ]
    }
}

pub fn compose_transaction_split(
    mut transaction: Transaction,
    sig_user: Signature,
    sig_blnd: Signature,
    commitment_script: &Script
) -> Transaction{
    transaction.input[0].witness.push(&[]);
    transaction.input[0].witness.push(&[sig_blnd.serialize_der().as_ref(), &[1u8]].concat());
    transaction.input[0].witness.push(&[sig_user.serialize_der().as_ref(), &[1u8]].concat());
    transaction.input[0].witness.push(&commitment_script.as_bytes());
    transaction
}

pub fn new_unsigned_transaction_split_delivery(
    commitment_transaction_txid: &Txid,
    commitment_transaction_vout: u32,
    transfer_amount: u64,
    payback_amount_user: u64,
    payback_amount_blnd: u64,
    split_script: &Script,
    addr_user: &Address,
    addr_blnd: &Address,
    relative_timelock: u32,
) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn{
                previous_output: OutPoint{
                    txid: commitment_transaction_txid.clone(),
                    vout: commitment_transaction_vout,
                },
                script_sig: Script::new(),
                sequence: relative_timelock,
                witness: Witness::new(),
            }
        ],
        output: vec![
            TxOut{
                value: transfer_amount,
                script_pubkey: split_script.to_v0_p2wsh(),
            },
            TxOut{
                value: payback_amount_user,
                script_pubkey: addr_user.script_pubkey(),
            },
            TxOut{
                value: payback_amount_blnd,
                script_pubkey: addr_blnd.script_pubkey(),
            },
        ]
    }
}

pub fn new_unsigned_transaction_aed(
    split_trnasaction_txid: &Txid,
    split_trnasaction_vout: u32,
    output_amount:u64,
    addr_target: &Address
) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn{
                previous_output: OutPoint{
                    txid: split_trnasaction_txid.clone(),
                    vout: split_trnasaction_vout,
                },
                script_sig: Script::new(),
                sequence: 0xFFFFFFFF,
                witness: Witness::new(),
            }
        ],
        output: vec![
            TxOut{
                value: output_amount,
                script_pubkey: addr_target.script_pubkey(),
            }
        ]
    }
}

pub fn new_unsigned_transaction_timeout(
    split_trnasaction_txid: &Txid,
    split_trnasaction_vout: u32,
    output_amount:u64,
    addr_fallback: &Address,
    sequence: u32
) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn{
                previous_output: OutPoint{
                    txid: split_trnasaction_txid.clone(),
                    vout: split_trnasaction_vout,
                },
                script_sig: Script::new(),
                sequence: sequence,
                witness: Witness::new(),
            }
        ],
        output: vec![
            TxOut{
                value: output_amount,
                script_pubkey: addr_fallback.script_pubkey(),
            }
        ]
    }
}

#[cfg(test)]
mod tests{
    use std::str::FromStr;

    use bitcoin::{consensus::{encode::serialize_hex}, PublicKey, PrivateKey, secp256k1::{Secp256k1}, Address};
    use curv::elliptic::curves::{secp256_k1::Secp256k1Scalar, ECScalar};
    use sha2::Digest;
    use testcontainers::{clients, images::coblox_bitcoincore::{BitcoinCore, BitcoinCoreImageArgs}, RunnableImage};
    use crate::{bitcoin_rpc::Client, script::{new_commitment_script, new_split_delivery_script}};

    use super::{new_unsigned_transaction_funding_template, new_unsigned_transcation_funding, sign_transaction_funding, compose_transaction_funding, new_unsigned_transcation_commitement, sign_transaction, compose_transaction_multisig, new_unsigned_transaction_split_final, compose_transaction_split, new_unsigned_transaction_split_delivery, new_unsigned_transaction_aed, new_unsigned_transaction_timeout};
    
    #[test]
    fn test_init_split() {
        // Initialize the testcontainer for bitcoin
        let docker = clients::Cli::default();
        let mut bitcoin_args = BitcoinCoreImageArgs::default();
        bitcoin_args.accept_non_std_txn = Some(true);
        let bitcoin_daemon = docker.run(RunnableImage::from(
            (BitcoinCore::default(), bitcoin_args)
        ));
        let bitcoin_auth = &bitcoin_daemon.image_args().rpc_auth;
        let bitcoin_base_url = format!("http://{}:{}@localhost:{}", bitcoin_auth.username(), bitcoin_auth.password(), bitcoin_daemon.get_host_port_ipv4(18443)).to_owned();
        let bitcoin_cli = Client::new(&bitcoin_base_url);

        // Initialize a meaningless address
        let address_null = "bcrt1q50cp8mzc0tqjuj0yyvp0hgekuuc33zrn9wd7rg";

        // Initialize the wallets for sender and tumbler
        let wallet_user = bitcoin_cli.create_wallet("liquid_user").unwrap();
        let wallet_blnd = bitcoin_cli.create_wallet("liquid_blnd").unwrap();

        // Initialize the money for each parties
        bitcoin_cli.mine(1, &wallet_user.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(1, &wallet_blnd.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(100, address_null).unwrap();

        let secp256k1 = Secp256k1::default();
        let sk_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let sk_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let pk_sig_user = PublicKey::from_private_key(&secp256k1, &PrivateKey::new(sk_user.clone(), bitcoin::Network::Regtest));
        let pk_sig_blnd = PublicKey::from_private_key(&secp256k1, &PrivateKey::new(sk_blnd.clone(), bitcoin::Network::Regtest));

        let script_funding = crate::script::new_funding_script(&pk_sig_user, &pk_sig_blnd);

        let funding_template_user = new_unsigned_transaction_funding_template(
            address_null,
            &bitcoin_cli,
            &wallet_user,
            30_0000_0000
        ).unwrap();
        let funding_template_blnd = new_unsigned_transaction_funding_template(
            address_null,
            &bitcoin_cli,
            &wallet_blnd,
            30_0000_0000
        ).unwrap();

        let funding_template = new_unsigned_transcation_funding(
            funding_template_user,
            funding_template_blnd,
            59_9990_0000,
            &script_funding
        );

        let funded_part_user = sign_transaction_funding(&funding_template, &wallet_user).unwrap();
        let funded_part_blnd = sign_transaction_funding(&funding_template, &wallet_blnd).unwrap();

        let funding_transaction = compose_transaction_funding(
            funded_part_user,
            funded_part_blnd,
        ).unwrap();
    
        bitcoin_cli.send_raw_transaction(&serialize_hex(&funding_transaction)).unwrap();
        bitcoin_cli.mine(6, address_null).unwrap();

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

        let script_commitment = new_commitment_script(
            2,
            4,
            &pk_sig_user,
            &pk_sig_blnd,
            &sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_user.to_bytes())).try_into().unwrap(),
            &sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_blnd.to_bytes())).try_into().unwrap(),
            &sk_pub_user.public_key(&secp),
            &sk_pub_blnd.public_key(&secp)
        );

        let commitment_transaction = new_unsigned_transcation_commitement(
            &funding_transaction.txid(),
            0,
            59_9980_0000,
            &script_commitment
        );
        let commitment_sig_user = sign_transaction(&commitment_transaction, 59_9990_0000, &sk_user, &script_funding).unwrap();
        let commitment_sig_blnd = sign_transaction(&commitment_transaction, 59_9990_0000, &sk_blnd, &script_funding).unwrap();
        let commitment_transaction = compose_transaction_multisig(
            commitment_transaction,
            commitment_sig_user,
            commitment_sig_blnd,
            &script_funding
        );

        bitcoin_cli.send_raw_transaction(&serialize_hex(&commitment_transaction)).unwrap();
        bitcoin_cli.mine(4, address_null).unwrap();

        let split_transaction = new_unsigned_transaction_split_final(
            &commitment_transaction.txid(),
            0,
            29_9980_0000,
            29_9980_0000,
            &Address::from_str(&wallet_user.get_new_address().unwrap()).unwrap(),
            &Address::from_str(&wallet_blnd.get_new_address().unwrap()).unwrap(),
            2
        );

        let split_sig_user = sign_transaction(
            &split_transaction,
            59_9980_0000,
            &sk_user,
            &script_commitment
        ).unwrap();
        let split_sig_blnd = sign_transaction(
            &split_transaction,
            59_9980_0000,
            &sk_blnd,
            &script_commitment
        ).unwrap();
        let split_transaction = compose_transaction_split(
            split_transaction,
            split_sig_user,
            split_sig_blnd,
            &script_commitment
        );

        bitcoin_cli.send_raw_transaction(&serialize_hex(&split_transaction)).unwrap();

    }

    #[test]
    fn test_transaction_aed(){
        // Initialize the testcontainer for bitcoin
        let docker = clients::Cli::default();
        let mut bitcoin_args = BitcoinCoreImageArgs::default();
        bitcoin_args.accept_non_std_txn = Some(true);
        let bitcoin_daemon = docker.run(RunnableImage::from(
            (BitcoinCore::default(), bitcoin_args)
        ));
        let bitcoin_auth = &bitcoin_daemon.image_args().rpc_auth;
        let bitcoin_base_url = format!("http://{}:{}@localhost:{}", bitcoin_auth.username(), bitcoin_auth.password(), bitcoin_daemon.get_host_port_ipv4(18443)).to_owned();
        let bitcoin_cli = Client::new(&bitcoin_base_url);

        // Initialize a meaningless address
        let address_null = "bcrt1q50cp8mzc0tqjuj0yyvp0hgekuuc33zrn9wd7rg";

        // Initialize the wallets for sender and tumbler
        let wallet_user = bitcoin_cli.create_wallet("liquid_user").unwrap();
        let wallet_blnd = bitcoin_cli.create_wallet("liquid_blnd").unwrap();

        // Initialize the money for each parties
        bitcoin_cli.mine(1, &wallet_user.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(1, &wallet_blnd.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(100, address_null).unwrap();

        let secp256k1 = Secp256k1::default();
        let sk_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let sk_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let pk_sig_user = PublicKey::from_private_key(&secp256k1, &PrivateKey::new(sk_user.clone(), bitcoin::Network::Regtest));
        let pk_sig_blnd = PublicKey::from_private_key(&secp256k1, &PrivateKey::new(sk_blnd.clone(), bitcoin::Network::Regtest));

        let script_funding = crate::script::new_funding_script(&pk_sig_user, &pk_sig_blnd);

        let funding_template_user = new_unsigned_transaction_funding_template(
            address_null,
            &bitcoin_cli,
            &wallet_user,
            30_0000_0000
        ).unwrap();
        let funding_template_blnd = new_unsigned_transaction_funding_template(
            address_null,
            &bitcoin_cli,
            &wallet_blnd,
            30_0000_0000
        ).unwrap();

        let funding_template = new_unsigned_transcation_funding(
            funding_template_user,
            funding_template_blnd,
            59_9990_0000,
            &script_funding
        );

        let funded_part_user = sign_transaction_funding(&funding_template, &wallet_user).unwrap();
        let funded_part_blnd = sign_transaction_funding(&funding_template, &wallet_blnd).unwrap();

        let funding_transaction = compose_transaction_funding(
            funded_part_user,
            funded_part_blnd,
        ).unwrap();
    
        bitcoin_cli.send_raw_transaction(&serialize_hex(&funding_transaction)).unwrap();
        bitcoin_cli.mine(6, address_null).unwrap();

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

        let script_commitment = new_commitment_script(
            2,
            4,
            &pk_sig_user,
            &pk_sig_blnd,
            &sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_user.to_bytes())).try_into().unwrap(),
            &sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_blnd.to_bytes())).try_into().unwrap(),
            &sk_pub_user.public_key(&secp),
            &sk_pub_blnd.public_key(&secp)
        );

        let commitment_transaction = new_unsigned_transcation_commitement(
            &funding_transaction.txid(),
            0,
            59_9980_0000,
            &script_commitment
        );
        let commitment_sig_user = sign_transaction(&commitment_transaction, 59_9990_0000, &sk_user, &script_funding).unwrap();
        let commitment_sig_blnd = sign_transaction(&commitment_transaction, 59_9990_0000, &sk_blnd, &script_funding).unwrap();
        let commitment_transaction = compose_transaction_multisig(
            commitment_transaction,
            commitment_sig_user,
            commitment_sig_blnd,
            &script_funding
        );

        bitcoin_cli.send_raw_transaction(&serialize_hex(&commitment_transaction)).unwrap();
        bitcoin_cli.mine(4, address_null).unwrap();

        let split_script = new_split_delivery_script(&pk_sig_user, &pk_sig_blnd);

        let split_transaction = new_unsigned_transaction_split_delivery(
            &commitment_transaction.txid(),
            0,
            20_0000_0000,
            19_9980_0000,
            19_9980_0000,
            &split_script,
            &Address::from_str(&wallet_user.get_new_address().unwrap()).unwrap(),
            &Address::from_str(&wallet_blnd.get_new_address().unwrap()).unwrap(),
            2
        );

        let split_sig_user = sign_transaction(
            &split_transaction,
            59_9980_0000,
            &sk_user,
            &script_commitment
        ).unwrap();
        let split_sig_blnd = sign_transaction(
            &split_transaction,
            59_9980_0000,
            &sk_blnd,
            &script_commitment
        ).unwrap();
        let split_transaction = compose_transaction_split(
            split_transaction,
            split_sig_user,
            split_sig_blnd,
            &script_commitment
        );

        bitcoin_cli.send_raw_transaction(&serialize_hex(&split_transaction)).unwrap();
        bitcoin_cli.mine(1, address_null).unwrap();

        let aded_transaction = new_unsigned_transaction_aed(
            &split_transaction.txid(),
            0,
            19_9990_0000, &Address::from_str(&wallet_blnd.get_new_address().unwrap()).unwrap()
        );
        let aded_sig_user = sign_transaction(
            &aded_transaction,
            20_0000_0000,
            &sk_user,
            &split_script
        ).unwrap();
        let aded_sig_lbnd = sign_transaction(
            &aded_transaction,
            20_0000_0000,
            &sk_blnd,
            &split_script
        ).unwrap();
        let aded_transaction = compose_transaction_multisig(aded_transaction, aded_sig_user, aded_sig_lbnd, &split_script);
        bitcoin_cli.send_raw_transaction(&serialize_hex(&aded_transaction)).unwrap();
        bitcoin_cli.mine(1, address_null).unwrap();
    }

    #[test]
    fn test_transaction_timeout(){
        // Initialize the testcontainer for bitcoin
        let docker = clients::Cli::default();
        let mut bitcoin_args = BitcoinCoreImageArgs::default();
        bitcoin_args.accept_non_std_txn = Some(true);
        let bitcoin_daemon = docker.run(RunnableImage::from(
            (BitcoinCore::default(), bitcoin_args)
        ));
        let bitcoin_auth = &bitcoin_daemon.image_args().rpc_auth;
        let bitcoin_base_url = format!("http://{}:{}@localhost:{}", bitcoin_auth.username(), bitcoin_auth.password(), bitcoin_daemon.get_host_port_ipv4(18443)).to_owned();
        let bitcoin_cli = Client::new(&bitcoin_base_url);

        // Initialize a meaningless address
        let address_null = "bcrt1q50cp8mzc0tqjuj0yyvp0hgekuuc33zrn9wd7rg";

        // Initialize the wallets for sender and tumbler
        let wallet_user = bitcoin_cli.create_wallet("liquid_user").unwrap();
        let wallet_blnd = bitcoin_cli.create_wallet("liquid_blnd").unwrap();

        // Initialize the money for each parties
        bitcoin_cli.mine(1, &wallet_user.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(1, &wallet_blnd.get_new_address().unwrap()).unwrap();
        bitcoin_cli.mine(100, address_null).unwrap();

        let secp256k1 = Secp256k1::default();
        let sk_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let sk_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let pk_sig_user = PublicKey::from_private_key(&secp256k1, &PrivateKey::new(sk_user.clone(), bitcoin::Network::Regtest));
        let pk_sig_blnd = PublicKey::from_private_key(&secp256k1, &PrivateKey::new(sk_blnd.clone(), bitcoin::Network::Regtest));

        let script_funding = crate::script::new_funding_script(&pk_sig_user, &pk_sig_blnd);

        let funding_template_user = new_unsigned_transaction_funding_template(
            address_null,
            &bitcoin_cli,
            &wallet_user,
            30_0000_0000
        ).unwrap();
        let funding_template_blnd = new_unsigned_transaction_funding_template(
            address_null,
            &bitcoin_cli,
            &wallet_blnd,
            30_0000_0000
        ).unwrap();

        let funding_template = new_unsigned_transcation_funding(
            funding_template_user,
            funding_template_blnd,
            59_9990_0000,
            &script_funding
        );

        let funded_part_user = sign_transaction_funding(&funding_template, &wallet_user).unwrap();
        let funded_part_blnd = sign_transaction_funding(&funding_template, &wallet_blnd).unwrap();

        let funding_transaction = compose_transaction_funding(
            funded_part_user,
            funded_part_blnd,
        ).unwrap();
    
        bitcoin_cli.send_raw_transaction(&serialize_hex(&funding_transaction)).unwrap();
        bitcoin_cli.mine(6, address_null).unwrap();

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

        let script_commitment = new_commitment_script(
            2,
            4,
            &pk_sig_user,
            &pk_sig_blnd,
            &sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_user.to_bytes())).try_into().unwrap(),
            &sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_blnd.to_bytes())).try_into().unwrap(),
            &sk_pub_user.public_key(&secp),
            &sk_pub_blnd.public_key(&secp)
        );

        let commitment_transaction = new_unsigned_transcation_commitement(
            &funding_transaction.txid(),
            0,
            59_9980_0000,
            &script_commitment
        );
        let commitment_sig_user = sign_transaction(&commitment_transaction, 59_9990_0000, &sk_user, &script_funding).unwrap();
        let commitment_sig_blnd = sign_transaction(&commitment_transaction, 59_9990_0000, &sk_blnd, &script_funding).unwrap();
        let commitment_transaction = compose_transaction_multisig(
            commitment_transaction,
            commitment_sig_user,
            commitment_sig_blnd,
            &script_funding
        );

        bitcoin_cli.send_raw_transaction(&serialize_hex(&commitment_transaction)).unwrap();
        bitcoin_cli.mine(4, address_null).unwrap();

        let split_script = new_split_delivery_script(&pk_sig_user, &pk_sig_blnd);

        let split_transaction = new_unsigned_transaction_split_delivery(
            &commitment_transaction.txid(),
            0,
            20_0000_0000,
            19_9980_0000,
            19_9980_0000,
            &split_script,
            &Address::from_str(&wallet_user.get_new_address().unwrap()).unwrap(),
            &Address::from_str(&wallet_blnd.get_new_address().unwrap()).unwrap(),
            2
        );

        let split_sig_user = sign_transaction(
            &split_transaction,
            59_9980_0000,
            &sk_user,
            &script_commitment
        ).unwrap();
        let split_sig_blnd = sign_transaction(
            &split_transaction,
            59_9980_0000,
            &sk_blnd,
            &script_commitment
        ).unwrap();
        let split_transaction = compose_transaction_split(
            split_transaction,
            split_sig_user,
            split_sig_blnd,
            &script_commitment
        );

        bitcoin_cli.send_raw_transaction(&serialize_hex(&split_transaction)).unwrap();
        bitcoin_cli.mine(4, address_null).unwrap();

        let tout_transaction = new_unsigned_transaction_timeout(
            &split_transaction.txid(),
            0,
            19_9990_0000,
            &Address::from_str(&wallet_blnd.get_new_address().unwrap()).unwrap(),
            3
        );
        let aded_sig_user = sign_transaction(
            &tout_transaction,
            20_0000_0000,
            &sk_user,
            &split_script
        ).unwrap();
        let aded_sig_lbnd = sign_transaction(
            &tout_transaction,
            20_0000_0000,
            &sk_blnd,
            &split_script
        ).unwrap();
        let tout_transaction = compose_transaction_multisig(tout_transaction, aded_sig_user, aded_sig_lbnd, &split_script);
        bitcoin_cli.send_raw_transaction(&serialize_hex(&tout_transaction)).unwrap();
        bitcoin_cli.mine(1, address_null).unwrap();
    }
}