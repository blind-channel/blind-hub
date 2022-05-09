use bitcoin::{PublicKey, Script, blockdata::{script, opcodes::all::*}};

pub fn new_funding_script(
    pk_sig_user: &PublicKey,
    pk_sig_blnd: &PublicKey
) -> Script {
    script::Builder::new()
        .push_int(2)
        .push_key(&pk_sig_user)
        .push_key(&pk_sig_blnd)
        .push_int(2)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

pub fn new_commitment_script(
    timelock_relative_split: u32,
    timelock_relative_punish: u32,
    pk_sig_user: &PublicKey,
    pk_sig_blnd: &PublicKey,
    rev_hash_user: &[u8;32], //revocation key
    rev_hash_blnd: &[u8;32],
    pk_pub_user: &PublicKey,
    pk_pub_blnd: &PublicKey
) -> Script {
    /*
        input: secretRev_B, secretAS_B, 0,    sigU 
           OR: secretRev_U, secretAS_U, sigB, 0
           OR: (after time delta)       sigB, sigU
           OR: (after time 2 * delta)   sigB, 0
     */
    script::Builder::new()
        .push_key(pk_sig_user)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_SWAP)
        .push_key(pk_sig_blnd)
        .push_opcode(OP_CHECKSIG)
        // Signature Blind is valid
        .push_opcode(OP_IF)
            // Signature User is valid
            .push_opcode(OP_IF)
                .push_int(timelock_relative_split.into())
                .push_opcode(OP_CSV)
                .push_opcode(OP_2DROP)
            // Signature User is NOT valid
            .push_opcode(OP_ELSE)
                .push_key(pk_pub_user) //Stack is either [0] or [0, secretRev_U, AS_U]
                .push_opcode(OP_CHECKSIG) //
                .push_opcode(OP_IF)
                    .push_opcode(OP_HASH256)
                    .push_slice(rev_hash_user)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_opcode(OP_DROP)
                .push_opcode(OP_ELSE)
                    .push_int((timelock_relative_punish).into())
                    .push_opcode(OP_CSV)
                    .push_opcode(OP_DROP)
                .push_opcode(OP_ENDIF)
            .push_opcode(OP_ENDIF)
        // Signature Blind is NOT valid
        .push_opcode(OP_ELSE)
            // Signature User is valid
            .push_opcode(OP_IF)
                .push_key(pk_pub_blnd)
                .push_opcode(OP_CHECKSIGVERIFY)
                .push_opcode(OP_HASH256)
                .push_slice(rev_hash_blnd)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_DROP)
            // Signature User is NOT valid
            .push_opcode(OP_ELSE)
                .push_opcode(OP_RETURN)
            // Signature Blind is NOT valid
            .push_opcode(OP_ENDIF)
        .push_opcode(OP_ENDIF)
        .push_int(1)
        .into_script()
}

pub fn new_split_delivery_script(
    pk_sig_user: &PublicKey,
    pk_sig_blnd: &PublicKey
) -> Script {
    script::Builder::new()
        .push_int(2)
        .push_key(&pk_sig_user)
        .push_key(&pk_sig_blnd)
        .push_int(2)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

#[cfg(test)]
mod tests{
    use bitcoin::{secp256k1::{Secp256k1, Message}, PrivateKey, Transaction, TxIn, OutPoint, Txid, Witness, util::sighash::SighashCache, Amount, EcdsaSighashType, TxOut};
    use curv::elliptic::curves::{secp256_k1::Secp256k1Scalar, ECScalar};
    use sha2::Digest;
    use crate::script::*;

    #[test]
    fn test_commitment_script() {
        let secp = Secp256k1::default();
        let sk_user = PrivateKey::new(
            Secp256k1Scalar::random().underlying_ref().clone().unwrap().0,
            bitcoin::Network::Regtest
        );
        let sk_blnd = PrivateKey::new(
            Secp256k1Scalar::random().underlying_ref().clone().unwrap().0,
            bitcoin::Network::Regtest
        );
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
        let com_script = new_commitment_script(
            1,
            2,
            &sk_user.public_key(&secp),
            &sk_blnd.public_key(&secp),
            &sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_user.to_bytes())).try_into().unwrap(),
            &sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_blnd.to_bytes())).try_into().unwrap(),
            &sk_pub_user.public_key(&secp),
            &sk_pub_blnd.public_key(&secp)
        );
        let mut following_transacion = Transaction{
            version: 2,
            lock_time: 0,
            input: vec![
                TxIn{
                    previous_output: OutPoint {
                        txid: Txid::default(),
                        vout: 0
                    },
                    script_sig: Script::new(),
                    sequence: 2,
                    witness: Witness::new(),
                }
            ],
            output: vec![],
        };
        let mut following_transacion_hash = SighashCache::new(&following_transacion);
        let following_transacion_sighash = following_transacion_hash.segwit_signature_hash(
            0,
            &com_script,
            Amount::from_sat(50000).as_sat(),
            EcdsaSighashType::All
        ).unwrap();
        let following_transacion_sig_user = secp.sign_ecdsa_low_r(
            &Message::from_slice(&following_transacion_sighash).unwrap(),
            &sk_user.inner
        );
        let following_transacion_sig_blnd = secp.sign_ecdsa_low_r(
            &Message::from_slice(&following_transacion_sighash).unwrap(),
            &sk_blnd.inner
        );
        let following_transacion_sig_pub_user = secp.sign_ecdsa_low_r(
            &Message::from_slice(&following_transacion_sighash).unwrap(),
            &sk_pub_user.inner
        );
        let following_transacion_sig_pub_blnd = secp.sign_ecdsa_low_r(
            &Message::from_slice(&following_transacion_sighash).unwrap(),
            &sk_pub_blnd.inner
        );

        //Signature of user and blind are valid
        following_transacion.input[0].witness.clear();
        following_transacion.input[0].witness.push(&[]);
        following_transacion.input[0].witness.push(&[following_transacion_sig_blnd.serialize_der().as_ref(), &[1u8]].concat());
        following_transacion.input[0].witness.push(&[following_transacion_sig_user.serialize_der().as_ref(), &[1u8]].concat());
        following_transacion.input[0].witness.push(com_script.as_bytes());
        following_transacion.verify(|_: &OutPoint|{
            Some(TxOut{
                value: 50000,
                script_pubkey: com_script.to_v0_p2wsh(),
            })
        }).unwrap();

        //Signature of blind is valid
        following_transacion.input[0].witness.clear();
        following_transacion.input[0].witness.push(&[]);
        following_transacion.input[0].witness.push(&rev_cred_user.to_bytes());
        following_transacion.input[0].witness.push(&[following_transacion_sig_pub_user.serialize_der().as_ref(), &[1u8]].concat());
        following_transacion.input[0].witness.push(&[following_transacion_sig_blnd.serialize_der().as_ref(), &[1u8]].concat());
        following_transacion.input[0].witness.push(&[]);
        following_transacion.input[0].witness.push(com_script.as_bytes());
        following_transacion.verify(|_: &OutPoint|{
            Some(TxOut{
                value: 50000,
                script_pubkey: com_script.to_v0_p2wsh(),
            })
        }).unwrap();

        //Signature of user is valid
        following_transacion.input[0].witness.clear();
        following_transacion.input[0].witness.push(&[]);
        following_transacion.input[0].witness.push(&rev_cred_blnd.to_bytes());
        following_transacion.input[0].witness.push(&[following_transacion_sig_pub_blnd.serialize_der().as_ref(), &[1u8]].concat());
        following_transacion.input[0].witness.push(&[]);
        following_transacion.input[0].witness.push(&[following_transacion_sig_user.serialize_der().as_ref(), &[1u8]].concat());
        following_transacion.input[0].witness.push(com_script.as_bytes());
        following_transacion.verify(|_: &OutPoint|{
            Some(TxOut{
                value: 50000,
                script_pubkey: com_script.to_v0_p2wsh(),
            })
        }).unwrap();

        //Reach 2T time
        following_transacion.input[0].witness.clear();
        following_transacion.input[0].witness.push(&[]);
        following_transacion.input[0].witness.push(&[following_transacion_sig_blnd.serialize_der().as_ref(), &[1u8]].concat());
        following_transacion.input[0].witness.push(&[]);
        following_transacion.input[0].witness.push(com_script.as_bytes());
        following_transacion.verify(|_: &OutPoint|{
            Some(TxOut{
                value: 50000,
                script_pubkey: com_script.to_v0_p2wsh(),
            })
        }).unwrap();
    }
}