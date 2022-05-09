use std::io::BufWriter;

use bitcoin::{Transaction, Script, EcdsaSighashType, consensus::Encodable, util::sighash::SighashCache};
use sha2::Digest;

pub fn encode_mpc_txin(transaction: &Transaction) -> anyhow::Result<[u8;12]> {
    if transaction.input.len() != 1 {
        return Err(anyhow::anyhow!("input length != 1 or index != 0"))
    }
    let mut result = [0u8;12];
    let txin = &transaction.input[0];
    result[ 0.. 3].copy_from_slice(txin.previous_output.txid.as_ref());
    result[ 4.. 7].copy_from_slice(&txin.previous_output.vout.to_le_bytes());
    result[ 8..11].copy_from_slice(&txin.sequence.to_le_bytes());
    Ok(result)
}

pub fn encode_mpc_hash_sequence(sequence: u32) -> [u8;4] {
    sequence.to_le_bytes()
}

fn encode_mpc_txout(transaction: &Transaction) -> anyhow::Result<Vec<u8>> {
    let mut result = Vec::new();
    for txout in &transaction.output {
        result.extend(txout.value.to_le_bytes());
        result.push(txout.script_pubkey.as_ref().len() as u8);
        result.extend(txout.script_pubkey.as_ref());
    }
    Ok(result)
}

pub fn encode_mpc_txout_split_delivery(transaction: &Transaction) -> anyhow::Result<[u8;105]> {
    encode_mpc_txout(transaction)?.try_into().map_err(|_|anyhow::anyhow!("invalid transaction output"))
}

pub fn encode_mpc_txout_split_final(transaction: &Transaction) -> anyhow::Result<[u8;62]> {
    encode_mpc_txout(transaction)?.try_into().map_err(|_|anyhow::anyhow!("invalid transaction output"))
}

pub fn encode_mpc_txout_multisig(transaction: &Transaction) -> anyhow::Result<[u8;31]> {
    encode_mpc_txout(transaction)?.try_into().map_err(|_|anyhow::anyhow!("invalid transaction output"))
}

pub fn encode_mpc_split_delivery(
    split_transaction: &Transaction,
    commitment_script: &Script,
    commitment_output_amount: u64
) -> anyhow::Result<[u8;463]>{
    if split_transaction.input.len() != 1{
        return Err(anyhow::anyhow!("input length != 1 or index != 0"))
    }
    let hash_prevouts  = sha2::Sha256::digest(&sha2::Sha256::digest(
        &[split_transaction.input[0].previous_output.txid.as_ref(), &split_transaction.input[0].previous_output.vout.to_le_bytes()].concat()
    ));
    let hash_sequence  = sha2::Sha256::digest(&sha2::Sha256::digest(&split_transaction.input[0].sequence.to_le_bytes()));

    let mut result = [0u8; 463];
    result[0  ..  4].copy_from_slice(&split_transaction.version.to_le_bytes());
    result[4  .. 36].copy_from_slice(&hash_prevouts);
    result[36 .. 68].copy_from_slice(&hash_sequence);
    result[68 ..100].copy_from_slice(&split_transaction.input[0].previous_output.txid.as_ref());
    result[100..104].copy_from_slice(&split_transaction.input[0].previous_output.vout.to_le_bytes());
    result[104..105].copy_from_slice(&[233u8]);
    result[105..338].copy_from_slice(&commitment_script.as_ref());
    result[338..346].copy_from_slice(&commitment_output_amount.to_le_bytes());
    result[346..350].copy_from_slice(&split_transaction.input[0].sequence.to_le_bytes());
    // encoded_all.extend_from_slice(&hash_outputs);
    result[350..354].copy_from_slice(&split_transaction.lock_time.to_le_bytes());
    result[354..358].copy_from_slice(&(EcdsaSighashType::All as u32).to_le_bytes());
    result[358..463].copy_from_slice(&encode_mpc_txout_split_delivery(&split_transaction)?);

    Ok(result)
}

pub fn encode_mpc_split_final(
    split_transaction: &Transaction,
    commitment_script: &Script,
    commitment_output_amount: u64)
-> anyhow::Result<[u8;420]> {
    if split_transaction.input.len() != 1{
        return Err(anyhow::anyhow!("input length != 1 or index != 0"))
    }
    let hash_prevouts  = sha2::Sha256::digest(&sha2::Sha256::digest(
        &[split_transaction.input[0].previous_output.txid.as_ref(), &split_transaction.input[0].previous_output.vout.to_le_bytes()].concat()
    ));
    let hash_sequence  = sha2::Sha256::digest(&sha2::Sha256::digest(&split_transaction.input[0].sequence.to_le_bytes()));

    let mut result = [0u8; 420];
    result[0  ..  4].copy_from_slice(&split_transaction.version.to_le_bytes());
    result[4  .. 36].copy_from_slice(&hash_prevouts);
    result[36 .. 68].copy_from_slice(&hash_sequence);
    result[68 ..100].copy_from_slice(&split_transaction.input[0].previous_output.txid.as_ref());
    result[100..104].copy_from_slice(&split_transaction.input[0].previous_output.vout.to_le_bytes());
    result[104..105].copy_from_slice(&[233u8]);
    result[105..338].copy_from_slice(&commitment_script.as_ref());
    result[338..346].copy_from_slice(&commitment_output_amount.to_le_bytes());
    result[346..350].copy_from_slice(&split_transaction.input[0].sequence.to_le_bytes());
    // encoded_all.extend_from_slice(&hash_outputs);
    result[350..354].copy_from_slice(&split_transaction.lock_time.to_le_bytes());
    result[354..358].copy_from_slice(&(EcdsaSighashType::All as u32).to_le_bytes());
    result[358..359].copy_from_slice(&[22u8]);
    result[359..381].copy_from_slice(&split_transaction.output[0].script_pubkey.as_bytes());
    result[381..382].copy_from_slice(&[22u8]);
    result[382..404].copy_from_slice(&split_transaction.output[1].script_pubkey.as_bytes());
    result[404..412].copy_from_slice(&split_transaction.output[0].value.to_le_bytes());
    result[412..420].copy_from_slice(&split_transaction.output[1].value.to_le_bytes());
    // dbg!(format!("Version     : {}", calc_index(000, 004, 420)));
    // dbg!(format!("HashPrevouts: {}", calc_index(004, 036, 420)));
    // dbg!(format!("HashSequence: {}", calc_index(036, 068, 420)));
    // dbg!(format!("In[0].txid  : {}", calc_index(068, 100, 420)));
    // dbg!(format!("In[0].vout  : {}", calc_index(100, 104, 420)));
    // dbg!(format!("ScriptCode  : {}", calc_index(104, 338, 420)));
    // dbg!(format!("In[0].amount: {}", calc_index(338, 346, 420)));
    // dbg!(format!("In[0].seq   : {}", calc_index(346, 350, 420)));
    // dbg!(format!("Locktime    : {}", calc_index(350, 354, 420)));
    // dbg!(format!("SighashType : {}", calc_index(354, 358, 420)));
    // dbg!(format!("out[0].val  : {}", calc_index(404, 412, 420)));
    // dbg!(format!("out[0].scrpt: {}", calc_index(358, 381, 420)));
    // dbg!(format!("out[1].val  : {}", calc_index(412, 420, 420)));
    // dbg!(format!("out[1].scrpt: {}", calc_index(381, 404, 420)));

    Ok(result)
}

pub fn encode_mpc_split_delivery_result(
    transaction: &Transaction,
    script_txin: &Script,
    input_amount: u64,
    transfer_amount: u64,
    payback_amount_user: u64,
    payback_amount_blnd: u64
) -> anyhow::Result<Vec<u8>>{
    Ok([
        transfer_amount.to_le_bytes().as_slice(),
        payback_amount_user.to_le_bytes().as_slice(),
        payback_amount_blnd.to_le_bytes().as_slice(),
        &transaction.txid().to_vec(),
        SighashCache::new(transaction).segwit_signature_hash(
            0, 
            script_txin, 
            input_amount, 
            EcdsaSighashType::All
        )?.as_ref()
    ].concat())
}


pub fn encode_mpc_split_input(
    transaction: &Transaction
) -> anyhow::Result<[u8;42]>{
    if transaction.input.len() != 1{
        return Err(anyhow::anyhow!("input length != 1 or index != 0"))
    }
    let mut result = Vec::new();
    transaction.input.consensus_encode(BufWriter::new(&mut result))?;
    result.try_into().map_err(|_| anyhow::anyhow!("encoded length is not 42"))
}

pub fn encode_mpc_multisig(
    transaction: &Transaction,
    script_txin: &Script,
    amount: u64)
-> anyhow::Result<[u8;227]> {
    if transaction.input.len() != 1{
        return Err(anyhow::anyhow!("input length != 1 or index != 0"))
    }
    let hash_prevouts  = sha2::Sha256::digest(&sha2::Sha256::digest(
        &[transaction.input[0].previous_output.txid.as_ref(), &transaction.input[0].previous_output.vout.to_le_bytes()].concat()
    ));
    let hash_sequence  = sha2::Sha256::digest(&sha2::Sha256::digest(&transaction.input[0].sequence.to_le_bytes()));

    let mut result = [0u8; 227];
    result[0  ..  4].copy_from_slice(&transaction.version.to_le_bytes());
    result[4  .. 36].copy_from_slice(&hash_prevouts);
    result[36 .. 68].copy_from_slice(&hash_sequence);
    result[68 ..100].copy_from_slice(&transaction.input[0].previous_output.txid.as_ref());
    result[100..104].copy_from_slice(&transaction.input[0].previous_output.vout.to_le_bytes());
    result[104..105].copy_from_slice(&[71u8]);
    result[105..176].copy_from_slice(&script_txin.as_ref());
    result[176..184].copy_from_slice(&amount.to_le_bytes());
    result[184..188].copy_from_slice(&transaction.input[0].sequence.to_le_bytes());
    // encoded_all.extend_from_slice(&hash_outputs);
    result[188..192].copy_from_slice(&transaction.lock_time.to_le_bytes());
    result[192..196].copy_from_slice(&(EcdsaSighashType::All as u32).to_le_bytes());
    result[196..227].copy_from_slice(&encode_mpc_txout_multisig(&transaction)?);
    dbg!(format!("Version     : {}", calc_index(000, 004, 227)));
    dbg!(format!("In[0].txid  : {}", calc_index(068, 100, 227)));
    dbg!(format!("In[0].vout  : {}", calc_index(100, 104, 227)));
    dbg!(format!("HashSequence: {}", calc_index(036, 068, 227)));
    dbg!(format!("ScriptCode  : {}", calc_index(104, 176, 227)));
    dbg!(format!("In[0].amount: {}", calc_index(176, 184, 227)));
    dbg!(format!("In[0].seq   : {}", calc_index(184, 188, 227)));
    dbg!(format!("Locktime    : {}", calc_index(188, 192, 227)));
    dbg!(format!("SighashType : {}", calc_index(192, 196, 227)));

    Ok(result)
}

pub fn encode_mpc_all(
    transaction_split: &Transaction,
    transaction_txaed: &Transaction,
    transaction_tmout: &Transaction,
    script_comit: &Script,
    script_split: &Script,
    amount_split_in: u64,
    fee: u64
) -> anyhow::Result<[u8;765]> {
    let split_hash_prevouts  = sha2::Sha256::digest(&sha2::Sha256::digest(&[
        transaction_split.input[0].previous_output.txid.as_ref(),
        &transaction_split.input[0].previous_output.vout.to_le_bytes()
    ].concat()));
    let split_hash_sequence  = sha2::Sha256::digest(&sha2::Sha256::digest(
        &transaction_split.input[0].sequence.to_le_bytes()
    ));
    let aed_hash_sequence  = sha2::Sha256::digest(&sha2::Sha256::digest(
        &transaction_txaed.input[0].sequence.to_le_bytes()
    ));
    let timeout_hash_sequence  = sha2::Sha256::digest(&sha2::Sha256::digest(
        &transaction_tmout.input[0].sequence.to_le_bytes()
    ));

    let mut encoded_all = [0u8;765];
    // Transaction Split
    encoded_all[000..004].copy_from_slice(&transaction_split.version.to_le_bytes());
    encoded_all[004..036].copy_from_slice(&split_hash_prevouts);
    encoded_all[036..068].copy_from_slice(&split_hash_sequence);
    encoded_all[068..100].copy_from_slice(&transaction_split.input[0].previous_output.txid.as_ref());
    encoded_all[100..104].copy_from_slice(&transaction_split.input[0].previous_output.vout.to_le_bytes());
    encoded_all[104..105].copy_from_slice(&[233u8]);
    encoded_all[105..338].copy_from_slice(&script_comit.as_ref());
    encoded_all[338..346].copy_from_slice(&amount_split_in.to_le_bytes());
    encoded_all[346..350].copy_from_slice(&transaction_split.input[0].sequence.to_le_bytes());
    encoded_all[350..354].copy_from_slice(&transaction_split.lock_time.to_le_bytes());
    encoded_all[354..358].copy_from_slice(&(EcdsaSighashType::All as u32).to_le_bytes());
    // Transaction AED
    encoded_all[358..362].copy_from_slice(&transaction_txaed.version.to_le_bytes());
    encoded_all[362..394].copy_from_slice(&aed_hash_sequence);
    encoded_all[394..398].copy_from_slice(&transaction_txaed.input[0].previous_output.vout.to_le_bytes());
    encoded_all[398..399].copy_from_slice(&[71u8]);
    encoded_all[399..470].copy_from_slice(&script_split.as_ref());
    encoded_all[470..474].copy_from_slice(&transaction_txaed.input[0].sequence.to_le_bytes());
    encoded_all[474..478].copy_from_slice(&transaction_txaed.lock_time.to_le_bytes());
    encoded_all[478..482].copy_from_slice(&(EcdsaSighashType::All as u32).to_le_bytes());
    // Transaction Timeout
    encoded_all[482..486].copy_from_slice(&transaction_tmout.version.to_le_bytes());
    encoded_all[486..518].copy_from_slice(&timeout_hash_sequence);
    encoded_all[518..522].copy_from_slice(&transaction_tmout.input[0].previous_output.vout.to_le_bytes());
    encoded_all[522..523].copy_from_slice(&[71u8]);
    encoded_all[523..594].copy_from_slice(&script_split.as_ref());
    encoded_all[594..598].copy_from_slice(&transaction_tmout.input[0].sequence.to_le_bytes());
    encoded_all[598..602].copy_from_slice(&transaction_tmout.lock_time.to_le_bytes());
    encoded_all[602..606].copy_from_slice(&(EcdsaSighashType::All as u32).to_le_bytes());
    // Output Scripts
    encoded_all[606..607].copy_from_slice(&[34u8]);
    encoded_all[607..641].copy_from_slice(&transaction_split.output[0].script_pubkey.as_bytes());
    encoded_all[641..642].copy_from_slice(&[22u8]);
    encoded_all[642..664].copy_from_slice(&transaction_split.output[1].script_pubkey.as_bytes());
    encoded_all[664..665].copy_from_slice(&[22u8]);
    encoded_all[665..687].copy_from_slice(&transaction_split.output[2].script_pubkey.as_bytes());
    encoded_all[687..688].copy_from_slice(&[22u8]);
    encoded_all[688..710].copy_from_slice(&transaction_txaed.output[0].script_pubkey.as_bytes());
    encoded_all[710..711].copy_from_slice(&[22u8]);
    encoded_all[711..733].copy_from_slice(&transaction_tmout.output[0].script_pubkey.as_bytes());
    // Fee
    encoded_all[733..741].copy_from_slice(&fee.to_le_bytes());
    // Secret (amount)
    encoded_all[741..749].copy_from_slice(&transaction_split.output[0].value.to_le_bytes());
    encoded_all[749..757].copy_from_slice(&transaction_split.output[1].value.to_le_bytes());
    encoded_all[757..765].copy_from_slice(&transaction_split.output[2].value.to_le_bytes());
    Ok(encoded_all)
}

// pub struct PublicData{
//     transaction_split: Transaction,
//     transaction_txaed: Transaction,
//     transaction_tmout: Transaction,
//     script_comit: Script,
//     script_split: Script,
//     amount_split_in: u64,
//     fee: u64
// }

// pub fn decode_mpc_all(encoded_all: &[u8]) -> anyhow::Result<PublicData> {
//     let script_commitment = Script::from(encoded_all[105..338].to_vec());
//     let amount_split_in = u64::from_le_bytes(encoded_all[100..104].try_into()?);
//     let transaction_split = Transaction{
//         version: i32::from_le_bytes(encoded_all[000..004].try_into()?),
//         input: vec![
//             TxIn{
//                previous_output: OutPoint{
//                     txid: Txid::from_slice(&encoded_all[068..100])?,
//                     vout: u32::from_le_bytes(encoded_all[100..104].try_into()?)
//                },
//                sequence: u32::from_le_bytes(encoded_all[346..350].try_into()?),
//                script_sig: Script::new(),
//                witness: Witness::new()
//             }
//         ],
//         output: vec![
//             TxOut{
//                 value: 0,
//                 script_pubkey: Script::from(encoded_all[607..641].to_vec())
//             },
//             TxOut{
//                 value: 0,
//                 script_pubkey: Script::from(encoded_all[642..664].to_vec())
//             },
//             TxOut{
//                 value: 0,
//                 script_pubkey: Script::from(encoded_all[665..687].to_vec())
//             }
//         ],
//         lock_time: u32::from_le_bytes(encoded_all[350..354].try_into()?),
//     };
//     let split_hash_prevouts = &encoded_all[004..036];
//     let split_hash_sequence = &encoded_all[036..068];
//     let split_hash_prevouts_comp = Sha256::digest(&Sha256::digest(&encoded_all[068..104]));
//     if split_hash_prevouts != split_hash_prevouts_comp.to_vec() {
//         return Err(anyhow::anyhow!("split transaction hash prevouts errors"));
//     }
//     if encoded_all[104] != 233u8 {
//         return Err(anyhow::anyhow!("invalid commitment script length"));
//     }
//     if &(EcdsaSighashType::All as u32).to_le_bytes() != &encoded_all[354..358] {
//         return Err(anyhow::anyhow!("sighash type errror"));
//     }
//     if encoded_all[606] != 34u8 {
//         return Err(anyhow::anyhow!("invalid split output[0] script length"));
//     }
//     if encoded_all[641] != 22u8 {
//         return Err(anyhow::anyhow!("invalid split output[1] script length"));
//     }
//     if encoded_all[664] != 22u8 {
//         return Err(anyhow::anyhow!("invalid split output[2] script length"));
//     }
//     if encoded_all[687] != 22u8 {
//         return Err(anyhow::anyhow!("invalid split output[2] script length"));
//     }
//     if encoded_all[710] != 22u8 {
//         return Err(anyhow::anyhow!("invalid split output[2] script length"));
//     }

//     // Transaction AED
//     encoded_all[358..362].copy_from_slice(&transaction_txaed.version.to_le_bytes());
//     encoded_all[362..394].copy_from_slice(&aed_hash_sequence);
//     encoded_all[394..398].copy_from_slice(&transaction_txaed.input[0].previous_output.vout.to_le_bytes());
//     encoded_all[398..399].copy_from_slice(&[71u8]);
//     encoded_all[399..470].copy_from_slice(&script_split.as_ref());
//     encoded_all[470..474].copy_from_slice(&transaction_txaed.input[0].sequence.to_le_bytes());
//     encoded_all[474..478].copy_from_slice(&transaction_txaed.lock_time.to_le_bytes());
//     encoded_all[478..482].copy_from_slice(&(EcdsaSighashType::All as u32).to_le_bytes());
//     // Transaction Timeout
//     encoded_all[482..486].copy_from_slice(&transaction_tmout.version.to_le_bytes());
//     encoded_all[486..518].copy_from_slice(&timeout_hash_sequence);
//     encoded_all[518..522].copy_from_slice(&transaction_tmout.input[0].previous_output.vout.to_le_bytes());
//     encoded_all[522..523].copy_from_slice(&[71u8]);
//     encoded_all[523..594].copy_from_slice(&script_split.as_ref());
//     encoded_all[594..598].copy_from_slice(&transaction_tmout.input[0].sequence.to_le_bytes());
//     encoded_all[598..602].copy_from_slice(&transaction_tmout.lock_time.to_le_bytes());
//     encoded_all[602..606].copy_from_slice(&(EcdsaSighashType::All as u32).to_le_bytes());
//     // Output Scripts
//     encoded_all[687..688].copy_from_slice(&[22u8]);
//     encoded_all[688..710].copy_from_slice(&transaction_txaed.output[0].script_pubkey.as_bytes());
//     encoded_all[710..711].copy_from_slice(&[22u8]);
//     encoded_all[711..733].copy_from_slice(&transaction_tmout.output[0].script_pubkey.as_bytes());
//     // Fee
//     let fee = u64::from_le_bytes(encoded_all[733..741].try_into()?);;
//     Ok(PublicData {
//         transaction_split,
//         transaction_txaed: todo!(),
//         transaction_tmout: todo!(),
//         script_comit: todo!(),
//         script_split: todo!(),
//         amount_split_in,
//         fee,
//     })
// }


pub fn calc_index(
    l: usize,
    r: usize,
    len: usize,
) -> String {
    format!("[{:04}:{:04}]", 8 * (len - l) - 1, 8 * (len - r))
}

#[cfg(test)]
mod tests {
    use bitcoin::{PublicKey, PrivateKey, Address, secp256k1::{Secp256k1, Message}, Txid, TxOut, hashes::{hex::ToHex, Hash}, util::sighash::SighashCache, EcdsaSighashType};
    use curv::elliptic::curves::{secp256_k1::Secp256k1Scalar, ECScalar};
    use fancy_garbling::encode_boolean;
    use sha2::{Digest, Sha256};
    use crate::{transaction::{compose_transaction_split, new_unsigned_transaction_split_delivery, new_unsigned_transaction_aed, compose_transaction_multisig, new_unsigned_transaction_timeout, new_unsigned_transaction_split_final}, script::{new_commitment_script, new_split_delivery_script}, encoder::{encode_mpc_split_input, encode_mpc_split_delivery_result, encode_mpc_split_final}};
    use super::{encode_mpc_multisig, encode_mpc_all};
    use std::str::FromStr;

    use super::encode_mpc_split_delivery;

    #[test]
    fn test_transaction_transfer_split() {
        let dummy_txid: Txid = Txid::from_str("2df0ce8b422af8aa1a0ea5cf3f2db50d33a9355281897d1193fedbbda6e41c07").unwrap();
        let dummy_addr_user: Address = Address::from_str("bcrt1qxzgp4utr352vp7rq79k97q6nuf6c3emyrumz68").unwrap();
        let dummy_addr_blnd: Address = Address::from_str("bcrt1qun5x7r2ft88gdxltjfjl3m3n6537ps8sypfttm").unwrap();

        let secp = Secp256k1::default();
        let sk_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let sk_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let pk_sig_user = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_user.clone(), bitcoin::Network::Regtest));
        let pk_sig_blnd = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_blnd.clone(), bitcoin::Network::Regtest));
        let rev_cred_user = PrivateKey::new(Secp256k1Scalar::random().underlying_ref().clone().unwrap().0, bitcoin::Network::Regtest);
        let rev_cred_blnd = PrivateKey::new(Secp256k1Scalar::random().underlying_ref().clone().unwrap().0, bitcoin::Network::Regtest);
        let sk_pub_user = PrivateKey::new(Secp256k1Scalar::random().underlying_ref().clone().unwrap().0, bitcoin::Network::Regtest);
        let sk_pub_blnd = PrivateKey::new(Secp256k1Scalar::random().underlying_ref().clone().unwrap().0, bitcoin::Network::Regtest);

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

        let script_split = new_split_delivery_script(&pk_sig_user, &pk_sig_blnd);

        let split_transaction = new_unsigned_transaction_split_delivery(
            &dummy_txid,
            0,
            10_0000_0000,
            10_5000_0000,
            20_0000_0000,
            &script_split,
            &dummy_addr_user,
            &dummy_addr_blnd,
            2
        );
        let split_sig_encode = encode_mpc_split_delivery(&split_transaction, &script_commitment, 59_9980_0000).unwrap();
        dbg!(split_sig_encode.to_hex());

        let split_sig_encode_binary = encode_boolean(&split_sig_encode.to_hex(), true).unwrap();
        assert_eq!(split_sig_encode_binary[776..840], encode_boolean(&10_0000_0000_u64.to_le_bytes().to_hex(), true).unwrap());
        assert_eq!(split_sig_encode_binary[432..496], encode_boolean(&10_5000_0000_u64.to_le_bytes().to_hex(), true).unwrap());
        assert_eq!(split_sig_encode_binary[184..248], encode_boolean(&20_0000_0000_u64.to_le_bytes().to_hex(), true).unwrap());
        let split_txid_encode = [
            &split_sig_encode[0  ..  4],
            &[01u8],
            &split_sig_encode[68 ..100],
            &split_sig_encode[100..104],
            &[00u8],
            &split_sig_encode[346..350],
            &[03u8],
            &split_sig_encode[358..463],
            &split_sig_encode[350..354]
        ].concat();
        let split_txid_encode_comp = [
            &split_sig_encode[0  ..  4],
            &encode_mpc_split_input(&split_transaction).unwrap(),
            &[03u8],
            &split_sig_encode[358..463],
            &split_sig_encode[350..354]
        ].concat();
        assert_eq!(split_txid_encode.to_hex(), split_txid_encode_comp.to_hex());
        // dbg!(split_txid_encode.len());

        // let mut split_txid_encode_comp = Vec::new();
        // split_transaction.version.consensus_encode(&mut split_txid_encode_comp).expect("engines don't error");
        // split_transaction.input.consensus_encode(&mut split_txid_encode_comp).expect("engines don't error");
        // split_transaction.output.consensus_encode(&mut split_txid_encode_comp).expect("engines don't error");
        // split_transaction.lock_time.consensus_encode(&mut split_txid_encode_comp).expect("engines don't error");
        // assert_eq!(split_txid_encode.to_hex(), split_txid_encode_comp.to_hex());

        // dbg!(split_txid_encode.to_hex());
        // dbg!(split_transaction.txid().to_vec().to_hex());
        assert_eq!(&split_transaction.txid().to_vec(), Sha256::digest(&Sha256::digest(split_txid_encode)).as_slice());

        let split_sig_encode = [
            &split_sig_encode[..350],
            &Sha256::digest(&Sha256::digest(&split_sig_encode[358..463])),
            &split_sig_encode[350..358]
        ].concat();

        let split_sig_hash = Sha256::digest(&Sha256::digest(&split_sig_encode));
        let split_sig_circuit_result = [
            10_0000_0000_u64.to_le_bytes().as_slice(),
            10_5000_0000_u64.to_le_bytes().as_slice(),
            20_0000_0000_u64.to_le_bytes().as_slice(),
            &split_transaction.txid(),
            &split_sig_hash
        ].concat();
        assert_eq!(split_sig_circuit_result, encode_mpc_split_delivery_result(
            &split_transaction,
            &script_commitment,
            59_9980_0000,
            10_0000_0000,
            10_5000_0000,
            20_0000_0000
        ).unwrap());
        dbg!(split_sig_circuit_result.to_hex());
        let split_sig_user = secp.sign_ecdsa_low_r(&Message::from_slice(&split_sig_hash).unwrap(), &sk_user);
        let split_sig_blnd = secp.sign_ecdsa_low_r(&Message::from_slice(&split_sig_hash).unwrap(), &sk_blnd);

        let split_transaction = compose_transaction_split(
            split_transaction,
            split_sig_user,
            split_sig_blnd,
            &script_commitment
        );
        split_transaction.verify(|_|{Some(TxOut{ value: 59_9980_0000, script_pubkey: script_commitment.to_v0_p2wsh() })}).unwrap();
    }

    #[test]
    fn test_transaction_aed() {
        let dummy_txid: Txid = Txid::from_str("2df0ce8b422af8aa1a0ea5cf3f2db50d33a9355281897d1193fedbbda6e41c07").unwrap();
        let dummy_addr_blnd: Address = Address::from_str("bcrt1qun5x7r2ft88gdxltjfjl3m3n6537ps8sypfttm").unwrap();

        let secp = Secp256k1::default();
        let sk_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let sk_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let pk_sig_user = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_user.clone(), bitcoin::Network::Regtest));
        let pk_sig_blnd = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_blnd.clone(), bitcoin::Network::Regtest));

        let script_split = new_split_delivery_script(&pk_sig_user, &pk_sig_blnd);

        let aed_transaction = new_unsigned_transaction_aed(
            &dummy_txid,
            0,
            10_0000_0000,
            &dummy_addr_blnd,
        );

        let aed_sig_encode = encode_mpc_multisig(
            &aed_transaction,
            &script_split,
            59_9980_0000
        ).unwrap();

        let aed_sig_hash_prevouts = sha2::Sha256::digest(&sha2::Sha256::digest(
            &[aed_transaction.input[0].previous_output.txid.as_ref(), &aed_transaction.input[0].previous_output.vout.to_le_bytes()].concat()
        ));
        dbg!(aed_sig_encode.to_hex());

        let aed_sig_encode = [
            &aed_sig_encode[..188],
            &Sha256::digest(&Sha256::digest(&aed_sig_encode[196..227])),
            &aed_sig_encode[188..196]
        ].concat();

        let aed_sig_hash = Sha256::digest(&Sha256::digest(&aed_sig_encode));
        let aed_sig_user = secp.sign_ecdsa_low_r(&Message::from_slice(&aed_sig_hash).unwrap(), &sk_user);
        let aed_sig_blnd = secp.sign_ecdsa_low_r(&Message::from_slice(&aed_sig_hash).unwrap(), &sk_blnd);

        dbg!([aed_sig_hash_prevouts, aed_sig_hash].concat().to_hex());

        let aed_transaction = compose_transaction_multisig(
            aed_transaction,
            aed_sig_user,
            aed_sig_blnd,
            &script_split
        );
        aed_transaction.verify(|_|{Some(TxOut{ value: 59_9980_0000, script_pubkey: script_split.to_v0_p2wsh() })}).unwrap();
    }


    #[test]
    fn test_transaction_split_final() {
        let dummy_txid: Txid = Txid::from_str("2df0ce8b422af8aa1a0ea5cf3f2db50d33a9355281897d1193fedbbda6e41c07").unwrap();
        let dummy_addr_user: Address = Address::from_str("bcrt1qxzgp4utr352vp7rq79k97q6nuf6c3emyrumz68").unwrap();
        let dummy_addr_blnd: Address = Address::from_str("bcrt1qun5x7r2ft88gdxltjfjl3m3n6537ps8sypfttm").unwrap();

        let secp = Secp256k1::default();
        let sk_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let sk_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let pk_sig_user = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_user.clone(), bitcoin::Network::Regtest));
        let pk_sig_blnd = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_blnd.clone(), bitcoin::Network::Regtest));
        
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
        dbg!(&commitment_script);

        let split_transaction = new_unsigned_transaction_split_final(
            &dummy_txid,
            0,
            39_9980_0000,
            19_9980_0000,
            &dummy_addr_user,
            &dummy_addr_blnd,
            2
        );

        let encoded_split = encode_mpc_split_final(
            &split_transaction,
            &commitment_script,
            60_0000_0000
        ).unwrap();

        let mut encoded_split_comp = Vec::new();
        SighashCache::new(&split_transaction).segwit_encode_signing_data_to(
            std::io::BufWriter::new(&mut encoded_split_comp),
            0,
            &commitment_script,
            60_0000_0000,
            EcdsaSighashType::All
        ).unwrap();

        assert_eq!(
            &[
                &encoded_split[000..350],
                Sha256::digest(&Sha256::digest(&[
                    &encoded_split[404..412],
                    &encoded_split[358..381],
                    &encoded_split[412..420],
                    &encoded_split[381..404],
                ].concat())).as_slice(),
                &encoded_split[350..358]
            ].concat().to_hex(),
            &encoded_split_comp.to_hex()
        );

        let split_transaction_sighash = Sha256::digest(&Sha256::digest(&
            [
                &encoded_split[000..350],
                Sha256::digest(&Sha256::digest(&[
                    &encoded_split[404..412],
                    &encoded_split[358..381],
                    &encoded_split[412..420],
                    &encoded_split[381..404],
                ].concat())).as_slice(),
                &encoded_split[350..358]
            ].concat()
        ));

        let split_transaction_sighash_comp = SighashCache::new(&split_transaction).segwit_signature_hash(
            0,
            &commitment_script,
            60_0000_0000,
            EcdsaSighashType::All
        ).unwrap();

        assert_eq!(&split_transaction_sighash[..], split_transaction_sighash_comp.as_inner());

        dbg!(encoded_split.to_hex());
        dbg!(split_transaction_sighash.to_hex());
    }

    #[test]
    fn test_transaction_tout() {
        let dummy_txid: Txid = Txid::from_str("2df0ce8b422af8aa1a0ea5cf3f2db50d33a9355281897d1193fedbbda6e41c07").unwrap();
        let dummy_addr_blnd: Address = Address::from_str("bcrt1qun5x7r2ft88gdxltjfjl3m3n6537ps8sypfttm").unwrap();

        let secp = Secp256k1::default();
        let sk_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let sk_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let pk_sig_user = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_user.clone(), bitcoin::Network::Regtest));
        let pk_sig_blnd = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_blnd.clone(), bitcoin::Network::Regtest));

        let script_split = new_split_delivery_script(&pk_sig_user, &pk_sig_blnd);

        let tout_transaction = new_unsigned_transaction_timeout(
            &dummy_txid,
            0,
            10_0000_0000,
            &dummy_addr_blnd,
            3
        );

        let tout_sig_encode = encode_mpc_multisig(
            &tout_transaction,
            &script_split,
            59_9980_0000
        ).unwrap();

        let tout_sig_encode = [
            &tout_sig_encode[..188],
            &Sha256::digest(&Sha256::digest(&tout_sig_encode[196..227])),
            &tout_sig_encode[188..196]
        ].concat();

        let tout_sig_hash = Sha256::digest(&Sha256::digest(&tout_sig_encode));

        let tout_sig_user = secp.sign_ecdsa_low_r(&Message::from_slice(&tout_sig_hash).unwrap(), &sk_user);
        let tout_sig_blnd = secp.sign_ecdsa_low_r(&Message::from_slice(&tout_sig_hash).unwrap(), &sk_blnd);

        let tout_transaction = compose_transaction_multisig(
            tout_transaction,
            tout_sig_user,
            tout_sig_blnd,
            &script_split
        );
        tout_transaction.verify(|_|{Some(TxOut{ value: 59_9980_0000, script_pubkey: script_split.to_v0_p2wsh() })}).unwrap();
    }

    #[test]
    fn test_encode_all(){
        let dummy_txid: Txid = Txid::from_str("2df0ce8b422af8aa1a0ea5cf3f2db50d33a9355281897d1193fedbbda6e41c07").unwrap();
        let dummy_addr_user: Address = Address::from_str("bcrt1qxzgp4utr352vp7rq79k97q6nuf6c3emyrumz68").unwrap();
        let dummy_addr_blnd: Address = Address::from_str("bcrt1qun5x7r2ft88gdxltjfjl3m3n6537ps8sypfttm").unwrap();

        let secp = Secp256k1::default();
        let sk_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let sk_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let pk_sig_user = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_user.clone(), bitcoin::Network::Regtest));
        let pk_sig_blnd = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_blnd.clone(), bitcoin::Network::Regtest));
        
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
        dbg!(&commitment_script);

        let split_script = new_split_delivery_script(&pk_sig_user, &pk_sig_blnd);

        let split_transaction = new_unsigned_transaction_split_delivery(
            &dummy_txid,
            0,
            20_0000_0000,
            19_9980_0000,
            19_9980_0000,
            &split_script,
            &dummy_addr_user,
            &dummy_addr_blnd,
            2
        );

        let aed_transaction = new_unsigned_transaction_aed(
            &split_transaction.txid(),
            0,
            19_9990_0000,
            &dummy_addr_blnd
        );

        let timeout_transaction = new_unsigned_transaction_timeout(
            &split_transaction.txid(),
            0,
            19_9990_0000,
            &dummy_addr_blnd,
            5
        );

        let encoded_all = encode_mpc_all(
            &split_transaction,
            &aed_transaction,
            &timeout_transaction,
            &commitment_script,
            &split_script,
            60_0000_0000,
            10_0000
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

        // println!("sighash_split sighash_split_unit(");
        // println!("    .nversion(encoded_transaction{}),",      calc_index(000, 004, 765));
        // println!("    .hash_prevouts(encoded_transaction{}),", calc_index(004, 036, 765));
        // println!("    .hash_sequence(encoded_transaction{}),", calc_index(036, 068, 765));
        // println!("    .in_txid(encoded_transaction{}),",       calc_index(068, 100, 765));
        // println!("    .in_vout(encoded_transaction{}),",       calc_index(100, 104, 765));
        // println!("    .script(encoded_transaction{}),",        calc_index(104, 338, 765));
        // println!("    .in_amount(encoded_transaction{}),",     calc_index(338, 346, 765));
        // println!("    .in_nseq(encoded_transaction{}),",       calc_index(346, 350, 765));
        // println!("    .locktime(encoded_transaction{}),",      calc_index(350, 354, 765));
        // println!("    .encoded_outputs({{");
        // println!("        encoded_transaction{},",             calc_index(741, 749, 765));
        // println!("        encoded_transaction{},",             calc_index(606, 641, 765));
        // println!("        encoded_transaction{},",             calc_index(749, 757, 765));
        // println!("        encoded_transaction{},",             calc_index(641, 664, 765));
        // println!("        encoded_transaction{},",             calc_index(757, 765, 765));
        // println!("        encoded_transaction{},",             calc_index(664, 687, 765));
        // println!("    }},");
        // println!("    .sighash_type(encoded_transaction{}),",  calc_index(354, 358, 765));
        // println!(");");

        // println!("sighash_aed_timeout sighash_aed_unit(");
        // println!("    .nversion(encoded_transaction{}),",      calc_index(358, 362, 765));
        // println!("    .in_vout(encoded_transaction{}),",       calc_index(394, 398, 765));
        // println!("    .hash_sequence(encoded_transaction{}),", calc_index(362, 394, 765));
        // println!("    .script(encoded_transaction{}),",        calc_index(398, 470, 765));
        // println!("    .in_amount(encoded_transaction{}),",     calc_index(741, 749, 765));
        // println!("    .in_nseq(encoded_transaction{}),",       calc_index(470, 474, 765));
        // println!("    .locktime(encoded_transaction{}),",      calc_index(474, 478, 765));
        // println!("    .encoded_outputs({{");
        // println!("        amount_minus_fee,",);
        // println!("        encoded_transaction{},",             calc_index(687, 710, 765));
        // println!("    }},");
        // println!("    .sighash_type(encoded_transaction{}),",  calc_index(478, 482, 765));
        // println!(");");

        // println!("sighash_aed_timeout sighash_timeout_unit(");
        // println!("    .nversion(encoded_transaction{}),",      calc_index(482, 486, 765));
        // println!("    .in_vout(encoded_transaction{}),",       calc_index(518, 522, 765));
        // println!("    .hash_sequence(encoded_transaction{}),", calc_index(486, 518, 765));
        // println!("    .script(encoded_transaction{}),",        calc_index(522, 594, 765));
        // println!("    .in_amount(encoded_transaction{}),",     calc_index(741, 749, 765));
        // println!("    .in_nseq(encoded_transaction{}),",       calc_index(594, 598, 765));
        // println!("    .locktime(encoded_transaction{}),",      calc_index(598, 602, 765));
        // println!("    .encoded_outputs({{");
        // println!("        amount_minus_fee,",);
        // println!("        encoded_transaction{},",             calc_index(710, 733, 765));
        // println!("    }},");
        // println!("    .sighash_type(encoded_transaction{}),",  calc_index(602, 606, 765));
        // println!(");");
    }
}