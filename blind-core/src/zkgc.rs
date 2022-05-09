use bitcoin::{Transaction, Script, hashes::{hex::{ToHex, FromHex}}};
use curv::{elliptic::curves::{ECScalar, ECPoint, bls12_381::{g1::G1Point, scalar::FieldScalar}}, BigInt, arithmetic::Converter};
use fancy_garbling::{circuit::Circuit, twopac::semihonest::{Garbler, Evaluator}, Wire, FancyInput, encode_boolean, decode_boolean};
use ocelot::ot::{NaorPinkasReceiver, NaorPinkasSender};
use scuttlebutt::{AbstractChannel, AesRng};
use sha2::{Sha256, Digest};

use crate::{encoder::{encode_mpc_all, encode_mpc_split_final}, zero_knowledge::CommitmentEqualityProof, channel::Transferable};

fn encode_index_from_mpc_native(start: usize) -> [usize;64] {
    const OFFSET: [usize; 64] = [
        07, 06, 05, 04, 03, 02, 01, 00,
        15, 14, 13, 12, 11, 10, 09, 08,
        23, 22, 21, 20, 19, 18, 17, 16,
        31, 30, 29, 28, 27, 26, 25, 24,
        39, 38, 37, 36, 35, 34, 33, 32,
        47, 46, 45, 44, 43, 42, 41, 40,
        55, 54, 53, 52, 51, 50, 49, 48,
        63, 62, 61, 60, 59, 58, 57, 56,
    ];
    let mut result = [start; 64];
    result.iter_mut().enumerate().for_each(|(i, a)| {
        *a += OFFSET[i];
    });
    result
}

fn write_amount_commitment<C: AbstractChannel>(
    channel: &mut C,
    start: usize,
    zs: &[FieldScalar],
    scalar2: &FieldScalar
) -> anyhow::Result<FieldScalar> {
    let message = encode_index_from_mpc_native(start).into_iter()
        .map(|index| &zs[index])
        .fold(FieldScalar::zero(), |sum, each| 
            sum.mul(&scalar2).add(each)
    );
    let randomness = FieldScalar::random();
    G1Point::generator().scalar_mul(&message).add_point(
        &G1Point::base_point2().scalar_mul(&randomness)
    ).write_channel(channel)?;
    Ok(randomness)
}

fn manipulate_amount_commitment<C: AbstractChannel>(
    channel: &mut C,
    start: usize,
    zs: &[FieldScalar],
    scalar2: &FieldScalar,
    delta: &FieldScalar
) -> anyhow::Result<G1Point> {
    let scalar_delta = encode_index_from_mpc_native(start).into_iter()
        .map(|index| &zs[index])
        .fold(FieldScalar::zero(), |sum, each| 
            sum.mul(&scalar2).add(each)
        );
    let m = G1Point::read_channel(channel)?
        .sub_point(&G1Point::generator().scalar_mul(&scalar_delta))
        .scalar_mul(&delta.invert().unwrap());
    // channel.write_pt(&m)?;
    Ok(m)
}

pub fn prove_all_transactions<C: AbstractChannel>(
    circ: &Circuit,
    f: &mut Evaluator<C, AesRng, NaorPinkasReceiver>,
    split_transaction: &Transaction,
    aed_transaction: &Transaction,
    timeout_transaction: &Transaction,
    commitment_script: &Script,
    split_script: &Script,
    commitment_output_amount: u64,
    fee: u64,
    commitment_rand_transfer_amount: &FieldScalar,
    commitment_rand_payback_amount_user: &FieldScalar,
    commitment_rand_payback_amount_blnd: &FieldScalar,
) -> anyhow::Result<()>{
    let ev_inputs_bytes = encode_mpc_all(
        &split_transaction,
        &aed_transaction,
        &timeout_transaction,
        &commitment_script,
        &split_script,
        commitment_output_amount,
        fee
    ).unwrap();
    // println!("Prover side  : {}", ev_inputs_bytes[000..741].to_hex());
    let ev_inputs_binary = encode_boolean(&ev_inputs_bytes.to_hex(), true).unwrap();
    let ev_inputs = f.encode_many(
        &ev_inputs_binary,
        &[2u16;6120]
    )?;
    let label_wire = circ.eval_label(f, &[], &ev_inputs)?;

    let encoded_amount = [
        split_transaction.output[0].value.to_le_bytes(),
        split_transaction.output[1].value.to_le_bytes(),
        split_transaction.output[2].value.to_le_bytes()
    ].concat();

    let zs: Vec<FieldScalar> = encode_boolean(&encoded_amount.to_hex(), true)
        .map_err(|_| anyhow::anyhow!("failed to encode boolean"))?
        .into_iter()
        .zip(&ev_inputs)
        .map(|(bit, wire)| {
            let c0 = FieldScalar::read_channel(f.get_channel())?;
            let c1 = FieldScalar::read_channel(f.get_channel())?;
            let wire_block = match wire {
                Wire::Mod2 { val } => Ok(val),
                _ => Err(anyhow::anyhow!("wire 0 is not modulo 2"))
            }?;
            match bit{
                0 => Ok(c0.sub(&FieldScalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&wire_block))))),
                1 => Ok(c1.sub(&FieldScalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&wire_block))))),
                _ => Err(anyhow::anyhow!("failed to encode boolean"))
            }
        }
    ).collect::<anyhow::Result::<_>>()?;

    let scalar2 = FieldScalar::from_bigint(&BigInt::from(2));
    let com_trans_temp_rand = write_amount_commitment(f.get_channel(), 128, &zs, &scalar2)?;
    let com_puser_temp_rand = write_amount_commitment(f.get_channel(), 064, &zs, &scalar2)?;
    let com_pblnd_temp_rand = write_amount_commitment(f.get_channel(), 000, &zs, &scalar2)?;
    // let com_trans_temp = f.get_channel().read_pt()?;
    // let com_puser_temp = f.get_channel().read_pt()?;
    // let com_pblnd_temp = f.get_channel().read_pt()?;
    let delta_inv = FieldScalar::read_channel(f.get_channel())?.invert().unwrap();
    let com_trans_temp_rand = com_trans_temp_rand.mul(&delta_inv);
    let com_puser_temp_rand = com_puser_temp_rand.mul(&delta_inv);
    let com_pblnd_temp_rand = com_pblnd_temp_rand.mul(&delta_inv);
    // debug_assert_eq!(
    //     com_trans_temp,
    //     Secp256k1Point::generator().scalar_mul(&Secp256k1Scalar::from_bigint(&BigInt::from(split_transaction.output[0].value)))
    //         .add_point(&Secp256k1Point::base_point2().scalar_mul(&com_trans_temp_rand))
    // );
    // debug_assert_eq!(
    //     com_puser_temp,
    //     Secp256k1Point::generator().scalar_mul(&Secp256k1Scalar::from_bigint(&BigInt::from(split_transaction.output[1].value)))
    //         .add_point(&Secp256k1Point::base_point2().scalar_mul(&com_puser_temp_rand))
    // );
    // debug_assert_eq!(
    //     com_pblnd_temp,
    //     Secp256k1Point::generator().scalar_mul(&Secp256k1Scalar::from_bigint(&BigInt::from(split_transaction.output[2].value)))
    //         .add_point(&Secp256k1Point::base_point2().scalar_mul(&com_pblnd_temp_rand))
    // );
    let com_eq_trans = CommitmentEqualityProof::prove(
        &FieldScalar::from_bigint(&BigInt::from(split_transaction.output[0].value)),
        &com_trans_temp_rand,
        &commitment_rand_transfer_amount,
    );
    let com_eq_puser = CommitmentEqualityProof::prove(
        &FieldScalar::from_bigint(&BigInt::from(split_transaction.output[1].value)),
        &com_puser_temp_rand,
        &commitment_rand_payback_amount_user,
    );
    let com_eq_pblnd = CommitmentEqualityProof::prove(
        &FieldScalar::from_bigint(&BigInt::from(split_transaction.output[2].value)),
        &com_pblnd_temp_rand,
        &commitment_rand_payback_amount_blnd,
    );
    f.get_channel().write_bytes(&com_eq_trans.serialize())?;
    f.get_channel().write_bytes(&com_eq_puser.serialize())?;
    f.get_channel().write_bytes(&com_eq_pblnd.serialize())?;
    // let output = circ.eval_from_label(f, label_wire).unwrap();

    ev_inputs[192..].into_iter().map(|lab| {
        match lab {
            Wire::Mod2 { val } => f.get_channel().write_block(&val).map_err(|_|anyhow::anyhow!("IO error")),
            _ => Err(anyhow::anyhow!("Invalid modulo"))
        }
    }).collect::<anyhow::Result::<()>>()?;

    label_wire.into_iter().map(|lab| {
        match lab {
            Wire::Mod2 { val } => f.get_channel().write_block(&val).map_err(|_|anyhow::anyhow!("IO error")),
            _ => Err(anyhow::anyhow!("Invalid modulo"))
        }
    }).collect::<anyhow::Result::<()>>()?;
    Ok(())
}

pub fn prove_split_final_transaction<C: AbstractChannel>(
    circ: &Circuit,
    f: &mut Evaluator<C, AesRng, NaorPinkasReceiver>,
    split_transaction: &Transaction,
    commitment_script: &Script,
    commitment_output_amount: u64,
    commitment_rand_payback_amount_user: &FieldScalar,
    commitment_rand_payback_amount_blnd: &FieldScalar,
) -> anyhow::Result<()>{
    let ev_inputs_bytes = encode_mpc_split_final(
        &split_transaction,
        &commitment_script,
        commitment_output_amount,
    ).unwrap();

    let ev_inputs_binary = encode_boolean(&ev_inputs_bytes.to_hex(), true).unwrap();
    let ev_inputs = f.encode_many(
        &ev_inputs_binary,
        &[2u16;3360]
    )?;
    let label_wire = circ.eval_label(f, &[], &ev_inputs)?;

    let encoded_amount = [
        split_transaction.output[0].value.to_le_bytes(),
        split_transaction.output[1].value.to_le_bytes(),
    ].concat();

    let zs: Vec<FieldScalar> = encode_boolean(&encoded_amount.to_hex(), true)
        .map_err(|_| anyhow::anyhow!("failed to encode boolean"))?
        .into_iter()
        .zip(&ev_inputs)
        .map(|(bit, wire)| {
            let c0 = FieldScalar::read_channel(f.get_channel())?;
            let c1 = FieldScalar::read_channel(f.get_channel())?;
            let wire_block = match wire {
                Wire::Mod2 { val } => Ok(val),
                _ => Err(anyhow::anyhow!("wire 0 is not modulo 2"))
            }?;
            match bit{
                0 => Ok(c0.sub(&FieldScalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&wire_block))))),
                1 => Ok(c1.sub(&FieldScalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&wire_block))))),
                _ => Err(anyhow::anyhow!("failed to encode boolean"))
            }
        }
    ).collect::<anyhow::Result::<_>>()?;
    let scalar2 = FieldScalar::from_bigint(&BigInt::from(2));
    let com_puser_temp_rand = write_amount_commitment(f.get_channel(), 064, &zs, &scalar2)?;
    let com_pblnd_temp_rand = write_amount_commitment(f.get_channel(), 000, &zs, &scalar2)?;
    let delta_inv = FieldScalar::read_channel(f.get_channel())?.invert().unwrap();
    let com_puser_temp_rand = com_puser_temp_rand.mul(&delta_inv);
    let com_pblnd_temp_rand = com_pblnd_temp_rand.mul(&delta_inv);
    // debug_assert_eq!(
    //     com_trans_temp,
    //     Secp256k1Point::generator().scalar_mul(&Secp256k1Scalar::from_bigint(&BigInt::from(split_transaction.output[0].value)))
    //         .add_point(&Secp256k1Point::base_point2().scalar_mul(&com_trans_temp_rand))
    // );
    // debug_assert_eq!(
    //     com_puser_temp,
    //     Secp256k1Point::generator().scalar_mul(&Secp256k1Scalar::from_bigint(&BigInt::from(split_transaction.output[1].value)))
    //         .add_point(&Secp256k1Point::base_point2().scalar_mul(&com_puser_temp_rand))
    // );
    // debug_assert_eq!(
    //     com_pblnd_temp,
    //     Secp256k1Point::generator().scalar_mul(&Secp256k1Scalar::from_bigint(&BigInt::from(split_transaction.output[2].value)))
    //         .add_point(&Secp256k1Point::base_point2().scalar_mul(&com_pblnd_temp_rand))
    // );
    let com_eq_puser = CommitmentEqualityProof::prove(
        &FieldScalar::from_bigint(&BigInt::from(split_transaction.output[0].value)),
        &com_puser_temp_rand,
        &commitment_rand_payback_amount_user,
    );
    let com_eq_pblnd = CommitmentEqualityProof::prove(
        &FieldScalar::from_bigint(&BigInt::from(split_transaction.output[1].value)),
        &com_pblnd_temp_rand,
        &commitment_rand_payback_amount_blnd,
    );
    f.get_channel().write_bytes(&com_eq_puser.serialize())?;
    f.get_channel().write_bytes(&com_eq_pblnd.serialize())?;

    ev_inputs[128..].into_iter().map(|lab| {
        match lab {
            Wire::Mod2 { val } => f.get_channel().write_block(&val).map_err(|_|anyhow::anyhow!("IO error")),
            _ => Err(anyhow::anyhow!("Invalid modulo"))
        }
    }).collect::<anyhow::Result::<()>>()?;

    label_wire.into_iter().map(|lab| {
        match lab {
            Wire::Mod2 { val } => f.get_channel().write_block(&val).map_err(|_|anyhow::anyhow!("IO error")),
            _ => Err(anyhow::anyhow!("Invalid modulo"))
        }
    }).collect::<anyhow::Result::<()>>()?;

    // f.get_channel().write_bytes(bitcoin::util::sighash::SighashCache::new(split_transaction).segwit_signature_hash(
    //     0,
    //     &commitment_script,
    //     commitment_output_amount,
    //     bitcoin::EcdsaSighashType::All
    // )?.as_inner())?;
    Ok(())
}

pub struct TransactionSignatures{
    pub sighash_split: [u8;32],
    pub sighash_txaed: [u8;32],
    pub sighash_tmout: [u8;32]
}

pub fn verify_all_transactions<C: AbstractChannel>(
    circ: &Circuit,
    f: &mut Garbler<C, AesRng, NaorPinkasSender>,
    split_transaction: &Transaction,
    aed_transaction: &Transaction,
    timeout_transaction: &Transaction,
    commitment_script: &Script,
    split_script: &Script,
    commitment_output_amount: u64,
    fee: u64,
    commitment_transfer_amount: &G1Point,
    commitment_payback_amount_user: &G1Point,
    commitment_payback_amount_blnd: &G1Point,
) -> anyhow::Result<TransactionSignatures>{
    let public_input_bytes_comp = encode_mpc_all(
        &split_transaction,
        &aed_transaction,
        &timeout_transaction,
        &commitment_script,
        &split_script,
        commitment_output_amount,
        fee
    ).unwrap()[000..741].to_vec();
    // println!("Verifier side: {}", public_input_bytes_comp.to_hex());

    let ev_inputs = f.receive_many(&[2u16;6120])?;
    let label_wire = circ.eval_label(f, &[], &ev_inputs)?;

    let mut zs = Vec::with_capacity(192);
    let delta = FieldScalar::random();
    for w0 in &ev_inputs[0..192]{
        let z0 = FieldScalar::random();
        let z1 = z0.add(&delta);

        zs.push(z0.clone());
        let w1 = w0.plus(&f.delta(2));
        let w0_block = match w0{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 0 is not modulo 2"))
        }?;
        let w1_block = match &w1{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 1 is not modulo 2"))
        }?;
        let c0 = z0.add(&FieldScalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&w0_block))));
        let c1 = z1.add(&FieldScalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&w1_block))));
        c0.write_channel(f.get_channel())?;
        c1.write_channel(f.get_channel())?;
        // f.get_channel().write_scalar(&c0)?;
        // f.get_channel().write_scalar(&c1)?;
        // f.get_channel().flush()?;
    }
    let scalar2 = FieldScalar::from_bigint(&BigInt::from(2));
    let com_trans_temp = manipulate_amount_commitment(f.get_channel(),128, &zs, &scalar2, &delta)?;
    let com_puser_temp = manipulate_amount_commitment(f.get_channel(),064, &zs, &scalar2, &delta)?;
    let com_pblnd_temp = manipulate_amount_commitment(f.get_channel(),000, &zs, &scalar2, &delta)?;
    delta.write_channel(f.get_channel())?;
    let mut proof_trans_bytes = [0u8; 192];
    f.get_channel().read_bytes(&mut proof_trans_bytes)?;
    CommitmentEqualityProof::deserialize(&proof_trans_bytes)?.verify(&com_trans_temp, commitment_transfer_amount)?;
    let mut proof_puser_bytes = [0u8; 192];
    f.get_channel().read_bytes(&mut proof_puser_bytes)?;
    CommitmentEqualityProof::deserialize(&proof_puser_bytes)?.verify(&com_puser_temp, commitment_payback_amount_user)?;
    let mut proof_pblnd_bytes = [0u8; 192];
    f.get_channel().read_bytes(&mut proof_pblnd_bytes)?;
    CommitmentEqualityProof::deserialize(&proof_pblnd_bytes)?.verify(&com_pblnd_temp, commitment_payback_amount_blnd)?;

    let mut public_input_bits = Vec::with_capacity(5864);
    for w0 in &ev_inputs[192..]{
        let w1 = w0.plus(&f.delta(2));
        let cur = f.get_channel().read_block()?;
        let w0_block = match w0{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 0 is not modulo 2"))
        }?;
        let w1_block = match &w1{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 1 is not modulo 2"))
        }?;
        let cur_bit = match cur{
            blk if &blk == w0_block => Ok(0u16),
            blk if &blk == w1_block => Ok(1u16),
            _ => Err(anyhow::anyhow!("invalid wire result"))
        }?;
        public_input_bits.push(cur_bit);
    }
    let public_input_bytes = Vec::<u8>::from_hex(
        &decode_boolean(&public_input_bits, true)
            .map_err(|_| anyhow::anyhow!("decode public input failed"))?
    )?;

    if public_input_bytes != public_input_bytes_comp{
        return Err(anyhow::anyhow!("invalid public input"));
    }

    let mut sighash_bits = Vec::with_capacity(768);
    for w0 in &label_wire{
        let w1 = w0.plus(&f.delta(2));
        let cur = f.get_channel().read_block()?;
        let w0_block = match w0{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 0 is not modulo 2"))
        }?;
        let w1_block = match &w1{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 1 is not modulo 2"))
        }?;
        let cur_bit = match cur{
            blk if &blk == w0_block => Ok(0u16),
            blk if &blk == w1_block => Ok(1u16),
            _ => Err(anyhow::anyhow!("invalid wire result"))
        }?;
        sighash_bits.push(cur_bit);
    }
    let sighash_split = Vec::<u8>::from_hex(
        &decode_boolean(&sighash_bits[512..768], true).map_err(|_| anyhow::anyhow!("failed to decode sighash split"))?
    )?;
    let sighash_txaed = Vec::<u8>::from_hex(
        &decode_boolean(&sighash_bits[256..512], true).map_err(|_| anyhow::anyhow!("failed to decode sighash aed"))?
    )?;
    let sighash_tmout = Vec::<u8>::from_hex(
        &decode_boolean(&sighash_bits[000..256], true).map_err(|_| anyhow::anyhow!("failed to decode sighash timeout"))?
    )?;
    Ok(TransactionSignatures{
        sighash_split: sighash_split.try_into().map_err(|_| anyhow::anyhow!("failed to transform split"))?,
        sighash_txaed: sighash_txaed.try_into().map_err(|_| anyhow::anyhow!("failed to transform txaed"))?,
        sighash_tmout: sighash_tmout.try_into().map_err(|_| anyhow::anyhow!("failed to transform tmout"))?,
    })
}

pub fn verify_split_final_transaction<C: AbstractChannel>(
    circ: &Circuit,
    f: &mut Garbler<C, AesRng, NaorPinkasSender>,
    split_transaction: &Transaction,
    commitment_script: &Script,
    commitment_output_amount: u64,
    commitment_payback_amount_user: &G1Point,
    commitment_payback_amount_blnd: &G1Point,
) -> anyhow::Result<[u8;32]>{
    let public_input_bytes_comp = encode_mpc_split_final(
        &split_transaction,
        &commitment_script,
        commitment_output_amount,
    ).unwrap()[000..404].to_vec();

    let ev_inputs = f.receive_many(&[2u16;3360])?;
    let label_wire = circ.eval_label(f, &[], &ev_inputs)?;

    let mut zs = Vec::with_capacity(128);
    let delta = FieldScalar::random();
    for w0 in &ev_inputs[0..128]{
        let z0 = FieldScalar::random();
        let z1 = z0.add(&delta);

        zs.push(z0.clone());
        let w1 = w0.plus(&f.delta(2));
        let w0_block = match w0{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 0 is not modulo 2"))
        }?;
        let w1_block = match &w1{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 1 is not modulo 2"))
        }?;
        let c0 = z0.add(&FieldScalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&w0_block))));
        let c1 = z1.add(&FieldScalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&w1_block))));
        c0.write_channel(f.get_channel())?;
        c1.write_channel(f.get_channel())?;
        // f.get_channel().write_scalar(&c0)?;
        // f.get_channel().write_scalar(&c1)?;
        // f.get_channel().flush()?;
    }
    let scalar2 = FieldScalar::from_bigint(&BigInt::from(2));
    let com_puser_temp = manipulate_amount_commitment(f.get_channel(),064, &zs, &scalar2, &delta)?;
    let com_pblnd_temp = manipulate_amount_commitment(f.get_channel(),000, &zs, &scalar2, &delta)?;
    delta.write_channel(f.get_channel())?;
    let mut proof_trans_bytes = [0u8; 192];
    f.get_channel().read_bytes(&mut proof_trans_bytes)?;
    CommitmentEqualityProof::deserialize(&proof_trans_bytes)?.verify(&com_puser_temp, commitment_payback_amount_user)?;
    let mut proof_puser_bytes = [0u8; 192];
    f.get_channel().read_bytes(&mut proof_puser_bytes)?;
    CommitmentEqualityProof::deserialize(&proof_puser_bytes)?.verify(&com_pblnd_temp, commitment_payback_amount_blnd)?;

    let mut public_input_bits = Vec::with_capacity(3232);
    for w0 in &ev_inputs[128..]{
        let w1 = w0.plus(&f.delta(2));
        let cur = f.get_channel().read_block()?;
        let w0_block = match w0{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 0 is not modulo 2"))
        }?;
        let w1_block = match &w1{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 1 is not modulo 2"))
        }?;
        let cur_bit = match cur{
            blk if &blk == w0_block => Ok(0u16),
            blk if &blk == w1_block => Ok(1u16),
            _ => Err(anyhow::anyhow!("invalid wire result"))
        }?;
        public_input_bits.push(cur_bit);
    }
    let public_input_bytes = Vec::<u8>::from_hex(
        &decode_boolean(&public_input_bits, true)
            .map_err(|_| anyhow::anyhow!("decode public input failed"))?
    )?;

    if public_input_bytes != public_input_bytes_comp{
        return Err(anyhow::anyhow!("invalid public input"));
    }
    
    let mut sighash_bits = Vec::with_capacity(256);
    for w0 in &label_wire{
        let w1 = w0.plus(&f.delta(2));
        let cur = f.get_channel().read_block()?;
        let w0_block = match w0{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 0 is not modulo 2"))
        }?;
        let w1_block = match &w1{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 1 is not modulo 2"))
        }?;
        let cur_bit = match cur{
            blk if &blk == w0_block => Ok(0u16),
            blk if &blk == w1_block => Ok(1u16),
            _ => Err(anyhow::anyhow!("invalid wire result"))
        }?;
        sighash_bits.push(cur_bit);
    }
    let sighash_split = Vec::<u8>::from_hex(
        &decode_boolean(&sighash_bits[000..256], true).map_err(|_| anyhow::anyhow!("failed to decode sighash split"))?
    )?;

    // let mut sighash = [0u8;32];
    // f.get_channel().read_bytes(&mut sighash)?;

    // debug_assert_eq!(
    //     sighash_split[..],
    //     sighash[..]
    // );
    sighash_split.try_into().map_err(|_| anyhow::anyhow!("sighash length not match"))
}

#[cfg(test)]
mod tests{
    use std::{os::unix::net::UnixStream, io::{BufReader, BufWriter}, str::FromStr, time::SystemTime};
    use bitcoin::{Address, secp256k1::Secp256k1, PublicKey, PrivateKey, Txid, Transaction, Script, EcdsaSighashType, util::sighash::SighashCache, hashes::hex::ToHex};
    use curv::{elliptic::curves::{secp256_k1::Secp256k1Scalar, ECScalar, ECPoint, bls12_381::{scalar::FieldScalar, g1::G1Point}}, BigInt};
    use ocelot::ot::{NaorPinkasReceiver as OtReceiver, NaorPinkasSender as OtSender};
    use fancy_garbling::{circuit::Circuit, twopac::semihonest::{Garbler, Evaluator}, encode_boolean};
    use scuttlebutt::{AesRng, TrackChannel, TrackUnixChannel, track_unix_channel_pair};
    use sha2::Digest;

    use crate::{script::{new_commitment_script, new_split_delivery_script}, transaction::{new_unsigned_transaction_split_delivery, new_unsigned_transaction_aed, new_unsigned_transaction_timeout, new_unsigned_transaction_split_final}, zkgc::{prove_split_final_transaction, verify_split_final_transaction}};

    use super::{prove_all_transactions, verify_all_transactions, encode_index_from_mpc_native};

    #[derive(Clone)]
    struct PreparedTransaction{
        split_transaction: Transaction,
        aed_transaction: Transaction,
        timeout_transaction: Transaction,
        commitment_script: Script,
        split_script: Script,
        commitment_amount: u64,
        transfer_amount: u64,
        payback_amount_user: u64,
        payback_amount_blnd: u64,
        fee: u64
    }

    fn prepare_transaction(
        commitment_txid: &Txid,
        addr_user: &Address,
        addr_blnd: &Address,
        pk_sig_user: &PublicKey,
        pk_sig_blnd: &PublicKey,
        rev_hash_user: &[u8;32],
        rev_hash_blnd: &[u8;32],
        pk_pub_user: &PublicKey,
        pk_pub_blnd: &PublicKey,
        commitment_amount: u64,
        transfer_amount: u64,
        payback_amount_user: u64,
        payback_amount_blnd: u64,
        fee: u64
    ) -> PreparedTransaction{    
        let commitment_script = new_commitment_script(
            2,
            4,
            &pk_sig_user,
            &pk_sig_blnd,
            rev_hash_user,
            rev_hash_blnd,
            pk_pub_user,
            pk_pub_blnd
        );
    
        let split_script = new_split_delivery_script(&pk_sig_user, &pk_sig_blnd);
    
        let split_transaction = new_unsigned_transaction_split_delivery(
            &commitment_txid,
            0,
            transfer_amount,
            payback_amount_user,
            payback_amount_blnd,
            &split_script,
            &addr_user,
            &addr_blnd,
            2
        );
    
        let aed_transaction = new_unsigned_transaction_aed(
            &split_transaction.txid(),
            0,
            transfer_amount-fee,
            &addr_blnd
        );
    
        let timeout_transaction = new_unsigned_transaction_timeout(
            &split_transaction.txid(),
            0,
            transfer_amount-fee,
            &addr_user,
            5
        );

        PreparedTransaction{
            split_transaction,
            aed_transaction,
            timeout_transaction,
            commitment_script: commitment_script.clone(),
            split_script: split_script.clone(),
            commitment_amount,
            transfer_amount,
            payback_amount_user,
            payback_amount_blnd,
            fee
        }
    }

    #[test]
    fn test_encode_index() {
        let amount = 0x0123456789abcdef_u64;
        let encoded = encode_boolean(&amount.to_le_bytes().to_hex(), true).unwrap();
        let index = encode_index_from_mpc_native(0);
        let mut result: u64 = 0;
        for i in 0..64{
            result *= 2;
            result += encoded[index[i]] as u64;
        }
        assert_eq!(amount, result);
    }

    #[test]
    fn test_zk_split_final() {
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
        // dbg!(&commitment_script);

        let circ_parse_time = SystemTime::now();
        let reader = BufReader::new(std::fs::File::open(
            "circuit/zk_split_final.circ"
        ).unwrap());
        let circ: Circuit = bincode::deserialize_from(reader).unwrap();    
        // let circ = Circuit::parse("circuit/zk_all.pp.bristol").unwrap();
        println!(
            "Circuit parse time: {} ms",
            circ_parse_time.elapsed().unwrap().as_millis()
        );

        let commitment_output_amount = 60_0000_0000_u64;
        let payback_amount_user = 39_9980_0000_u64;
        let payback_amount_blnd = 19_9980_0000_u64;

        let com_puser_rand = FieldScalar::random();
        let com_pblnd_rand = FieldScalar::random();
        let com_puser = G1Point::generator().scalar_mul(&FieldScalar::from_bigint(&BigInt::from(payback_amount_user)))
            .add_point(&G1Point::base_point2().scalar_mul(&com_puser_rand));
        let com_pblnd = G1Point::generator().scalar_mul(&FieldScalar::from_bigint(&BigInt::from(payback_amount_blnd)))
            .add_point(&G1Point::base_point2().scalar_mul(&com_pblnd_rand));

        let split_transaction = new_unsigned_transaction_split_final(
            &dummy_txid,
            0,
            payback_amount_user,
            payback_amount_blnd,
            &dummy_addr_user,
            &dummy_addr_blnd,
            2
        );

        let split_sighash_comp = SighashCache::new(&split_transaction).segwit_signature_hash(
            0,
            &commitment_script,
            commitment_output_amount,
            EcdsaSighashType::All
        ).unwrap();

        let circ_ = circ.clone();
        let commitment_script_ = commitment_script.clone();
        let (tx, rx) = track_unix_channel_pair();
        let handle = std::thread::spawn(move || {
            let rng = AesRng::new();
            // let start = SystemTime::now();
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, OtReceiver>::new(tx, rng).unwrap();
            
            prove_split_final_transaction(
                &circ_,
                &mut ev,
                &split_transaction,
                &commitment_script_,
                commitment_output_amount,
                &com_puser_rand,
                &com_pblnd_rand,
            ).unwrap();

            println!(
                "Prover :: sent {} KB",
                ev.get_channel().kilobytes_written()
            );
        
            println!(
                "Prover :: Receive {} KB",
                ev.get_channel().kilobytes_read()
            );
        });

        let split_transaction = new_unsigned_transaction_split_final(
            &dummy_txid,
            0,
            0,
            0,
            &dummy_addr_user,
            &dummy_addr_blnd,
            2
        );

        let rng = AesRng::new();
        let mut gb = Garbler::<TrackUnixChannel, AesRng, OtSender>::new(rx, rng).unwrap();
        let split_sighash = verify_split_final_transaction(
            &circ,
            &mut gb,
            &split_transaction,
            &commitment_script,
            commitment_output_amount,
            &com_puser,
            &com_pblnd
        ).unwrap();

        assert_eq!(split_sighash[..], split_sighash_comp[..]);

        handle.join().unwrap();
    }

    #[test]
    fn test_zk_all_proof(){
        let dummy_txid: Txid = Txid::from_str("2df0ce8b422af8aa1a0ea5cf3f2db50d33a9355281897d1193fedbbda6e41c07").unwrap();
        let dummy_addr_user: Address = Address::from_str("bcrt1qxzgp4utr352vp7rq79k97q6nuf6c3emyrumz68").unwrap();
        let dummy_addr_blnd: Address = Address::from_str("bcrt1qun5x7r2ft88gdxltjfjl3m3n6537ps8sypfttm").unwrap();
    
        let secp = Secp256k1::default();
        let sk_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let sk_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let pk_sig_user = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_user.clone(), bitcoin::Network::Regtest));
        let pk_sig_blnd = PublicKey::from_private_key(&secp, &PrivateKey::new(sk_blnd.clone(), bitcoin::Network::Regtest));
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

        let rev_hash_user = sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_user.to_bytes())).try_into().unwrap();
        let rev_hash_blnd = sha2::Sha256::digest(&sha2::Sha256::digest(&rev_cred_blnd.to_bytes())).try_into().unwrap();
        let pk_pub_user = sk_pub_user.public_key(&secp);
        let pk_pub_blnd = sk_pub_blnd.public_key(&secp);

        let commitment_amount = 60_0000_0000_u64;
        let transfer_amount = 20_0000_0000_u64;
        let payback_amount_user = 19_9980_0000_u64;
        let payback_amount_blnd = 19_9980_0000_u64;
        let fee = 10_0000;

        let prepared = prepare_transaction(
            &dummy_txid,
            &dummy_addr_user,
            &dummy_addr_blnd,
            &pk_sig_user,
            &pk_sig_blnd,
            &rev_hash_user,
            &rev_hash_blnd,
            &pk_pub_user,
            &pk_pub_blnd,
            commitment_amount,
            transfer_amount,
            payback_amount_user,
            payback_amount_blnd,
            fee
        );
        let split_sighash_comp = SighashCache::new(&prepared.split_transaction).segwit_signature_hash(
            0,
            &prepared.commitment_script,
            prepared.commitment_amount,
            EcdsaSighashType::All
        ).unwrap();
        let aed_sighash_comp = SighashCache::new(&prepared.aed_transaction).segwit_signature_hash(
            0,
            &prepared.split_script,
            prepared.transfer_amount,
            EcdsaSighashType::All
        ).unwrap();
        let timeout_sighash_comp = SighashCache::new(&prepared.timeout_transaction).segwit_signature_hash(
            0,
            &prepared.split_script,
            prepared.transfer_amount,
            EcdsaSighashType::All
        ).unwrap();

        let circ_parse_time = SystemTime::now();
        let reader = BufReader::new(std::fs::File::open(
            "circuit/zk_all.circ"
        ).unwrap());
        let circ: Circuit = bincode::deserialize_from(reader).unwrap();    
        // let circ = Circuit::parse("circuit/zk_all.pp.bristol").unwrap();
        println!(
            "Circuit parse time: {} ms",
            circ_parse_time.elapsed().unwrap().as_millis()
        );

        let com_trans_rand = FieldScalar::random();
        let com_puser_rand = FieldScalar::random();
        let com_pblnd_rand = FieldScalar::random();
        let com_trans = G1Point::generator().scalar_mul(&FieldScalar::from_bigint(&BigInt::from(prepared.transfer_amount)))
            .add_point(&G1Point::base_point2().scalar_mul(&com_trans_rand));
        let com_puser = G1Point::generator().scalar_mul(&FieldScalar::from_bigint(&BigInt::from(prepared.payback_amount_user)))
            .add_point(&G1Point::base_point2().scalar_mul(&com_puser_rand));
        let com_pblnd = G1Point::generator().scalar_mul(&FieldScalar::from_bigint(&BigInt::from(prepared.payback_amount_blnd)))
            .add_point(&G1Point::base_point2().scalar_mul(&com_pblnd_rand));
        
        let total = SystemTime::now();
        let circ_ = circ.clone();
        let (tx, rx) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let rng = AesRng::new();
            // let start = SystemTime::now();
            let sender = TrackChannel::new(BufReader::new(tx.try_clone().unwrap()), BufWriter::new(tx));
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, OtReceiver>::new(sender, rng).unwrap();
            prove_all_transactions(
                &circ_,
                &mut ev,
                &prepared.split_transaction,
                &prepared.aed_transaction,
                &prepared.timeout_transaction,
                &prepared.commitment_script,
                &prepared.split_script,
                prepared.commitment_amount,
                prepared.fee,
                &com_trans_rand,
                &com_puser_rand,
                &com_pblnd_rand
            ).unwrap();

            println!(
                "Prover :: sent {} KB",
                ev.get_channel().kilobytes_written()
            );
        
            println!(
                "Prover :: Receive {} KB",
                ev.get_channel().kilobytes_read()
            );
        });

        let prepared_comp = prepare_transaction(
            &dummy_txid,
            &dummy_addr_user,
            &dummy_addr_blnd,
            &pk_sig_user,
            &pk_sig_blnd,
            &rev_hash_user,
            &rev_hash_blnd,
            &pk_pub_user,
            &pk_pub_blnd,
            commitment_amount,
            fee, //Prevent overflow here
            0,
            0,
            fee
        );

        let rng = AesRng::new();
        // let start = SystemTime::now();
        let receiver = TrackChannel::new(BufReader::new(rx.try_clone().unwrap()), BufWriter::new(rx));
        let mut gb = Garbler::<TrackUnixChannel, AesRng, OtSender>::new(receiver, rng).unwrap();
        let sighash_transactions = verify_all_transactions(
            &circ,
            &mut gb,
            &prepared_comp.split_transaction,
            &prepared_comp.aed_transaction,
            &prepared_comp.timeout_transaction,
            &prepared_comp.commitment_script,
            &prepared_comp.split_script,
            prepared_comp.commitment_amount,
            prepared_comp.fee,
            &com_trans,
            &com_puser,
            &com_pblnd
        ).unwrap();
        assert_eq!(sighash_transactions.sighash_split.as_slice(), &split_sighash_comp.to_vec());
        assert_eq!(sighash_transactions.sighash_txaed.as_slice(), &aed_sighash_comp.to_vec());
        assert_eq!(sighash_transactions.sighash_tmout.as_slice(), &timeout_sighash_comp.to_vec());
        handle.join().unwrap();

        println!(
            "Total: {} ms",
            total.elapsed().unwrap().as_millis()
        );
    }
}