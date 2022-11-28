use std::time::SystemTime;

use class_group::primitives::cl_dl_public_setup::{Ciphertext, self, CLGroup, PK, SK};
use curv::elliptic::curves::{bls12_381::{scalar::FieldScalar, g1::G1Point}, ECScalar, ECPoint, secp256_k1::{Secp256k1Scalar, Secp256k1Point}};
use scuttlebutt::AbstractChannel;
use sha2::{Sha256, Digest};

use crate::{rsohc::{commit, self}, channel::Transferable};

use super::{DlKnowledgeProof, CommitKnowledgeProof, DleqProof};

pub struct PureEcdsaSender {
    clgroup: CLGroup,
    clsk_sender: SK,
    clpk_tumbler: PK,
    amount: FieldScalar
}

impl PureEcdsaSender {
    pub fn pure_ecdsa_reigster<C: AbstractChannel>(
        channel_tumbler: &mut C,
        channel_receiver: &mut C,
        clgroup: CLGroup,
        clsk_sender: SK,
        clpk_tumbler: PK,
        pk_rsohc: &rsohc::PublicKey
    ) -> anyhow::Result<Self> {
        let timer = SystemTime::now();

        let mut witness = FieldScalar::random();
        let token = FieldScalar::random();
        let amount = FieldScalar::random();

        let mut statement = G1Point::generator_mul(&witness);
        let (mut commitment_token, mut commitment_token_randomness) = commit(&token);
        let (mut commitment_amount, mut commitment_amount_randomness) = commit(&amount);

        statement.write_channel(channel_tumbler)?;
        commitment_token.write_channel(channel_tumbler)?;
        commitment_amount.write_channel(channel_tumbler)?;
        channel_tumbler.flush()?;

        let mut signature = rsohc::Signature::read_channel(channel_tumbler)?;

        signature.verify(pk_rsohc, &statement, &commitment_token, &commitment_amount)?;

        let sig_randomenss = signature.randomize(
            &mut statement,
            &mut commitment_token,
            &mut commitment_amount
        );
        witness.add_assign(&sig_randomenss);
        commitment_token_randomness.add_assign(&sig_randomenss);
        commitment_amount_randomness.add_assign(&sig_randomenss);

        token.write_channel(channel_receiver)?;
        commitment_token_randomness.write_channel(channel_receiver)?;
        commitment_amount_randomness.write_channel(channel_receiver)?;
        statement.write_channel(channel_receiver)?;
        commitment_token.write_channel(channel_receiver)?;
        commitment_amount.write_channel(channel_receiver)?;
        signature.write_channel(channel_receiver)?;
        channel_receiver.flush()?;

        println!("Sender  :: register: {} ms", timer.elapsed().unwrap().as_millis());

        Ok(Self{
            clgroup,
            clsk_sender,
            clpk_tumbler,
            amount
        })
    }

    pub fn pure_ecdsa_solve<C: AbstractChannel>(
        &self,
        channel_tumbler: &mut C,
        channel_receiver: &mut C,
        pk_tumbler: &Secp256k1Point,
        sighash_sender: &Secp256k1Scalar
    ) -> anyhow::Result<()>{

        let mut statement_secp256k1_point = channel_receiver.read_pt()?;
        let mut statement_bls12_381_point = G1Point::read_channel(channel_receiver)?;
        let mut statement_ciphertext = Ciphertext::read_channel(channel_receiver)?;
        let mut rsohc_statement_r1 = G1Point::read_channel(channel_receiver)?;
        let mut rsohc_statement = rsohc::Signature::read_channel(channel_receiver)?;
        let mut commitment_amount_randomness = FieldScalar::read_channel(channel_receiver)?;
        let mut commitment_amount = G1Point::read_channel(channel_receiver)?;

        let timer = SystemTime::now();

        let rsohc_statement_rand = rsohc_statement.randomize(
            &mut statement_bls12_381_point,
            &mut rsohc_statement_r1,
            &mut commitment_amount
        );
        commitment_amount_randomness.add_assign(&rsohc_statement_rand);
        statement_secp256k1_point.add_point_assign(
            &Secp256k1Point::generator_mul(&Secp256k1Scalar::from_bigint(&rsohc_statement_rand.to_bigint()))
        );
        statement_ciphertext = cl_dl_public_setup::eval_sum(
            &statement_ciphertext,
            &cl_dl_public_setup::encrypt(
                &self.clgroup, 
                &self.clpk_tumbler,
                &rsohc_statement_rand.to_bigint()
            ).0
        );
        let commitment_amount_knowledge_proof = CommitKnowledgeProof::prove(&self.amount, &commitment_amount_randomness);
        // commitment_amount_knowledge_proof.verify(&commitment_amount).unwrap();
        
        let mut commitment_rt = [0u8;32];
        channel_tumbler.read_bytes(&mut commitment_rt)?;

        let ks = Secp256k1Scalar::random();
        let rs = Secp256k1Point::generator_mul(&ks);
        let rs_knowledge_proof = DlKnowledgeProof::prove(&ks);

        channel_tumbler.write_pt(&rs)?;
        rs_knowledge_proof.write_channel(channel_tumbler)?;
        commitment_amount.write_channel(channel_tumbler)?;
        commitment_amount_knowledge_proof.write_channel(channel_tumbler)?;
        channel_tumbler.write_pt(&statement_secp256k1_point)?;
        statement_bls12_381_point.write_channel(channel_tumbler)?;
        statement_ciphertext.write_channel(channel_tumbler)?;
        rsohc_statement_r1.write_channel(channel_tumbler)?;
        rsohc_statement.write_channel(channel_tumbler)?;
        channel_tumbler.flush()?;

        let rt = channel_tumbler.read_pt()?;
        let commitment_rt_randomness = channel_tumbler.read_scalar()?;
        let rc = channel_tumbler.read_pt()?;
        let rc_dleq_proof = DleqProof::read_channel(channel_tumbler)?;
        let rt_knowledge_proof = DlKnowledgeProof::read_channel(channel_tumbler)?;
        let sig_s_ciphertext = Ciphertext::read_channel(channel_tumbler)?;

        let commitment_rt_comp = Sha256::digest(&[
            &rt.serialize_compressed()[..],
            &commitment_rt_randomness.serialize()[..]
        ].concat());
        if commitment_rt[..] != commitment_rt_comp[..] {
            return Err(anyhow::anyhow!("invalid decommitment for rt"));
        }
        rt_knowledge_proof.verify(&rt)?;
        rc_dleq_proof.verify(&statement_secp256k1_point, &rt, &rc)?;
        let r_point = rc.scalar_mul(&ks);
        let sig_r = Secp256k1Scalar::from_bigint(&r_point.x_coord().unwrap());
        let sig_s = cl_dl_public_setup::decrypt(
            &self.clgroup,
            &self.clsk_sender,
            &sig_s_ciphertext
        );
        let sig_s = Secp256k1Scalar::from_bigint(&sig_s);
        if Secp256k1Point::generator_mul(&sig_s) == pk_tumbler.scalar_mul(&sig_r).add_point(&Secp256k1Point::generator_mul(&sighash_sender)){
            return Err(anyhow::anyhow!("invalid s verification"))
        }
        let sig_s_ks_invert = sig_s.mul(&ks.invert().unwrap());
        channel_tumbler.write_scalar(&sig_s_ks_invert)?;
        channel_tumbler.flush()?;

        let sig_s = channel_tumbler.read_scalar()?;
        let y_secp256k1 = &sig_s_ks_invert.mul(&sig_s.invert().unwrap());
        if statement_secp256k1_point != Secp256k1Point::generator_mul(&y_secp256k1) {
            return Err(anyhow::anyhow!("witness not match statement"))
        }

        channel_receiver.write_scalar(
            &y_secp256k1.sub(&Secp256k1Scalar::from_bigint(&rsohc_statement_rand.to_bigint()))
        )?;
        channel_receiver.flush()?;

        println!("Sender  :: solve   : {} ms", timer.elapsed().unwrap().as_millis());

        Ok(())
    }
}

pub struct ChannelSender {
    clgroup: CLGroup,
    clpk_tumbler: PK,
    amount: u64
}

impl ChannelSender {
    pub fn channel_reigster<C: AbstractChannel>(
        channel_tumbler: &mut C,
        channel_receiver: &mut C,
        clgroup: CLGroup,
        clpk_tumbler: PK,
        pk_rsohc: &rsohc::PublicKey,
        amount: u64
    ) -> anyhow::Result<(Self, FieldScalar)> {
        let timer = SystemTime::now();

        let mut witness = FieldScalar::random();
        let token = FieldScalar::random();

        let mut statement = G1Point::generator_mul(&witness);
        let (mut commitment_token, mut commitment_token_randomness) = commit(&token);
        let (mut commitment_amount, mut commitment_amount_randomness) = commit(&FieldScalar::from_bigint(&amount.into()));

        statement.write_channel(channel_tumbler)?;
        commitment_token.write_channel(channel_tumbler)?;
        commitment_amount.write_channel(channel_tumbler)?;
        channel_tumbler.flush()?;

        let mut signature = rsohc::Signature::read_channel(channel_tumbler)?;

        signature.verify(pk_rsohc, &statement, &commitment_token, &commitment_amount)?;

        let commitment_amount_randomness_old = commitment_amount_randomness.clone();

        let sig_randomenss = signature.randomize(
            &mut statement,
            &mut commitment_token,
            &mut commitment_amount
        );
        witness.add_assign(&sig_randomenss);
        commitment_token_randomness.add_assign(&sig_randomenss);
        commitment_amount_randomness.add_assign(&sig_randomenss);

        token.write_channel(channel_receiver)?;
        commitment_token_randomness.write_channel(channel_receiver)?;
        commitment_amount_randomness.write_channel(channel_receiver)?;
        statement.write_channel(channel_receiver)?;
        commitment_token.write_channel(channel_receiver)?;
        commitment_amount.write_channel(channel_receiver)?;
        signature.write_channel(channel_receiver)?;
        channel_receiver.flush()?;

        println!("Sender  :: register: {} ms", timer.elapsed().unwrap().as_millis());

        Ok((Self{
            clgroup,
            clpk_tumbler,
            amount
        }, commitment_amount_randomness_old))
    }

    pub fn channel_solve_part1<C: AbstractChannel>(
        &self,
        channel_tumbler: &mut C,
        channel_receiver: &mut C,
    ) -> anyhow::Result<(
        Secp256k1Point,
        FieldScalar,
        FieldScalar
    )>{
        let mut statement_secp256k1_point = channel_receiver.read_pt()?;
        let mut statement_bls12_381_point = G1Point::read_channel(channel_receiver)?;
        let mut statement_ciphertext = Ciphertext::read_channel(channel_receiver)?;
        let mut rsohc_statement_r1 = G1Point::read_channel(channel_receiver)?;
        let mut rsohc_statement = rsohc::Signature::read_channel(channel_receiver)?;
        let mut commitment_amount_randomness = FieldScalar::read_channel(channel_receiver)?;
        let mut commitment_amount = G1Point::read_channel(channel_receiver)?;

        let timer = SystemTime::now();

        let rsohc_statement_rand = rsohc_statement.randomize(
            &mut statement_bls12_381_point,
            &mut rsohc_statement_r1,
            &mut commitment_amount
        );
        commitment_amount_randomness.add_assign(&rsohc_statement_rand);
        statement_secp256k1_point.add_point_assign(
            &Secp256k1Point::generator_mul(&Secp256k1Scalar::from_bigint(&rsohc_statement_rand.to_bigint()))
        );
        statement_ciphertext = cl_dl_public_setup::eval_sum(
            &statement_ciphertext,
            &cl_dl_public_setup::encrypt(
                &self.clgroup, 
                &self.clpk_tumbler,
                &rsohc_statement_rand.to_bigint()
            ).0
        );
        let commitment_amount_knowledge_proof = CommitKnowledgeProof::prove(
            &FieldScalar::from_bigint(&self.amount.into()),
            &commitment_amount_randomness
        );

        commitment_amount.write_channel(channel_tumbler)?;
        commitment_amount_knowledge_proof.write_channel(channel_tumbler)?;
        channel_tumbler.write_pt(&statement_secp256k1_point)?;
        statement_bls12_381_point.write_channel(channel_tumbler)?;
        statement_ciphertext.write_channel(channel_tumbler)?;
        rsohc_statement_r1.write_channel(channel_tumbler)?;
        rsohc_statement.write_channel(channel_tumbler)?;
        channel_tumbler.flush()?;

        println!("Sender  :: solve1  : {} ms", timer.elapsed().unwrap().as_millis());

        Ok((
            statement_secp256k1_point.clone(),
            rsohc_statement_rand,
            commitment_amount_randomness,
        ))
    }
    
    pub fn channel_solve_part2<C: AbstractChannel>(
        &self,
        channel_tumbler: &mut C,
        channel_receiver: &mut C,
        rsohc_statement_rand: FieldScalar
    ) -> anyhow::Result<Secp256k1Scalar>{    
        let timer = SystemTime::now();

        let y_secp256k1 = channel_tumbler.read_scalar()?;

        channel_receiver.write_scalar(
            &y_secp256k1.sub(&Secp256k1Scalar::from_bigint(&rsohc_statement_rand.to_bigint()))
        )?;
        channel_receiver.flush()?;

        println!("Sender  :: solve2  : {} ms", timer.elapsed().unwrap().as_millis());

        Ok(y_secp256k1)
    }
}