use std::time::SystemTime;

use class_group::primitives::cl_dl_public_setup::{SK, PK, Ciphertext, self, CLGroup};
use curv::elliptic::curves::{bls12_381::{g1::G1Point, scalar::FieldScalar}, ECPoint, secp256_k1::{Secp256k1Scalar, Secp256k1Point}, ECScalar};
use scuttlebutt::AbstractChannel;
use sha2::{Sha256, Digest};

use crate::{channel::Transferable, rsohc, puzzle::PuzzleStatement};

use super::{BindingProof, DlKnowledgeProof, DleqProof};

pub struct PureEcdsaReceiver {
    pk_rsohc: rsohc::PublicKey,
    clgroup: CLGroup,
    clsk_receiver: SK,
    statement: G1Point,
    commitment_token: G1Point,
    commitment_amount: G1Point,
    token: FieldScalar,
    commitment_token_randomness: FieldScalar,
    commitment_amount_randomness: FieldScalar,
    signature: rsohc::Signature
}

impl PureEcdsaReceiver {
    pub fn pure_ecdsa_register<C: AbstractChannel>(
        channel_sender: &mut C,
        pk_rsohc: &rsohc::PublicKey,
        clgroup: CLGroup,
        clsk_receiver: SK
    ) -> anyhow::Result<Self>{
        let token = FieldScalar::read_channel(channel_sender)?;
        let commitment_token_randomness = FieldScalar::read_channel(channel_sender)?;
        let commitment_amount_randomness = FieldScalar::read_channel(channel_sender)?;
        let statement = G1Point::read_channel(channel_sender)?;
        let commitment_token = G1Point::read_channel(channel_sender)?;
        let commitment_amount = G1Point::read_channel(channel_sender)?;
        let signature = rsohc::Signature::read_channel(channel_sender)?;

        let timer = SystemTime::now();

        signature.verify(
            pk_rsohc,
            &statement,
            &commitment_token,
            &commitment_amount
        )?;

        println!("Receiver:: register: {} ms", timer.elapsed().unwrap().as_millis());

        Ok(Self {
            pk_rsohc: pk_rsohc.clone(),
            clgroup,
            clsk_receiver,
            statement,
            commitment_token,
            commitment_amount,
            token,
            commitment_token_randomness,
            commitment_amount_randomness,
            signature,
        })
    }

    pub fn pure_ecdsa_promise<C: AbstractChannel> (
        &self,
        channel_tumbler: &mut C,
        channel_sender: &mut C,
        clpk_tumbler: &PK,
        pk_tumbler: &Secp256k1Point,
        sighash_receiver: &Secp256k1Scalar
     ) -> anyhow::Result<(Secp256k1Scalar, Secp256k1Scalar, Secp256k1Scalar)> {
        let timer = SystemTime::now();

        let d_g1 = G1Point::generator_mul(&self.token);
        let proof = BindingProof::prove(&self.token, &self.commitment_token_randomness);

        self.statement.write_channel(channel_tumbler)?;
        self.commitment_token.write_channel(channel_tumbler)?;
        self.commitment_amount.write_channel(channel_tumbler)?;
        self.signature.write_channel(channel_tumbler)?;
        d_g1.write_channel(channel_tumbler)?;
        proof.write_channel(channel_tumbler)?;

        let mut commitment_rt = [0u8;32];
        channel_tumbler.read_bytes(&mut commitment_rt)?;
        let statement = PuzzleStatement::read_channel(channel_tumbler)?;
        let mut rsohc_statement_r1 = G1Point::read_channel(channel_tumbler)?;
        let mut rsohc_statement = rsohc::Signature::read_channel(channel_tumbler)?;
        rsohc_statement.verify(
            &self.pk_rsohc,
            &statement.get_bls12_381_point(),
            &rsohc_statement_r1,
            &self.commitment_amount
        )?;

        let kr = Secp256k1Scalar::random();
        let rr = Secp256k1Point::generator_mul(&kr);
        let rr_knowledge_proof = DlKnowledgeProof::prove(&kr);
        channel_tumbler.write_pt(&rr)?;
        rr_knowledge_proof.write_channel(channel_tumbler)?;

        let c = Ciphertext::read_channel(channel_tumbler)?;
        let rt = channel_tumbler.read_pt()?;
        let commitment_rt_randomness = channel_tumbler.read_scalar()?;
        let commitment_rt_comp = Sha256::digest(&[
            &rt.serialize_compressed()[..],
            &commitment_rt_randomness.serialize()[..]
        ].concat());
        if commitment_rt[..] != commitment_rt_comp[..] {
            return Err(anyhow::anyhow!("invalid decommitment for rt"));
        }
        let rc = channel_tumbler.read_pt()?;
        let rc_dleq_proof = DleqProof::read_channel(channel_tumbler)?;
        rc_dleq_proof.verify(&statement.get_secp256k1_point(), &rt, &rc)?;

        let sig_s_ciphertext = cl_dl_public_setup::decrypt(
            &self.clgroup,
            &self.clsk_receiver,
            &c
        );
        let r_point = rc.scalar_mul(&kr);
        let sig_r = Secp256k1Scalar::from_bigint(&r_point.x_coord().unwrap());
        let sig_s = Secp256k1Scalar::from_bigint(&sig_s_ciphertext);
        if Secp256k1Point::generator_mul(&sig_s) == pk_tumbler.scalar_mul(&sig_r).add_point(&Secp256k1Point::generator_mul(&sighash_receiver)){
            return Err(anyhow::anyhow!("invalid s verification"))
        }
        let sig_s = sig_s.mul(&kr.invert().unwrap());
        let mut commitment_amount_randomness = self.commitment_amount_randomness.clone();
        let mut commitment_amount = self.commitment_amount.clone();
        let rsohc_statement_rand = rsohc_statement.randomize(
            &mut G1Point::generator().clone(),
            &mut rsohc_statement_r1,
            &mut commitment_amount
        );
        commitment_amount_randomness.add_assign(&rsohc_statement_rand);
        let statement_bls12_381_point = statement.bls12_381_point.add_point(
            &G1Point::generator_mul(&rsohc_statement_rand)
        );
        let statement_secp256k1_point = statement.secp256k1_point.add_point(
            &Secp256k1Point::generator_mul(&Secp256k1Scalar::from_bigint(&rsohc_statement_rand.to_bigint()))
        );
        let statement_ciphertext = cl_dl_public_setup::eval_sum(
            &statement.ciphertext,
            &cl_dl_public_setup::encrypt(
                &self.clgroup, 
                &clpk_tumbler,
                &rsohc_statement_rand.to_bigint()
            ).0
        );
        // rsohc_statement.verify(
        //     &self.pk_rsohc,
        //     &statement_bls12_381_point,
        //     &rsohc_statement_r1,
        //     &commitment_amount
        // )?;

        channel_sender.write_pt(&statement_secp256k1_point)?;
        statement_bls12_381_point.write_channel(channel_sender)?;
        statement_ciphertext.write_channel(channel_sender)?;
        rsohc_statement_r1.write_channel(channel_sender)?;
        rsohc_statement.write_channel(channel_sender)?;
        commitment_amount_randomness.write_channel(channel_sender)?;
        commitment_amount.write_channel(channel_sender)?;

        println!("Receiver:: promise : {} ms", timer.elapsed().unwrap().as_millis());

        Ok((
            Secp256k1Scalar::from_bigint(&rsohc_statement_rand.to_bigint()),
            sig_r,
            sig_s
        ))
    }

    pub fn pure_ecdsa_solve<C: AbstractChannel> (
        &self,
        channel_sender: &mut C,
        rsohc_statement_rand: Secp256k1Scalar,
        sig_r: Secp256k1Scalar,
        sig_s: Secp256k1Scalar,
    ) -> anyhow::Result<(Secp256k1Scalar, Secp256k1Scalar)> {
        let y_secp256k1 = channel_sender.read_scalar()?;

        let timer = SystemTime::now();

        let sig_s = sig_s.mul(
            &y_secp256k1.sub(&rsohc_statement_rand).invert().unwrap()
        );

        println!("Receiver:: solve   : {} ms", timer.elapsed().unwrap().as_millis());
        
        Ok((sig_r, sig_s))
    }
}

pub struct ChannelReceiver {
    pk_rsohc: rsohc::PublicKey,
    clgroup: CLGroup,
    statement: G1Point,
    commitment_token: G1Point,
    commitment_amount: G1Point,
    token: FieldScalar,
    commitment_token_randomness: FieldScalar,
    commitment_amount_randomness: FieldScalar,
    signature: rsohc::Signature
}

impl ChannelReceiver {
    pub fn channel_register<C: AbstractChannel>(
        channel_sender: &mut C,
        pk_rsohc: &rsohc::PublicKey,
        clgroup: CLGroup,
    ) -> anyhow::Result<Self>{
        let token = FieldScalar::read_channel(channel_sender)?;
        let commitment_token_randomness = FieldScalar::read_channel(channel_sender)?;
        let commitment_amount_randomness = FieldScalar::read_channel(channel_sender)?;
        let statement = G1Point::read_channel(channel_sender)?;
        let commitment_token = G1Point::read_channel(channel_sender)?;
        let commitment_amount = G1Point::read_channel(channel_sender)?;
        let signature = rsohc::Signature::read_channel(channel_sender)?;

        let timer = SystemTime::now();

        signature.verify(
            pk_rsohc,
            &statement,
            &commitment_token,
            &commitment_amount
        )?;

        println!("Receiver:: register: {} ms", timer.elapsed().unwrap().as_millis());

        Ok(Self {
            pk_rsohc: pk_rsohc.clone(),
            clgroup,
            statement,
            commitment_token,
            commitment_amount,
            token,
            commitment_token_randomness,
            commitment_amount_randomness,
            signature,
        })
    }

    pub fn channel_promise<C: AbstractChannel> (
        &self,
        channel_tumbler: &mut C,
        channel_sender: &mut C,
        clpk_tumbler: &PK,
     ) -> anyhow::Result<(Secp256k1Point, Secp256k1Scalar)> {
        let timer = SystemTime::now();
        
        let d_g1 = G1Point::generator_mul(&self.token);
        let proof = BindingProof::prove(&self.token, &self.commitment_token_randomness);

        self.statement.write_channel(channel_tumbler)?;
        self.commitment_token.write_channel(channel_tumbler)?;
        self.commitment_amount.write_channel(channel_tumbler)?;
        self.signature.write_channel(channel_tumbler)?;
        d_g1.write_channel(channel_tumbler)?;
        proof.write_channel(channel_tumbler)?;

        let statement = PuzzleStatement::read_channel(channel_tumbler)?;
        let mut rsohc_statement_r1 = G1Point::read_channel(channel_tumbler)?;
        let mut rsohc_statement = rsohc::Signature::read_channel(channel_tumbler)?;
        rsohc_statement.verify(
            &self.pk_rsohc,
            &statement.get_bls12_381_point(),
            &rsohc_statement_r1,
            &self.commitment_amount
        )?;

        let mut commitment_amount_randomness = self.commitment_amount_randomness.clone();
        let mut commitment_amount = self.commitment_amount.clone();
        let rsohc_statement_rand = rsohc_statement.randomize(
            &mut G1Point::generator().clone(),
            &mut rsohc_statement_r1,
            &mut commitment_amount
        );
        commitment_amount_randomness.add_assign(&rsohc_statement_rand);
        let statement_bls12_381_point = statement.bls12_381_point.add_point(
            &G1Point::generator_mul(&rsohc_statement_rand)
        );
        let statement_secp256k1_point = statement.secp256k1_point.add_point(
            &Secp256k1Point::generator_mul(&Secp256k1Scalar::from_bigint(&rsohc_statement_rand.to_bigint()))
        );
        let statement_ciphertext = cl_dl_public_setup::eval_sum(
            &statement.ciphertext,
            &cl_dl_public_setup::encrypt(
                &self.clgroup, 
                &clpk_tumbler,
                &rsohc_statement_rand.to_bigint()
            ).0
        );

        channel_sender.write_pt(&statement_secp256k1_point)?;
        statement_bls12_381_point.write_channel(channel_sender)?;
        statement_ciphertext.write_channel(channel_sender)?;
        rsohc_statement_r1.write_channel(channel_sender)?;
        rsohc_statement.write_channel(channel_sender)?;
        commitment_amount_randomness.write_channel(channel_sender)?;
        commitment_amount.write_channel(channel_sender)?;

        println!("Receiver:: promise : {} ms", timer.elapsed().unwrap().as_millis());

        Ok((
            statement.secp256k1_point,
            Secp256k1Scalar::from_bigint(&rsohc_statement_rand.to_bigint())
        ))
    }

    pub fn channel_solve<C: AbstractChannel> (
        &self,
        channel_sender: &mut C,
        rsohc_statement_rand: &Secp256k1Scalar,
    ) -> anyhow::Result<Secp256k1Scalar> {
        let mut y_secp256k1 = channel_sender.read_scalar()?;

        let timer = SystemTime::now();

        y_secp256k1.sub_assign(&rsohc_statement_rand);

        println!("Receiver:: solve   : {} ms", timer.elapsed().unwrap().as_millis());
        
        Ok(y_secp256k1)
    }

    pub fn get_amount_commitment_randomness(&self) -> &FieldScalar {
        &self.commitment_amount_randomness
    }
}