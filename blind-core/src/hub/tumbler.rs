use std::time::SystemTime;

use class_group::primitives::cl_dl_public_setup::{CLGroup, PK, SK, self, Ciphertext};
use curv::elliptic::curves::{bls12_381::{g1::G1Point, scalar::FieldScalar}, secp256_k1::{Secp256k1Scalar, Secp256k1Point}, ECScalar, ECPoint};
use scuttlebutt::AbstractChannel;
use sha2::{Sha256, Digest};

use crate::{channel::Transferable, rsohc, puzzle::{PuzzleStatement}};

use super::{BindingProof, sample_witness, DlKnowledgeProof, DleqProof, CommitKnowledgeProof};

pub struct PureEcdsaTumbler {
    sk_rsohc: rsohc::SecretKey,
    pk_rsohc: rsohc::PublicKey,
    clgroup: CLGroup,
    clsk_tumbler: SK,
    clpk_tumbler: PK
}

impl PureEcdsaTumbler {
    pub fn new(
        sk_rsohc: rsohc::SecretKey,
        pk_rsohc: rsohc::PublicKey,
        clgroup: CLGroup,
        clsk_tumbler: SK,
        clpk_tumbler: PK
    ) -> Self {
        Self {
            sk_rsohc,
            pk_rsohc,
            clgroup,
            clsk_tumbler,
            clpk_tumbler,
        }
    }

    pub fn pure_ecdsa_register<C: AbstractChannel>(
        &self,
        channel_sender: &mut C,
    ) -> anyhow::Result<()> {
        let statement = G1Point::read_channel(channel_sender)?;
        let commitment_token = G1Point::read_channel(channel_sender)?;
        let commitment_amount = G1Point::read_channel(channel_sender)?;

        let timer = SystemTime::now();

        let signature = self.sk_rsohc.sign(&statement, &commitment_token, &commitment_amount);

        signature.write_channel(channel_sender)?;
        channel_sender.flush()?;

        println!("Tumbler :: register: {} ms", timer.elapsed().unwrap().as_millis());
        
        Ok(())
    }

    pub fn pure_ecdsa_promiese<C: AbstractChannel> (
        &self,
        channel_receiver: &mut C,
        clpk_receiver: &PK,
        ciphertext_sk_receiver: &Ciphertext,
        sk_tumbler: &Secp256k1Scalar,
        sighash_receiver: &Secp256k1Scalar
     ) -> anyhow::Result<()> {
        let statement = G1Point::read_channel(channel_receiver)?;
        let commitment_token = G1Point::read_channel(channel_receiver)?;
        let commitment_amount = G1Point::read_channel(channel_receiver)?;
        let rsohc_token = rsohc::Signature::read_channel(channel_receiver)?;
        let d_g1 = G1Point::read_channel(channel_receiver)?;
        let binding_proof = BindingProof::read_channel(channel_receiver)?;

        let timer = SystemTime::now();

        rsohc_token.verify(
            &rsohc::PublicKey::from_sk(&self.sk_rsohc),
            &statement,
            &commitment_token,
            &commitment_amount
        )?;
        binding_proof.verify(&d_g1, &commitment_token)?;

        let (
            y_bigint,
            y_secp256k1,
            _
        ) = sample_witness();
        let statement = PuzzleStatement::from_witness(&y_bigint, &self.clgroup, &self.clpk_tumbler);
        let kt = Secp256k1Scalar::random();
        let rt = Secp256k1Point::generator_mul(&kt);
        let commitment_rt_randomness = Secp256k1Scalar::random();
        let commitment_rt = Sha256::digest(&[
            &rt.serialize_compressed()[..],
            &commitment_rt_randomness.serialize()[..]
        ].concat());
        // let v = FieldScalar::random();
        // let v_invert = v.invert().unwrap();
        // let b_g1 = G1Point::generator()
        //     .add_point(&statement.get_bls12_381_point().scalar_mul(&self.sk_rsohc.x1))
        //     .add_point(&commitment_amount.scalar_mul(&self.sk_rsohc.x2))
        //     .scalar_mul(&v_invert);
        // let w_g1 = G1Point::generator_mul(&self.sk_rsohc.x1)
        //     .add_point(&G1Point::base_point2().scalar_mul(&self.sk_rsohc.x2))
        //     .scalar_mul(&v_invert);
        // let v_g1 = G1Point::generator_mul(&v);
        // let v_g2 = G2Point::generator_mul(&v);
        // debug_assert_eq!(
        //     Pair::compute_pairing(b_g1, v_g2),
        //     Pair::compute_pairing(G1Point::generator(), G2Point::generator())
        // );
        let rsohc_statement_r1 = G1Point::generator_mul(&FieldScalar::random());
        let rsohc_statement = self.sk_rsohc.sign(
            &statement.bls12_381_point,
            &rsohc_statement_r1,
            &commitment_amount
        );

        channel_receiver.write_bytes(&commitment_rt)?;
        statement.write_channel(channel_receiver)?;
        rsohc_statement_r1.write_channel(channel_receiver)?;
        rsohc_statement.write_channel(channel_receiver)?;
        channel_receiver.flush()?;

        let rr = channel_receiver.read_pt()?;
        let rr_knwoledge_proof = DlKnowledgeProof::read_channel(channel_receiver)?;
        rr_knwoledge_proof.verify(&rr)?;

        let rc = rt.scalar_mul(&y_secp256k1);
        let rc_dleq_proof = DleqProof::prove(&y_secp256k1, &rt);
        let r_point = rr.scalar_mul(&kt).scalar_mul(&y_secp256k1);
        let sig_r = Secp256k1Scalar::from_bigint(&r_point.x_coord().unwrap());
        let kt_invert = kt.invert().unwrap();
        let c2_scalar = kt_invert.mul(&sig_r).mul(&sk_tumbler);
        let c1 = cl_dl_public_setup::encrypt(
            &self.clgroup,
            clpk_receiver,
            &kt_invert.mul(&sighash_receiver).to_bigint()
        ).0;
        let c2 = cl_dl_public_setup::eval_scal(
            ciphertext_sk_receiver,
            &c2_scalar.to_bigint()
        );
        let c = cl_dl_public_setup::eval_sum(&c1, &c2);
        c.write_channel(channel_receiver)?;
        channel_receiver.write_pt(&rt)?;
        channel_receiver.write_scalar(&commitment_rt_randomness)?;
        channel_receiver.write_pt(&rc)?;
        rc_dleq_proof.write_channel(channel_receiver)?;
        channel_receiver.flush()?;

        println!("Tumbler :: promise : {} ms", timer.elapsed().unwrap().as_millis());

        Ok(())
    }

    pub fn pure_ecdsa_solve<C: AbstractChannel>(
        &self,
        channel_sender: &mut C,
        clpk_sender: &PK,
        ciphertext_sk_sender: &Ciphertext,
        sk_tumbler: &Secp256k1Scalar,
        pk_sender: &Secp256k1Point,
        sighash_sender: &Secp256k1Scalar
    ) -> anyhow::Result<(Secp256k1Scalar, Secp256k1Scalar)> {
        let timer = SystemTime::now();

        let kt = Secp256k1Scalar::random();
        let rt = Secp256k1Point::generator_mul(&kt);
        let commitment_rt_randomness = Secp256k1Scalar::random();
        let commitment_rt = Sha256::digest(&[
            &rt.serialize_compressed()[..],
            &commitment_rt_randomness.serialize()[..]
        ].concat());
        channel_sender.write_bytes(&commitment_rt)?;
        channel_sender.flush()?;

        let rs = channel_sender.read_pt()?;
        let rs_knowledge_proof = DlKnowledgeProof::read_channel(channel_sender)?;
        let commitment_amount = G1Point::read_channel(channel_sender)?;
        let commitment_amount_knowledge_proof = CommitKnowledgeProof::read_channel(channel_sender)?;
        let statement_secp256k1_point = channel_sender.read_pt()?;
        let statement_bls12_381_point = G1Point::read_channel(channel_sender)?;
        let statement_ciphertext = Ciphertext::read_channel(channel_sender)?;
        let rsohc_statement_r1 = G1Point::read_channel(channel_sender)?;
        let rsohc_statement = rsohc::Signature::read_channel(channel_sender)?;
        rs_knowledge_proof.verify(&rs)?;
        commitment_amount_knowledge_proof.verify(&commitment_amount)?;
        rsohc_statement.verify(
            &self.pk_rsohc,
            &statement_bls12_381_point,
            &rsohc_statement_r1,
            &commitment_amount
        )?;

        let y = cl_dl_public_setup::decrypt(
            &self.clgroup,
            &self.clsk_tumbler,
            &statement_ciphertext
        );
        let y_secp256k1 = Secp256k1Scalar::from_bigint(&y);
        let y_bls12_381 = FieldScalar::from_bigint(&y);
        if Secp256k1Point::generator_mul(&y_secp256k1) != statement_secp256k1_point {
            return Err(anyhow::anyhow!("witness not match secp256k1 statement"))
        }
        if G1Point::generator_mul(&y_bls12_381) != statement_bls12_381_point {
            return Err(anyhow::anyhow!("witness not match bls12_381 statement"))
        }
        let rc = rt.scalar_mul(&y_secp256k1);
        let rc_dleq_proof = DleqProof::prove(&y_secp256k1, &rt);
        let r_point = rs.scalar_mul(&kt.mul(&y_secp256k1));
        let sig_r = Secp256k1Scalar::from_bigint(&r_point.x_coord().unwrap());
        let kt_invert = kt.invert().unwrap();
        let c1 = cl_dl_public_setup::encrypt(
            &self.clgroup,
            clpk_sender,
            &kt_invert.mul(&sighash_sender).to_bigint()
        ).0;
        let c2_scalar = kt_invert.mul(&sig_r).mul(&sk_tumbler);
        let c2 = cl_dl_public_setup::eval_scal(
            ciphertext_sk_sender,
            &c2_scalar.to_bigint()
        );
        let c = cl_dl_public_setup::eval_sum(&c1, &c2);
        let rt_knowledge_proof = DlKnowledgeProof::prove(&kt);

        channel_sender.write_pt(&rt)?;
        channel_sender.write_scalar(&commitment_rt_randomness)?;
        channel_sender.write_pt(&rc)?;
        rc_dleq_proof.write_channel(channel_sender)?;
        rt_knowledge_proof.write_channel(channel_sender)?;
        c.write_channel(channel_sender)?;
        channel_sender.flush()?;

        let sig_s_ks_invert = channel_sender.read_scalar()?;
        let sig_s = sig_s_ks_invert.mul(&y_secp256k1.invert().unwrap());

        debug_assert_eq!(
            r_point.scalar_mul(&sig_s),
            Secp256k1Point::generator_mul(&sighash_sender).add_point(
                &pk_sender.scalar_mul(&sk_tumbler).scalar_mul(&sig_r)
            )
        );

        channel_sender.write_scalar(&sig_s)?;
        channel_sender.flush()?;

        println!("Tumbler :: solve   : {} ms", timer.elapsed().unwrap().as_millis());

        Ok((sig_r, sig_s))
    }
}

pub struct ChannelTumbler {
    sk_rsohc: rsohc::SecretKey,
    pk_rsohc: rsohc::PublicKey,
    clgroup: CLGroup,
    clsk_tumbler: SK,
    clpk_tumbler: PK
}

impl ChannelTumbler {
    pub fn new(
        sk_rsohc: rsohc::SecretKey,
        pk_rsohc: rsohc::PublicKey,
        clgroup: CLGroup,
        clsk_tumbler: SK,
        clpk_tumbler: PK
    ) -> Self {
        Self {
            sk_rsohc,
            pk_rsohc,
            clgroup,
            clsk_tumbler,
            clpk_tumbler,
        }
    }

    pub fn channel_register<C: AbstractChannel>(
        &self,
        channel_sender: &mut C,
    ) -> anyhow::Result<G1Point> {
        let statement = G1Point::read_channel(channel_sender)?;
        let commitment_token = G1Point::read_channel(channel_sender)?;
        let commitment_amount = G1Point::read_channel(channel_sender)?;

        let timer = SystemTime::now();

        let signature = self.sk_rsohc.sign(&statement, &commitment_token, &commitment_amount);

        signature.write_channel(channel_sender)?;
        channel_sender.flush()?;

        println!("Tumbler :: register: {} ms", timer.elapsed().unwrap().as_millis());
        
        Ok(commitment_amount)
    }

    pub fn channel_promiese<C: AbstractChannel> (
        &self,
        channel_receiver: &mut C,
     ) -> anyhow::Result<(Secp256k1Point, G1Point)> {
        let statement = G1Point::read_channel(channel_receiver)?;
        let commitment_token = G1Point::read_channel(channel_receiver)?;
        let commitment_amount = G1Point::read_channel(channel_receiver)?;
        let rsohc_token = rsohc::Signature::read_channel(channel_receiver)?;
        let d_g1 = G1Point::read_channel(channel_receiver)?;
        let binding_proof = BindingProof::read_channel(channel_receiver)?;

        let timer = SystemTime::now();

        rsohc_token.verify(
            &rsohc::PublicKey::from_sk(&self.sk_rsohc),
            &statement,
            &commitment_token,
            &commitment_amount
        )?;
        binding_proof.verify(&d_g1, &commitment_token)?;

        let (
            y_bigint,
            _,
            _
        ) = sample_witness();
        let statement = PuzzleStatement::from_witness(&y_bigint, &self.clgroup, &self.clpk_tumbler);
        let rsohc_statement_r1 = G1Point::generator_mul(&FieldScalar::random());
        let rsohc_statement = self.sk_rsohc.sign(
            &statement.bls12_381_point,
            &rsohc_statement_r1,
            &commitment_amount
        );

        statement.write_channel(channel_receiver)?;
        rsohc_statement_r1.write_channel(channel_receiver)?;
        rsohc_statement.write_channel(channel_receiver)?;
        channel_receiver.flush()?;

        println!("Tumbler :: promise : {} ms", timer.elapsed().unwrap().as_millis());

        Ok((statement.secp256k1_point, commitment_amount))
    }

    pub fn channel_solve_part1<C: AbstractChannel>(
        &self,
        channel_sender: &mut C,
    ) -> anyhow::Result<(Secp256k1Point, Secp256k1Scalar, G1Point)> {
        let commitment_amount = G1Point::read_channel(channel_sender)?;
        let commitment_amount_knowledge_proof = CommitKnowledgeProof::read_channel(channel_sender)?;
        let statement_secp256k1_point = channel_sender.read_pt()?;
        let statement_bls12_381_point = G1Point::read_channel(channel_sender)?;
        let statement_ciphertext = Ciphertext::read_channel(channel_sender)?;
        let rsohc_statement_r1 = G1Point::read_channel(channel_sender)?;
        let rsohc_statement = rsohc::Signature::read_channel(channel_sender)?;

        let timer = SystemTime::now();

        commitment_amount_knowledge_proof.verify(&commitment_amount)?;
        rsohc_statement.verify(
            &self.pk_rsohc,
            &statement_bls12_381_point,
            &rsohc_statement_r1,
            &commitment_amount
        )?;

        let y = cl_dl_public_setup::decrypt(
            &self.clgroup,
            &self.clsk_tumbler,
            &statement_ciphertext
        );
        let y_secp256k1 = Secp256k1Scalar::from_bigint(&y);
        let y_bls12_381 = FieldScalar::from_bigint(&y);
        if Secp256k1Point::generator_mul(&y_secp256k1) != statement_secp256k1_point {
            return Err(anyhow::anyhow!("witness not match secp256k1 statement"))
        }
        if G1Point::generator_mul(&y_bls12_381) != statement_bls12_381_point {
            return Err(anyhow::anyhow!("witness not match bls12_381 statement"))
        }
        println!("Tumbler :: solve1  : {} ms", timer.elapsed().unwrap().as_millis());

        Ok((
            statement_secp256k1_point,
            y_secp256k1,
            commitment_amount
        ))
    }

    pub fn channel_solve_part2<C: AbstractChannel>(
        &self,
        channel_sender: &mut C,
        witness: &Secp256k1Scalar
    ) -> anyhow::Result<()> {
        let timer = SystemTime::now();
        channel_sender.write_scalar(&witness)?;
        channel_sender.flush()?;
        println!("Tumbler :: solve2  : {} ms", timer.elapsed().unwrap().as_millis());
        Ok(())
    }
}