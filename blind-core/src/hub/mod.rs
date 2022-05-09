use class_group::primitives::cl_dl_public_setup::{Ciphertext, CLDLProof};
use curv::{elliptic::curves::{bls12_381::{g1::G1Point, scalar::FieldScalar, g2::G2Point}, ECPoint, ECScalar, secp256_k1::{Secp256k1Scalar, Secp256k1Point}}, BigInt, arithmetic::Converter};
use sha2::{Sha256, Digest};

use crate::{channel::Transferable, rsohc::{self, commit_with_randomness}, puzzle::PuzzleStatement};

mod sender;
mod tumbler;
mod reciver;

pub use sender::PureEcdsaSender;
pub use tumbler::PureEcdsaTumbler;
pub use reciver::PureEcdsaReceiver;
pub use sender::ChannelSender;
pub use tumbler::ChannelTumbler;
pub use reciver::ChannelReceiver;

pub fn sample_witness() -> (BigInt, Secp256k1Scalar, FieldScalar) {
    let y_bls12_381 = FieldScalar::random();
    let y_bigint = y_bls12_381.to_bigint();
    let y_secp256k1 = Secp256k1Scalar::from_bigint(&y_bigint);
    (
        y_bigint,
        y_secp256k1,
        y_bls12_381
    )
}

impl Transferable for FieldScalar {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded: [u8;32] = self.serialize().try_into()?;
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8;32];
        chan.read_bytes(&mut encoded)?;
        Self::deserialize(&encoded).map_err(|_| anyhow::anyhow!("failed to deserialize g1 point"))
        
    }
}

impl Transferable for G1Point {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded: [u8;48] = self.serialize_compressed().try_into()?;
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8;48];
        chan.read_bytes(&mut encoded)?;
        Self::deserialize(&encoded).map_err(|_| anyhow::anyhow!("failed to deserialize g1 point"))
        
    }
}

impl Transferable for G2Point {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded: [u8;96] = self.serialize_compressed().as_slice().try_into()?;
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8;96];
        chan.read_bytes(&mut encoded)?;
        Self::deserialize(&encoded).map_err(|_| anyhow::anyhow!("failed to deserialize g1 point"))
        
    }
}

impl Transferable for Ciphertext {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded = bincode::serialize(&self)?;
        chan.write_usize(encoded.len())?;
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let encoded_len = chan.read_usize()?;
        let mut encoded = vec![0u8;encoded_len];
        chan.read_bytes(&mut encoded)?;
        let ciphertext = bincode::deserialize::<Ciphertext>(&encoded)?;
        Ok(ciphertext)
    }
}

impl Transferable for rsohc::Signature {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded = self.serialize();
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8; 240];
        chan.read_bytes(&mut encoded)?;
        Self::deserialize(&encoded)
    }
}

impl Transferable for PuzzleStatement {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        chan.write_pt(&self.secp256k1_point)?;
        self.bls12_381_point.write_channel(chan)?;
        let encoded = bincode::serialize(&self.ciphertext)?;
        chan.write_usize(encoded.len())?;
        chan.write_bytes(&encoded)?;
        let encoded = bincode::serialize(&self.proof)?;
        chan.write_usize(encoded.len())?;
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let secp256k1_point = chan.read_pt()?;
        let bls12_381_point = G1Point::read_channel(chan)?;

        let encoded_len = chan.read_usize()?;
        let mut encoded = vec![0u8;encoded_len];
        chan.read_bytes(&mut encoded)?;
        let ciphertext = bincode::deserialize::<Ciphertext>(&encoded)?;

        let encoded_len = chan.read_usize()?;
        let mut encoded = vec![0u8;encoded_len];
        chan.read_bytes(&mut encoded)?;
        let proof = bincode::deserialize::<CLDLProof>(&encoded)?;

        Ok(Self{
            secp256k1_point,
            bls12_381_point,
            ciphertext,
            proof
        })
    }
}

pub struct BindingProof {
    mask_point: G1Point,
    mask_commitment: G1Point,
    resp_secret: FieldScalar,
    resp_randomness: FieldScalar
}

impl BindingProof {
    pub fn prove(
        secret: &FieldScalar,
        randomness: &FieldScalar
    ) -> Self {
        let r1 = FieldScalar::random();
        let r2 = FieldScalar::random();
        let mask_point = G1Point::generator_mul(&r1);
        let mask_commitment = commit_with_randomness(&r1, &r2);
        let mut challenge = Sha256::new();
        challenge.update(&mask_point.serialize_compressed());
        challenge.update(&mask_commitment.serialize_compressed());
        let challenge = FieldScalar::from_bigint(&BigInt::from_bytes(challenge.finalize().as_slice()));
        let resp_secret = challenge.mul(&secret).add(&r1);
        let resp_randomness = challenge.mul(&randomness).add(&r2);

        Self {
            mask_point,
            mask_commitment,
            resp_secret,
            resp_randomness,
        }
    }

    pub fn verify(&self, point: &G1Point, commitment: &G1Point) -> anyhow::Result<()> {
        let mut challenge = Sha256::new();
        challenge.update(&self.mask_point.serialize_compressed());
        challenge.update(&self.mask_commitment.serialize_compressed());
        let challenge = FieldScalar::from_bigint(&BigInt::from_bytes(challenge.finalize().as_slice()));
        let cond1_left = G1Point::generator_mul(&self.resp_secret);
        let cond1_right = point.scalar_mul(&challenge).add_point(&self.mask_point);
        if cond1_left != cond1_right {
            return Err(anyhow::anyhow!("invalid equality proof"));
        }
        let cond2_left = G1Point::generator_mul(&self.resp_secret).add_point(
            &G1Point::base_point2().scalar_mul(&self.resp_randomness)
        );
        let cond2_right = commitment.scalar_mul(&challenge).add_point(&self.mask_commitment);
        if cond2_left != cond2_right {
            return Err(anyhow::anyhow!("invalid equality proof"))
        }
        Ok(())
    }

    pub fn serialize(&self) -> [u8;160] {
        let mut encoded = [0u8;160];
        encoded[000..048].copy_from_slice(&self.mask_point.serialize_compressed());
        encoded[048..096].copy_from_slice(&self.mask_commitment.serialize_compressed());
        encoded[096..128].copy_from_slice(&self.resp_secret.serialize());
        encoded[128..160].copy_from_slice(&self.resp_randomness.serialize());
        encoded
    }

    pub fn deserialize(encoded: &[u8;160]) -> anyhow::Result<Self> {
        let mask_point = G1Point::deserialize(&encoded[000..048])?;
        let mask_commitment = G1Point::deserialize(&encoded[048..096])?;
        let resp_secret = FieldScalar::deserialize(&encoded[096..128])?;
        let resp_randomness = FieldScalar::deserialize(&encoded[128..160])?;
        
        Ok(Self{
            mask_point,
            mask_commitment,
            resp_secret,
            resp_randomness,
        })
    }
}

impl Transferable for BindingProof {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded = self.serialize();
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8; 160];
        chan.read_bytes(&mut encoded)?;
        Self::deserialize(&encoded)
    }
}

pub struct DlKnowledgeProof {
    mask_point: Secp256k1Point,
    response: Secp256k1Scalar
}

impl DlKnowledgeProof {
    pub fn prove(witness: &Secp256k1Scalar) -> Self {
        let r = Secp256k1Scalar::random();
        let mask_point = Secp256k1Point::generator_mul(&r);
        let challenge = Secp256k1Scalar::from_bigint(&BigInt::from_bytes(sha2::Sha512::digest(&[
            &mask_point.serialize_compressed()[..],
        ].concat()).as_slice()));
        let response = challenge.mul(&witness).add(&r);
        
        Self {
            mask_point,
            response,
        }
    }

    pub fn verify(&self, point: &Secp256k1Point) -> anyhow::Result<()> {
        let challenge = Secp256k1Scalar::from_bigint(&BigInt::from_bytes(sha2::Sha512::digest(&[
            &self.mask_point.serialize_compressed()[..],
        ].concat()).as_slice()));
        let cond1_left = Secp256k1Point::generator_mul(&self.response);
        let cond1_right = point.scalar_mul(&challenge).add_point(&self.mask_point);
        if cond1_left != cond1_right {
            return Err(anyhow::anyhow!("invalid proof"));
        }
        Ok(())
    }

    pub fn serialize(&self) -> [u8;65] {
        let mut encoded = [0u8;65];
        encoded[00..33].copy_from_slice(&self.mask_point.serialize_compressed()[..]);
        encoded[33..65].copy_from_slice(&self.response.serialize()[..]);
        encoded
    }

    pub fn deserialize(encoded: &[u8;65]) -> anyhow::Result<Self> {
        let mask_point = Secp256k1Point::deserialize(&encoded[00..33])?;
        let response = Secp256k1Scalar::deserialize(&encoded[33..65])?;
        
        Ok(Self {
            mask_point,
            response,
        })
    }
}


impl Transferable for DlKnowledgeProof {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded = self.serialize();
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8; 65];
        chan.read_bytes(&mut encoded)?;
        Self::deserialize(&encoded)
    }
}

pub struct CommitKnowledgeProof {
    mask_point: G1Point,
    response_msg: FieldScalar,
    response_rnd: FieldScalar
}

impl CommitKnowledgeProof {
    pub fn prove(message: &FieldScalar, randomness: &FieldScalar) -> Self {
        let r1 = FieldScalar::random();
        let r2 = FieldScalar::random();
        let mask_point = commit_with_randomness(&r1, &r2);
        let challenge = FieldScalar::from_bigint(&BigInt::from_bytes(sha2::Sha512::digest(&[
            &mask_point.serialize_compressed()[..],
        ].concat()).as_slice()));
        let response_msg = challenge.mul(&message).add(&r1);
        let response_rnd = challenge.mul(&randomness).add(&r2);
        
        Self {
            mask_point,
            response_msg,
            response_rnd
        }
    }

    pub fn verify(&self, point: &G1Point) -> anyhow::Result<()> {
        let challenge = FieldScalar::from_bigint(&BigInt::from_bytes(sha2::Sha512::digest(&[
            &self.mask_point.serialize_compressed()[..],
        ].concat()).as_slice()));
        let cond1_left = commit_with_randomness(&self.response_msg, &self.response_rnd);
        let cond1_right = point.scalar_mul(&challenge).add_point(&self.mask_point);
        if cond1_left != cond1_right {
            return Err(anyhow::anyhow!("invalid commitment knowledge proof"));
        }
        Ok(())
    }

    pub fn serialize(&self) -> [u8;112] {
        let mut encoded = [0u8;112];
        encoded[000..048].copy_from_slice(&self.mask_point.serialize_compressed()[..]);
        encoded[048..080].copy_from_slice(&self.response_msg.serialize()[..]);
        encoded[080..112].copy_from_slice(&self.response_rnd.serialize()[..]);
        encoded
    }

    pub fn deserialize(encoded: &[u8;112]) -> anyhow::Result<Self> {
        let mask_point = G1Point::deserialize(&encoded[000..048])?;
        let response_msg = FieldScalar::deserialize(&encoded[048..080])?;
        let response_rnd = FieldScalar::deserialize(&encoded[080..112])?;
        
        Ok(Self {
            mask_point,
            response_msg,
            response_rnd,
        })
    }
}


impl Transferable for CommitKnowledgeProof {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded = self.serialize();
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8; 112];
        chan.read_bytes(&mut encoded)?;
        Self::deserialize(&encoded)
    }
}


pub struct DleqProof {
    mask_point: Secp256k1Point,
    mask_base2: Secp256k1Point,
    response: Secp256k1Scalar
}

impl DleqProof {
    pub fn prove(witness: &Secp256k1Scalar, base2: &Secp256k1Point) -> Self {
        let r = Secp256k1Scalar::random();
        let mask_point = Secp256k1Point::generator_mul(&r);
        let mask_base2 = base2.scalar_mul(&r);
        let challenge = Secp256k1Scalar::from_bigint(&BigInt::from_bytes(sha2::Sha512::digest(&[
            &mask_point.serialize_compressed()[..],
        ].concat()).as_slice()));
        let response = challenge.mul(&witness).add(&r);
        
        Self {
            mask_point,
            mask_base2,
            response,
        }
    }

    pub fn verify(&self, point: &Secp256k1Point, base2: &Secp256k1Point, point2: &Secp256k1Point) -> anyhow::Result<()> {
        let challenge = Secp256k1Scalar::from_bigint(&BigInt::from_bytes(sha2::Sha512::digest(&[
            &self.mask_point.serialize_compressed()[..],
        ].concat()).as_slice()));
        let cond1_left = Secp256k1Point::generator_mul(&self.response);
        let cond1_right = point.scalar_mul(&challenge).add_point(&self.mask_point);
        if cond1_left != cond1_right {
            return Err(anyhow::anyhow!("invalid proof"));
        }
        let cond2_left = base2.scalar_mul(&self.response);
        let cond2_right = point2.scalar_mul(&challenge).add_point(&self.mask_base2);
        if cond2_left != cond2_right {
            return Err(anyhow::anyhow!("invalid proof"));
        }
        Ok(())
    }

    pub fn serialize(&self) -> [u8;98] {
        let mut encoded = [0u8;98];
        encoded[00..33].copy_from_slice(&self.mask_point.serialize_compressed()[..]);
        encoded[33..66].copy_from_slice(&self.mask_base2.serialize_compressed()[..]);
        encoded[66..98].copy_from_slice(&self.response.serialize()[..]);
        encoded
    }

    pub fn deserialize(encoded: &[u8;98]) -> anyhow::Result<Self> {
        let mask_point = Secp256k1Point::deserialize(&encoded[00..33])?;
        let mask_base2 = Secp256k1Point::deserialize(&encoded[33..66])?;
        let response = Secp256k1Scalar::deserialize(&encoded[66..98])?;
        
        Ok(Self {
            mask_point,
            mask_base2,
            response,
        })
    }
}


impl Transferable for DleqProof {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded = self.serialize();
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8; 98];
        chan.read_bytes(&mut encoded)?;
        Self::deserialize(&encoded)
    }
}


#[cfg(test)]
mod tests {
    use std::{time::SystemTime, io::BufReader};

    use bitcoin::{Transaction, hashes::hex::ToHex};
    use class_group::primitives::cl_dl_public_setup::{CLGroup, sample_prime_by_length, self};
    use curv::{elliptic::curves::{bls12_381::{scalar::FieldScalar, g1::G1Point}, ECScalar, ECPoint, secp256_k1::{Secp256k1Point, Secp256k1Scalar}}, BigInt, arithmetic::Zero};
    use fancy_garbling::{circuit::Circuit, twopac::semihonest::{Garbler, Evaluator}};
    use ocelot::ot::{NaorPinkasSender, NaorPinkasReceiver};
    use scuttlebutt::{track_unix_channel_pair, unix_channel_pair, AesRng, TrackUnixChannel};
    use testcontainers::{clients, images::coblox_bitcoincore::{BitcoinCoreImageArgs, BitcoinCore}, RunnableImage};

    use crate::{rsohc::{self, commit_with_randomness}, puzzle::PuzzleStatement, channel::{Transferable, ChannelUser, ChannelBlind}, hub::{tumbler::ChannelTumbler, sender::ChannelSender, reciver::ChannelReceiver}, bitcoin_rpc::Client, transaction::new_unsigned_transaction_funding_template};

    use super::{PureEcdsaSender, PureEcdsaTumbler, PureEcdsaReceiver, BindingProof, DlKnowledgeProof, DleqProof, CommitKnowledgeProof};

    #[test]
    fn test_puzzle_statment_transferable() {
        let clgroup = CLGroup::new_from_setup(&3845, &BigInt::zero(), &sample_prime_by_length(800));
        let (clsk, clpk) = clgroup.keygen();
        let witness = FieldScalar::random().to_bigint();
        let statement =  PuzzleStatement::from_witness(&witness, &clgroup, &clpk);

        dbg!(&statement);
        statement.verify(&clgroup, &clpk).unwrap();

        let (mut chan1,mut chan2) = track_unix_channel_pair();
        statement.write_channel(&mut chan1).unwrap();
        let statement = PuzzleStatement::read_channel(&mut chan2).unwrap();
        
        dbg!(&statement);
        statement.verify(&clgroup, &clpk).unwrap();

        let extracted = statement.decrypt(&clgroup, &clsk);
        assert_eq!(extracted, witness)
    }

    #[test]
    fn test_equal_proof() {
        let secret = FieldScalar::random();
        let randomness = FieldScalar::random();
        let proof = BindingProof::prove(&secret, &randomness);

        let point = G1Point::generator_mul(&secret);
        let commitment = commit_with_randomness(&secret, &randomness);
        
        BindingProof::deserialize(&proof.serialize()).unwrap().verify(&point, &commitment).unwrap();
    }

    #[test]
    fn test_commit_knowledge_proof() {
        let secret = FieldScalar::random();
        let randomness = FieldScalar::random();
        let proof = CommitKnowledgeProof::prove(&secret, &randomness);

        let commitment = commit_with_randomness(&secret, &randomness);
        let (mut tx, mut rx) = unix_channel_pair();
        proof.write_channel(&mut tx).unwrap();
        
        CommitKnowledgeProof::read_channel(&mut rx).unwrap().verify(&commitment).unwrap();
    }

    #[test]
    fn test_dl_knowledge_proof() {
        let secret = Secp256k1Scalar::random();
        let proof = DlKnowledgeProof::prove(&secret);

        let point = Secp256k1Point::generator_mul(&secret);
        
        DlKnowledgeProof::deserialize(&proof.serialize()).unwrap().verify(&point).unwrap();
    }

    #[test]
    fn test_dleq_proof() {
        let secret = Secp256k1Scalar::random();
        let proof = DleqProof::prove(&secret, Secp256k1Point::base_point2());

        let point = Secp256k1Point::generator_mul(&secret);
        let point2 = Secp256k1Point::base_point2().scalar_mul(&secret);
        
        DleqProof::deserialize(&proof.serialize()).unwrap().verify(&point, &Secp256k1Point::base_point2(), &point2).unwrap();
    }

    #[test]
    fn test_ecdsa_pure_hub() {
        let sk_rsohc = rsohc::SecretKey::new();
        let pk_rsohc = rsohc::PublicKey::from_sk(&sk_rsohc);
        let pk_rsohc_sender = pk_rsohc.clone();
        let pk_rsohc_receiver = pk_rsohc.clone();

        let sk_sender = Secp256k1Scalar::random();
        let pk_sender = Secp256k1Point::generator_mul(&sk_sender);
        let sk_tumbler = Secp256k1Scalar::random();
        let pk_tumbler = Secp256k1Point::generator_mul(&sk_tumbler);
        let sk_receiver = Secp256k1Scalar::random();

        let clgroup = CLGroup::new_from_setup(&3845, &BigInt::zero(), &sample_prime_by_length(800));
        let (clsk_sender, clpk_sender) = clgroup.keygen();
        let (clsk_tumbler, clpk_tumbler) = clgroup.keygen();
        let (clsk_receiver, clpk_receiver) = clgroup.keygen();

        let ciphertext_sk_sender = cl_dl_public_setup::encrypt(
            &clgroup,
            &clpk_sender,
            &sk_sender.to_bigint()
        ).0;

        let ciphertext_sk_receiver = cl_dl_public_setup::encrypt(
            &clgroup,
            &clpk_receiver,
            &sk_receiver.to_bigint()
        ).0;

        let (
            clgroup_sender,
            clgroup_tumbler,
            clgroup_receiver
        ) = (clgroup.clone(), clgroup.clone(), clgroup);
        let (
            clpk_tumbler_sender,
            clpk_tumbler_receiver
        ) = (clpk_tumbler.clone(), clpk_tumbler.clone());

        let (
            mut sender_channel_tumbler,
            mut tumbler_channel_sender
        ) = track_unix_channel_pair();
        let (
            mut sender_channel_receiver,
            mut receiver_channel_sender,
        ) = track_unix_channel_pair();
        let (
            mut tumbler_channel_receiver,
            mut receiver_channel_tumbler
        ) = track_unix_channel_pair();

        let time_total = SystemTime::now();

        // println!("Sender  :: register: {} ms", timer.elapsed().unwrap().as_millis());
        // println!("Sender  :: promise : {} ms", timer.elapsed().unwrap().as_millis());
        // println!("Sender  :: solve   : {} ms", timer.elapsed().unwrap().as_millis());
        // println!("Tumbler :: register: {} ms", timer.elapsed().unwrap().as_millis());
        // println!("Tumbler :: promise : {} ms", timer.elapsed().unwrap().as_millis());
        // println!("Tumbler :: solve   : {} ms", timer.elapsed().unwrap().as_millis());
        // println!("Receiver:: register: {} ms", timer.elapsed().unwrap().as_millis());
        // println!("Receiver:: promise : {} ms", timer.elapsed().unwrap().as_millis());
        // println!("Receiver:: solve   : {} ms", timer.elapsed().unwrap().as_millis());

        let handler_sender = std::thread::spawn(move || {
            let sender = PureEcdsaSender::pure_ecdsa_reigster(
                &mut sender_channel_tumbler,
                &mut sender_channel_receiver,
                clgroup_sender,
                clsk_sender,
                clpk_tumbler_sender,
                &pk_rsohc_sender
            ).unwrap();
            
            sender.pure_ecdsa_solve(
                &mut sender_channel_tumbler,
                &mut sender_channel_receiver,
                &pk_tumbler,
                &Secp256k1Scalar::from_bigint(&BigInt::from(32))
            ).unwrap();
        });

        let handler_tumbler = std::thread::spawn(move || {
            let tumbler = PureEcdsaTumbler::new(
                sk_rsohc,
                pk_rsohc,
                clgroup_tumbler,
                clsk_tumbler,
                clpk_tumbler
            );
            tumbler.pure_ecdsa_register(&mut tumbler_channel_sender).unwrap();

            tumbler.pure_ecdsa_promiese(
                &mut tumbler_channel_receiver,
                &clpk_receiver,
                &ciphertext_sk_receiver,
                &sk_tumbler,
                &Secp256k1Scalar::from_bigint(&BigInt::from(12))
            ).unwrap();

            tumbler.pure_ecdsa_solve(
                &mut tumbler_channel_sender,
                &clpk_sender,
                &ciphertext_sk_sender,
                &sk_tumbler,
                &pk_sender,
                &Secp256k1Scalar::from_bigint(&BigInt::from(32))
            ).unwrap();
        });

        let handler_receiver= std::thread::spawn(move || {
            let receiver = PureEcdsaReceiver::pure_ecdsa_register(
                &mut receiver_channel_sender,
                &pk_rsohc_receiver,
                clgroup_receiver,
                clsk_receiver,
            ).unwrap();

            let (
                rsohc_statement_rand,
                sig_r,
                sig_s
            ) = receiver.pure_ecdsa_promise(
                &mut receiver_channel_tumbler,
                &mut receiver_channel_sender,
                &clpk_tumbler_receiver,
                &pk_tumbler,
                &Secp256k1Scalar::from_bigint(&BigInt::from(12))
            ).unwrap();

            let (sig_r, sig_s) = receiver.pure_ecdsa_solve(
                &mut receiver_channel_sender,
                rsohc_statement_rand,
                sig_r,
                sig_s
            ).unwrap();

            let r_point = Secp256k1Point::generator_mul(&Secp256k1Scalar::from_bigint(&BigInt::from(12))).add_point(
                &&pk_tumbler.scalar_mul(&sk_receiver).scalar_mul(&sig_r)
            ).scalar_mul(&sig_s.invert().unwrap());
            assert_eq!(
                sig_r,
                Secp256k1Scalar::from_bigint(&r_point.x_coord().unwrap())
            );
        });

        handler_sender.join().unwrap();
        handler_tumbler.join().unwrap();
        handler_receiver.join().unwrap();

        println!("Total: {} ms", time_total.elapsed().unwrap().as_millis());

    }

    #[test]
    fn test_channel_hub_unreduced() {
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
        let reader = BufReader::new(std::fs::File::open(
            "circuit/zk_all.circ"
        ).unwrap());
        let circ_sender: Circuit = bincode::deserialize_from(reader).unwrap();    
        let circ_tumbler = circ_sender.clone();
        let circ_receiver = circ_sender.clone();
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

        let (
            mut sender_channel_tumbler,
            mut tumbler_channel_sender
        ) = track_unix_channel_pair();
        let (
            mut sender_channel_receiver,
            mut receiver_channel_sender,
        ) = track_unix_channel_pair();
        let (
            mut tumbler_channel_receiver,
            mut receiver_channel_tumbler
        ) = track_unix_channel_pair();

        let split_return_amount_init = 29_9980_0000_u64;
        let transfer_amount = 20_0000_0000_u64;
        let fee_amount = 10_0000_u64;

        let time_total = SystemTime::now();

        let handler_sender = std::thread::spawn(move || {
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

            let sender = ChannelSender::channel_reigster(
                &mut sender_channel_tumbler,
                &mut sender_channel_receiver,
                clgroup_sender,
                clpk_tumbler_sender,
                &pk_rsohc_sender,
                transfer_amount
            ).unwrap().0;
            
            let (
                statement,
                state,
                commitment_transfer_amount_randomness
            ) = sender.channel_solve_part1(
                &mut sender_channel_tumbler,
                &mut sender_channel_receiver,
            ).unwrap();

            let rng = AesRng::new();
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(sender_channel_tumbler, rng).unwrap();
            blind_channel.make_transfer(
                &circ_sender,
                &mut ev,
                crate::channel::ChannelUserRole::Payer,
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

            if statement != Secp256k1Point::generator_mul(&witness) {
                panic!("witness not match statement")
            }

            match blind_channel.status {
                crate::channel::ChannelStatus::SplitFinal { .. } => panic!("invalid status"),
                crate::channel::ChannelStatus::SplitDeliv {
                    commitment_transaction,
                    split_transaction,
                    ..
                } => {
                    bitcoin_cli_sender.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&commitment_transaction)).unwrap();
                    bitcoin_cli_sender.mine(10, address_null).unwrap();
                    bitcoin_cli_sender.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&split_transaction)).unwrap();
                    bitcoin_cli_sender.mine(10, address_null).unwrap();

                    // You can't fetch the transaction with pure bitcoin rpc, but with libbitcoin?
                    // https://bitcoin.stackexchange.com/questions/61794/bitcoin-rpc-how-to-find-the-transaction-that-spends-a-txo
                    split_transaction.write_channel(&mut sender_channel_tumbler).unwrap();
                }
            };

            println!("Sender   <==> Tumbler : {} KB", sender_channel_tumbler.total_kilobytes());
            println!("Sender   <==> Receiver: {} KB", sender_channel_receiver.total_kilobytes());
        });

        let handler_tumbler = std::thread::spawn(move || {
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

            // let mut garbler_sender = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(chan_blnd, rng).unwrap();

            let tumbler = ChannelTumbler::new(
                sk_rsohc,
                pk_rsohc,
                clgroup_tumbler,
                clsk_tumbler,
                clpk_tumbler
            );
            tumbler.channel_register(&mut tumbler_channel_sender).unwrap();

            let (
                statement_receiver,
                commitment_transfer_amount_receiver
            ) = tumbler.channel_promiese(
                &mut tumbler_channel_receiver,
            ).unwrap();

            let timer = SystemTime::now();
            let rng = AesRng::new();
            let mut gb_receiver = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(tumbler_channel_receiver, rng).unwrap();
            blind_channel_receiver.make_transfer(
                &circ_tumbler,
                &mut gb_receiver,
                crate::channel::ChannelUserRole::Payee,
                &statement_receiver,
                10_0000,
                bitcoin::Network::Regtest,
                &commitment_transfer_amount_receiver,
                &blind_channel_receiver.commitment_amount_user.clone(),
                &blind_channel_receiver.commitment_amount_blnd.sub_point(&commitment_transfer_amount_receiver)
            ).unwrap();
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
            let mut gb_sender = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(tumbler_channel_sender, rng).unwrap();
            blind_channel_sender.make_transfer(
                &circ_tumbler,
                &mut gb_sender,
                crate::channel::ChannelUserRole::Payer,
                &statement_sender,
                10_0000,
                bitcoin::Network::Regtest,
                &commitment_transfer_amount_sender,
                &blind_channel_sender.commitment_amount_user.sub_point(&commitment_transfer_amount_sender),
                &blind_channel_sender.commitment_amount_blnd.clone()
            ).unwrap();
            let mut tumbler_channel_sender = gb_sender.channel;
            let tumbler_channel_receiver = gb_receiver.channel;
            println!("Tumbler :: pay_tmbl: {} ms", timer.elapsed().unwrap().as_millis());

            tumbler.channel_solve_part2(
                &mut tumbler_channel_sender,
                &witness
            ).unwrap();

            blind_channel_sender.complete_aed_trnasaction(&witness).unwrap();

            match &mut blind_channel_sender.status {
                crate::channel::ChannelStatus::SplitFinal { .. } => panic!("invalid status"),
                crate::channel::ChannelStatus::SplitDeliv {
                    aed_transaction,
                    ..
                } => {
                    // Assume we find the split transaction in blockchain
                    let split_transaction = Transaction::read_channel(&mut tumbler_channel_sender).unwrap();
                    loop {
                        std::thread::sleep(std::time::Duration::from_micros(200));
                        let raw = bitcoin_cli_tumbler.get_raw_transaction(
                            &split_transaction.txid().to_hex()
                        );
                        if raw.is_ok() {
                            aed_transaction.input[0].previous_output.txid = split_transaction.txid();
                            aed_transaction.output[0].value = split_transaction.output[0].value - 10_0000;
                            bitcoin_cli_tumbler.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&aed_transaction)).unwrap();
                            bitcoin_cli_tumbler.mine(10, address_null).unwrap();
                            break;
                        }
                    }
                }
            };
            println!("Tumbler  <==> Receiver: {} KB", tumbler_channel_receiver.total_kilobytes());
        });

        let handler_receiver= std::thread::spawn(move || {
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
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(receiver_channel_tumbler, rng).unwrap();
            blind_channel.make_transfer(
                &circ_receiver,
                &mut ev,
                crate::channel::ChannelUserRole::Payee,
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
            // let receiver_channel_tumbler = ev.channel;

            let witness = receiver.channel_solve(
                &mut receiver_channel_sender,
                &rsohc_statement_rand
            ).unwrap();

            assert_eq!(
                statement,
                Secp256k1Point::generator_mul(&witness)
            );

            blind_channel.complete_aed_trnasaction(&witness).unwrap();
            match blind_channel.status {
                crate::channel::ChannelStatus::SplitFinal { .. } => panic!("invalid status"),
                crate::channel::ChannelStatus::SplitDeliv {
                    commitment_transaction,
                    split_transaction,
                    aed_transaction,
                    ..
                } => {
                    bitcoin_cli_receiver.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&commitment_transaction)).unwrap();
                    bitcoin_cli_receiver.mine(10, address_null).unwrap();
                    bitcoin_cli_receiver.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&split_transaction)).unwrap();
                    bitcoin_cli_receiver.send_raw_transaction(&bitcoin::consensus::encode::serialize_hex(&aed_transaction)).unwrap();
                    bitcoin_cli_receiver.mine(10, address_null).unwrap();
                }
            };
        });

        handler_sender.join().unwrap();
        handler_tumbler.join().unwrap();
        handler_receiver.join().unwrap();

        println!("Total: {} ms", time_total.elapsed().unwrap().as_millis());

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
        let reader = BufReader::new(std::fs::File::open(
            "circuit/zk_all.circ"
        ).unwrap());
        let circ_all_sender: Circuit = bincode::deserialize_from(reader).unwrap();    
        let circ_all_tumbler = circ_all_sender.clone();
        let circ_all_receiver = circ_all_sender.clone();
        let reader = BufReader::new(std::fs::File::open(
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

        let (
            mut sender_channel_tumbler,
            mut tumbler_channel_sender
        ) = track_unix_channel_pair();
        let (
            mut sender_channel_receiver,
            mut receiver_channel_sender,
        ) = track_unix_channel_pair();
        let (
            mut tumbler_channel_receiver,
            mut receiver_channel_tumbler
        ) = track_unix_channel_pair();

        let split_return_amount_init = 29_9980_0000_u64;
        let transfer_amount = 20_0000_0000_u64;
        let fee_amount = 10_0000_u64;

        let time_total = SystemTime::now();

        let handler_sender = std::thread::spawn(move || {
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
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(sender_channel_tumbler, rng).unwrap();
            blind_channel_lock.make_transfer(
                &circ_all_sender,
                &mut ev,
                crate::channel::ChannelUserRole::Payer,
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
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(sender_channel_tumbler, rng).unwrap();
            blind_channel.make_transfer(
                &circ_all_sender,
                &mut ev,
                crate::channel::ChannelUserRole::Payer,
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
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(sender_channel_tumbler, rng).unwrap();
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
                crate::channel::ChannelStatus::SplitDeliv { .. } => panic!("invalid status"),
                crate::channel::ChannelStatus::SplitFinal {
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

            // let mut garbler_sender = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(chan_blnd, rng).unwrap();

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
            let mut gb_sender = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(tumbler_channel_sender, rng).unwrap();
            blind_channel_sender_lock.make_transfer(
                &circ_all_tumbler,
                &mut gb_sender,
                crate::channel::ChannelUserRole::Payer,
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
            let mut gb_receiver = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(tumbler_channel_receiver, rng).unwrap();
            blind_channel_receiver.make_transfer(
                &circ_all_tumbler,
                &mut gb_receiver,
                crate::channel::ChannelUserRole::Payee,
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
            let mut gb_sender = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(tumbler_channel_sender, rng).unwrap();
            blind_channel_sender.make_transfer(
                &circ_all_tumbler,
                &mut gb_sender,
                crate::channel::ChannelUserRole::Payer,
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
            let mut gb_sender = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(tumbler_channel_sender, rng).unwrap();
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
            let mut gb_receiver = Garbler::<TrackUnixChannel, AesRng, NaorPinkasSender>::new(tumbler_channel_receiver, rng).unwrap();
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
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(receiver_channel_tumbler, rng).unwrap();
            blind_channel.make_transfer(
                &circ_all_receiver,
                &mut ev,
                crate::channel::ChannelUserRole::Payee,
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
            let mut ev = Evaluator::<TrackUnixChannel, AesRng, NaorPinkasReceiver>::new(receiver_channel_tumbler, rng).unwrap();
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

        println!("Total: {} ms", time_total.elapsed().unwrap().as_millis());

    }
}