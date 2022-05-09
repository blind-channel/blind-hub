use bitcoin::{secp256k1::{ecdsa::Signature, SecretKey}, PublicKey};
use curv::{elliptic::curves::{secp256_k1::{Secp256k1Point, Secp256k1Scalar, self}, ECScalar, ECPoint, Secp256k1, Scalar, Point}, BigInt, arithmetic::Converter};
use sha2::{Sha256, Digest};

#[derive(Clone)]
pub struct AdaptorSignature{
    r: Scalar<Secp256k1>,
    s_tilde: Scalar<Secp256k1>,
    k_point: Point<Secp256k1>,
    zk_k_tilde: Point<Secp256k1>,
    zk_k_point: Point<Secp256k1>,
    zk_scalar: Scalar<Secp256k1>
}

impl AdaptorSignature {
    pub fn sign(statement: &PublicKey, message: &[u8;32], sk: &SecretKey) -> Self {
        Self::sign_kzen(
            &Secp256k1Point::from_underlying(Some(secp256_k1::PK(statement.inner))),
            message,
            &Secp256k1Scalar::from_underlying(Some(secp256_k1::SK(sk.clone())))
        )
    }

    pub fn sign_kzen(statement: &Secp256k1Point, message: &[u8;32], sk: &Secp256k1Scalar) -> Self{
        let k_scalar = Secp256k1Scalar::random();
        let k_point = statement.scalar_mul(&k_scalar);
        let r = Secp256k1Scalar::from_bigint(&k_point.x_coord().unwrap());
        let s_tilde = k_scalar.invert().unwrap().mul(
            &Secp256k1Scalar::from_bigint(&BigInt::from_bytes(message)).add(
                &sk.mul(&r)
            )
        );

        let zk_randomness = Secp256k1Scalar::random();
        let zk_k_tilde = Secp256k1Point::generator_mul(&zk_randomness);
        let zk_k_point = statement.scalar_mul(&zk_randomness);
        let zk_challenge = Secp256k1Scalar::from_bigint(&BigInt::from_bytes(
            &Sha256::digest(&[zk_k_tilde.serialize_compressed(), zk_k_point.serialize_compressed()].concat())
        ));
        let zk_scalar = zk_randomness.add(&zk_challenge.mul(&k_scalar));
        return Self {
            r: Scalar::<Secp256k1>::from_raw(r),
            s_tilde: Scalar::<Secp256k1>::from_raw(s_tilde),
            k_point: Point::<Secp256k1>::from_raw(k_point).unwrap(),
            zk_k_tilde: Point::<Secp256k1>::from_raw(zk_k_tilde).unwrap(),
            zk_k_point: Point::<Secp256k1>::from_raw(zk_k_point).unwrap(),
            zk_scalar: Scalar::<Secp256k1>::from_raw(zk_scalar)
        }
    }

    pub fn pre_verify(&self, statement: &PublicKey, message: &[u8;32], pk: &PublicKey) -> anyhow::Result<()> {
        self.pre_verify_kzen(
            &Secp256k1Point::from_underlying(Some(secp256_k1::PK(statement.inner))),
            message,
            &Secp256k1Point::from_underlying(Some(secp256_k1::PK(pk.inner))),
        )
    }

    pub fn pre_verify_kzen(&self, statement: &Secp256k1Point, message: &[u8;32], pk: &Secp256k1Point) -> anyhow::Result<()>{
        let u = Secp256k1Scalar::from_bigint(&BigInt::from_bytes(message)).mul(&self.s_tilde.invert().ok_or(anyhow::anyhow!("s_tilde is 0"))?.as_raw());
        let v = self.r.as_raw().mul(&self.s_tilde.as_raw().invert().ok_or(anyhow::anyhow!("s_tilde is 0"))?);
        let k_prime = Secp256k1Point::generator_mul(&u).add_point(
            &pk.scalar_mul(&v)
        );
        if self.r.as_raw() != &Secp256k1Scalar::from_bigint(&self.k_point.x_coord().unwrap()){
            return Err(anyhow::anyhow!("checked failed"))
        }
        let challenge = Secp256k1Scalar::from_bigint(&BigInt::from_bytes(
            &Sha256::digest(&[self.zk_k_tilde.as_raw().serialize_compressed(), self.zk_k_point.as_raw().serialize_compressed()].concat())
        ));
        if Secp256k1Point::generator_mul(&self.zk_scalar.as_raw()) != self.zk_k_tilde.as_raw().add_point(&k_prime.scalar_mul(&challenge)) {
            return Err(anyhow::anyhow!("checked failed"))
        }
        if statement.scalar_mul(&self.zk_scalar.as_raw()) != self.zk_k_point.as_raw().add_point(&self.k_point.as_raw().scalar_mul(&challenge)){
            return Err(anyhow::anyhow!("checked failed"))
        }

        Ok(())
    }

    pub fn adapt(&self, witness: &SecretKey) -> anyhow::Result<Signature> {
        self.adapt_kzen(&Secp256k1Scalar::from_underlying(Some(secp256_k1::SK(witness.clone()))))
    }

    pub fn adapt_kzen(&self, witness: &Secp256k1Scalar) -> anyhow::Result<Signature> {
        let s = {
            let temp = self.s_tilde.as_raw().mul(&witness.invert().ok_or(anyhow::anyhow!("witness is 0"))?);
            if temp.serialize()[0] >= 128u8 {
                temp.neg()
            } else {
                temp
            }
        };
        let data = [
            self.r.as_raw().serialize(),
            s.serialize()
        ].concat();
        // dbg!(self.r.serialize().to_hex());
        // dbg!(s.serialize().to_hex());
        debug_assert_eq!(
            &self.r.as_raw().serialize().as_slice(),
            &self.r.as_raw().underlying_ref().clone().unwrap().0.secret_bytes()
        );
        debug_assert_eq!(
            &s.serialize().as_slice(),
            &s.underlying_ref().clone().unwrap().0.secret_bytes()
        );
        Ok(Signature::from_compact(&data)?)
    }

    pub fn extract(&self, sig: &Signature, statement: &Secp256k1Point) -> anyhow::Result<Secp256k1Scalar>{
        let s = Secp256k1Scalar::deserialize(&sig.serialize_compact()[32..64])?;
        let witness = s.invert().ok_or(anyhow::anyhow!("s is 0"))?.mul(&self.s_tilde.as_raw());
        if &Secp256k1Point::generator_mul(&witness) == statement {
            return Ok(witness);
        }
        let witness = witness.neg();
        if &Secp256k1Point::generator_mul(&witness) == statement {
            return Ok(witness);
        }
        Err(anyhow::anyhow!("invalid extraction"))
    }

    pub fn serialize(&self) -> [u8;195]{
        let mut data = [0u8;195];
        data[000..032].copy_from_slice(&self.r.as_raw().serialize());
        data[032..064].copy_from_slice(&self.s_tilde.as_raw().serialize());
        data[064..097].copy_from_slice(&self.k_point.as_raw().serialize_compressed());
        data[097..130].copy_from_slice(&self.zk_k_tilde.as_raw().serialize_compressed());
        data[130..163].copy_from_slice(&self.zk_k_point.as_raw().serialize_compressed());
        data[163..195].copy_from_slice(&self.zk_scalar.as_raw().serialize());
        data
    }

    pub fn deserialize(data: &[u8]) -> anyhow::Result<Self>{
        Ok(Self{
            r: Scalar::<Secp256k1>::from_raw(Secp256k1Scalar::deserialize(&data[000..032])?),
            s_tilde: Scalar::<Secp256k1>::from_raw(Secp256k1Scalar::deserialize(&data[032..064])?),
            k_point: Point::<Secp256k1>::from_raw(Secp256k1Point::deserialize(&data[064..097])?)?,
            zk_k_tilde: Point::<Secp256k1>::from_raw(Secp256k1Point::deserialize(&data[097..130])?)?,
            zk_k_point: Point::<Secp256k1>::from_raw(Secp256k1Point::deserialize(&data[130..163])?)?,
            zk_scalar: Scalar::<Secp256k1>::from_raw(Secp256k1Scalar::deserialize(&data[163..195])?),
        })
    }
}

#[cfg(test)]
mod tests{
    use bitcoin::{secp256k1::Message};
    use curv::{elliptic::curves::{secp256_k1::{Secp256k1Scalar, Secp256k1Point}, ECScalar, ECPoint}};

    use crate::ecdsa::AdaptorSignature;

    #[test]
    fn test_adaptor_signature(){
        //Secp256k1 serialize is big endian
        // dbg!(Secp256k1Scalar::from_bigint(&BigInt::from(2)).serialize().to_hex());
        // dbg!(Secp256k1Scalar::group_order().to_hex());

        // let clgroup = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix("191238981236130138", 10).unwrap());
        // let (_, clpk) = clgroup.keygen();
        let mut rng = rand::rngs::ThreadRng::default();
        let sk = Secp256k1Scalar::random();
        let pk = Secp256k1Point::generator_mul(&sk);
        let msg = rand::Rng::gen::<[u8;32]>(&mut rng);
        let witness = Secp256k1Scalar::random();
        let statement =  Secp256k1Point::generator_mul(&witness);

        let pre_signature = AdaptorSignature::sign(
            &bitcoin::PublicKey::new(statement.underlying_ref().unwrap().0),
            &msg,
            &sk.underlying_ref().clone().unwrap().0
        );
        let pre_signature_bytes = pre_signature.serialize();
        let pre_signature = AdaptorSignature::deserialize(&pre_signature_bytes).unwrap();
        assert!(pre_signature.pre_verify(
            &bitcoin::PublicKey::new(statement.underlying_ref().unwrap().0),
            &msg,
            &bitcoin::PublicKey::new(pk.underlying_ref().unwrap().0),
        ).is_ok());

        let signature = pre_signature.adapt(&witness.underlying_ref().clone().unwrap().0).unwrap();
        let msg = Message::from_slice(&msg).unwrap();
        let pk = pk.underlying_ref().unwrap();
        assert!(signature.verify(&msg, &pk).is_ok());

        let extracted_witness = pre_signature.extract(&signature, &statement).unwrap();
        assert_eq!(witness, extracted_witness);
    }
}
