use curv::elliptic::curves::{bls12_381::{g1::G1Point, scalar::FieldScalar, g2::G2Point, Pair}, ECScalar, ECPoint, Bls12_381_1, Point, Bls12_381_2};

pub fn commit_with_randomness(
    m: &FieldScalar,
    r: &FieldScalar
) -> G1Point {
    G1Point::generator_mul(&m).add_point(
        &G1Point::base_point2().scalar_mul(&r)
    )
}

pub fn commit(
    m: &FieldScalar
) -> (G1Point, FieldScalar) {
    let r = FieldScalar::random();
    (commit_with_randomness(m, &r), r)
}

pub struct SecretKey{
    x0: FieldScalar,
    x1: FieldScalar,
    x2: FieldScalar
}

impl SecretKey {
    pub fn new() -> Self {
        Self{
            x0: FieldScalar::random(),
            x1: FieldScalar::random(),
            x2: FieldScalar::random(),
        }
    }

    pub fn sign(
        &self,
        statement: &G1Point,
        commitment1: &G1Point,
        commitment2: &G1Point
    ) -> Signature {
        let r = FieldScalar::random();
        let a_g1 = G1Point::generator()
            .add_point(&statement.scalar_mul(&self.x0))
            .add_point(&commitment1.scalar_mul(&self.x1))
            .add_point(&commitment2.scalar_mul(&self.x2))
            .scalar_mul(&r.invert().unwrap());
        let v_g1 = G1Point::generator_mul(&r);
        let v_g2 = G2Point::generator_mul(&r);
        let t_g1 = G1Point::generator_mul(&self.x0)
            .add_point(&G1Point::base_point2().scalar_mul(&self.x1))
            .add_point(&G1Point::base_point2().scalar_mul(&self.x2))
            .scalar_mul(&r.invert().unwrap());
        Signature{
            a_g1,
            v_g1,
            v_g2,
            t_g1,
        }
    }
}

#[derive(Clone)]
pub struct PublicKey{
    y0: G2Point,
    y1: G2Point,
    y2: G2Point
}

impl PublicKey {
    pub fn from_sk(sk: &SecretKey) -> Self {
        Self{
            y0: G2Point::generator_mul(&sk.x0),
            y1: G2Point::generator_mul(&sk.x1),
            y2: G2Point::generator_mul(&sk.x2),
        }
    }
}

pub struct Signature {
    a_g1: G1Point,
    v_g1: G1Point,
    v_g2: G2Point,
    t_g1: G1Point
}

impl Signature {
    pub fn serialize(&self) -> [u8;240] {
        let encoded_a_g1 = self.a_g1.serialize_compressed();
        let encoded_v_g1 = self.v_g1.serialize_compressed();
        let encoded_v_g2 = self.v_g2.serialize_compressed();
        let encoded_t_g1 = self.t_g1.serialize_compressed();

        let mut encoded = [0u8;240];
        encoded[000..048].copy_from_slice(encoded_a_g1.as_slice());
        encoded[048..096].copy_from_slice(encoded_v_g1.as_slice());
        encoded[096..192].copy_from_slice(encoded_v_g2.as_slice());
        encoded[192..240].copy_from_slice(encoded_t_g1.as_slice());
        encoded
    }

    pub fn deserialize(encoded: &[u8;240]) -> anyhow::Result<Self>{
        let a_g1 = G1Point::deserialize(&encoded[000..048])?;
        let v_g1 = G1Point::deserialize(&encoded[048..096])?;
        let v_g2 = G2Point::deserialize(&encoded[096..192])?;
        let t_g1 = G1Point::deserialize(&encoded[192..240])?;
        Ok(Self {
            a_g1,
            v_g1,
            v_g2,
            t_g1,
        })
    }

    pub fn randomize(
        &mut self,
        statement: &mut G1Point,
        commitment1: &mut G1Point,
        commitment2: &mut G1Point,
    ) -> FieldScalar {
        let r1 = FieldScalar::random();
        let r2 = FieldScalar::random();
        let a_g1 = self.a_g1.add_point(&self.t_g1.scalar_mul(&r1)).scalar_mul(&r2.invert().unwrap());
        let v_g1 = self.v_g1.scalar_mul(&r2);
        let v_g2 = self.v_g2.scalar_mul(&r2);
        let t_g1 = self.t_g1.scalar_mul(&r2.invert().unwrap());

        *self = Signature{ a_g1, v_g1, v_g2, t_g1 };
        statement.add_point_assign(&G1Point::generator_mul(&r1));
        commitment1.add_point_assign(&G1Point::base_point2().scalar_mul(&r1));
        commitment2.add_point_assign(&G1Point::base_point2().scalar_mul(&r1));

        r1
    }

    pub fn verify(
        &self,
        pk: &PublicKey,
        statement: &G1Point,
        commitment1: &G1Point,
        commitment2: &G1Point
    ) -> anyhow::Result<()> {
        let cond1_left = Pair::compute_pairing(
            &Point::<Bls12_381_1>::from_raw(self.a_g1.clone())?,
            &Point::<Bls12_381_2>::from_raw(self.v_g2.clone())?
        );
        let cond1_right = Pair::compute_pairing(&Point::<Bls12_381_1>::generator(), &Point::<Bls12_381_2>::generator())
            .add_pair(&Pair::compute_pairing(
                &Point::<Bls12_381_1>::from_raw(statement.clone())?,
                &Point::<Bls12_381_2>::from_raw(pk.y0.clone())?
            ))
            .add_pair(&Pair::compute_pairing(
                &Point::<Bls12_381_1>::from_raw(commitment1.clone())?,
                &Point::<Bls12_381_2>::from_raw(pk.y1.clone())?
            ))
            .add_pair(&Pair::compute_pairing(
                &Point::<Bls12_381_1>::from_raw(commitment2.clone())?,
                &Point::<Bls12_381_2>::from_raw(pk.y2.clone())?
            ));
        if  cond1_left != cond1_right{
            return Err(anyhow::anyhow!("invalid signature"));
        }

        let cond2_left = Pair::compute_pairing(
            &Point::<Bls12_381_1>::generator(),
            &Point::<Bls12_381_2>::from_raw(self.v_g2.clone())?
        );
        let cond2_right = Pair::compute_pairing(
            &Point::<Bls12_381_1>::from_raw(self.v_g1.clone())?,
            &Point::<Bls12_381_2>::generator()
        );
        if  cond2_left != cond2_right{
            return Err(anyhow::anyhow!("invalid signature"));
        }

        let cond3_left = Pair::compute_pairing(
            &Point::<Bls12_381_1>::from_raw(self.t_g1.clone())?,
            &Point::<Bls12_381_2>::from_raw(self.v_g2.clone())?
        );
        let cond3_right = Pair::compute_pairing(
            &Point::<Bls12_381_1>::generator(),
            &Point::<Bls12_381_2>::from_raw(pk.y0.clone())?
        ).add_pair(&Pair::compute_pairing(
            &Point::<Bls12_381_1>::base_point2(),
            &Point::<Bls12_381_2>::from_raw(pk.y1.clone())?
        )).add_pair(&Pair::compute_pairing(
            &Point::<Bls12_381_1>::base_point2(),
            &Point::<Bls12_381_2>::from_raw(pk.y2.clone())?
        ));

        if  cond3_left != cond3_right{
            return Err(anyhow::anyhow!("invalid signature"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests{
    use curv::elliptic::curves::{bls12_381::{g1::G1Point, scalar::FieldScalar}, ECPoint, ECScalar};

    use super::{SecretKey, PublicKey, commit, Signature};

    #[test]
    fn test_all() {
        let mut witness = FieldScalar::random();
        let commitment1_message = FieldScalar::random();
        let commitment2_message = FieldScalar::random();

        let mut statement = G1Point::generator_mul(&witness);
        let (mut commitment1, mut commitment1_randomness) = commit(&commitment1_message);
        let (mut commitment2, mut commitment2_randomness) = commit(&commitment2_message);
        
        let sk = SecretKey::new();
        let pk = PublicKey::from_sk(&sk);

        let mut sig = sk.sign(&statement, &commitment1, &commitment2);

        let r1 = sig.randomize(
            &mut statement,
            &mut commitment1,
            &mut commitment2
        );
        witness.add_assign(&r1);
        commitment1_randomness.add_assign(&r1);
        commitment2_randomness.add_assign(&r1);

        let r1 = sig.randomize(
            &mut statement,
            &mut commitment1,
            &mut commitment2
        );
        witness.add_assign(&r1);
        commitment1_randomness.add_assign(&r1);
        commitment2_randomness.add_assign(&r1);

        let sig = Signature::deserialize(&sig.serialize()).unwrap();

        sig.verify(&pk, &statement, &commitment1, &commitment2).unwrap();

        assert_eq!(&G1Point::generator_mul(&witness), &statement);
    }
}