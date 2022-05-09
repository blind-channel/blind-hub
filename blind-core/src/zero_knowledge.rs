use curv::{elliptic::curves::{ECScalar, ECPoint, bls12_381::{g1::G1Point, scalar::FieldScalar}}, BigInt, arithmetic::Converter};
use sha2::{Sha256, Digest};

pub struct CommitmentEqualityProof {
    mask_com1: G1Point,
    mask_com2: G1Point,
    result_m: FieldScalar,
    result_r1: FieldScalar,
    result_r2: FieldScalar
}

impl CommitmentEqualityProof {
    pub fn prove(
        m: &FieldScalar,
        r1: &FieldScalar,
        r2: &FieldScalar
    ) -> Self {
        let mask_m = FieldScalar::random();
        let mask_r1 = FieldScalar::random();
        let mask_r2 = FieldScalar::random();
        let mask_com1 = G1Point::generator_mul(&mask_m).add_point(&G1Point::base_point2().scalar_mul(&mask_r1));
        let mask_com2 = G1Point::generator_mul(&mask_m).add_point(&G1Point::base_point2().scalar_mul(&mask_r2));
        let challenge = FieldScalar::from_bigint(&BigInt::from_bytes(
            &Sha256::digest(&[mask_com1.serialize_compressed(), mask_com2.serialize_compressed()].concat())
        ));
        let result_m = mask_m.add(&challenge.mul(&m));
        let result_r1 = mask_r1.add(&challenge.mul(&r1));
        let result_r2 = mask_r2.add(&challenge.mul(&r2));
        Self { mask_com1, mask_com2, result_m, result_r1, result_r2 }
    }

    pub fn verify(&self, com1: &G1Point, com2: &G1Point) -> anyhow::Result<()>{
        let challenge = FieldScalar::from_bigint(&BigInt::from_bytes(
            &Sha256::digest(&[self.mask_com1.serialize_compressed(), self.mask_com2.serialize_compressed()].concat())
        ));
        if G1Point::generator_mul(&self.result_m).add_point(&G1Point::base_point2().scalar_mul(&self.result_r1)) != com1.scalar_mul(&challenge).add_point(&&self.mask_com1){
            return Err(anyhow::anyhow!("mask for commitment 1 not correct"))
        }
        if G1Point::generator_mul(&self.result_m).add_point(&G1Point::base_point2().scalar_mul(&self.result_r2)) != com2.scalar_mul(&challenge).add_point(&&self.mask_com2){
            return Err(anyhow::anyhow!("mask for commitment 2 not correct"))
        }
        Ok(())
    }

    pub fn serialize(&self) -> [u8;192]{
        let mut result = [0u8;192];
        result[  0.. 48].copy_from_slice(&self.mask_com1.serialize_compressed());
        result[ 48.. 96].copy_from_slice(&self.mask_com2.serialize_compressed());
        result[ 96..128].copy_from_slice(&self.result_m.serialize());
        result[128..160].copy_from_slice(&self.result_r1.serialize());
        result[160..192].copy_from_slice(&self.result_r2.serialize());
        result
    }

    pub fn deserialize(data: &[u8]) -> anyhow::Result<Self>{
        Ok(Self{
            mask_com1: G1Point::deserialize(
                &data[  0.. 48]).map_err(|_|anyhow::anyhow!("failed to parse mask_com1"))?,
            mask_com2: G1Point::deserialize(
                &data[ 48.. 96]).map_err(|_|anyhow::anyhow!("failed to parse mask_com2"))?,
            result_m:  FieldScalar::deserialize(
                &data[ 96..128]).map_err(|_|anyhow::anyhow!("failed to parse result_m"))?,
            result_r1: FieldScalar::deserialize(
                &data[128..160]).map_err(|_|anyhow::anyhow!("failed to parse result_r1"))?,
            result_r2: FieldScalar::deserialize(
                &data[160..192]).map_err(|_|anyhow::anyhow!("failed to parse result_r2"))?
        })
    }
}

#[cfg(test)]
mod tests{
    use curv::elliptic::curves::{ECScalar, ECPoint, bls12_381::{scalar::FieldScalar, g1::G1Point}};

    use super::CommitmentEqualityProof;

    #[test]
    fn test_commitment_equality() {
        let m = FieldScalar::random();
        let r1 = FieldScalar::random();
        let r2 = FieldScalar::random();
        let com1 = G1Point::generator_mul(&m).add_point(&G1Point::base_point2().scalar_mul(&r1));
        let com2 = G1Point::generator_mul(&m).add_point(&G1Point::base_point2().scalar_mul(&r2));
        let proof = CommitmentEqualityProof::prove(&m, &r1, &r2);
        CommitmentEqualityProof::deserialize(&proof.serialize()).unwrap().verify(&com1, &com2).unwrap();
    }
}