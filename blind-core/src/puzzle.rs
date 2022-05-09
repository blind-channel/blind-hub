use class_group::primitives::cl_dl_public_setup::{self, Ciphertext,CLGroup,PK, SK, CLDLProof};
use curv::{elliptic::curves::{secp256_k1::{Secp256k1Point, Secp256k1Scalar}, ECScalar, ECPoint, bls12_381::{g1::G1Point, scalar::FieldScalar}}, BigInt};

#[derive(Debug)]
pub struct PuzzleStatement{
    pub(crate) secp256k1_point: Secp256k1Point,
    pub(crate) bls12_381_point: G1Point,
    pub(crate) ciphertext: Ciphertext,
    pub(crate) proof: CLDLProof
}

impl PuzzleStatement {
    pub fn from_witness(
        witness: &BigInt,
        clgroup: &CLGroup,
        clpk: &PK
    ) -> PuzzleStatement{
        let secp256k1_witness = Secp256k1Scalar::from_bigint(&witness);
        let secp256k1_point = Secp256k1Point::generator().scalar_mul(&secp256k1_witness);
        let bls12_381_witness = FieldScalar::from_bigint(&witness);
        let bls12_381_point = G1Point::generator().scalar_mul(&bls12_381_witness);
        let (ciphertext, proof) = cl_dl_public_setup::verifiably_encrypt(
            clgroup,
            clpk,
            (&secp256k1_witness, &secp256k1_point)
        );
        //TODO: equality proof
        PuzzleStatement {
            secp256k1_point,
            bls12_381_point,
            ciphertext,
            proof
        }
    }

    pub fn get_secp256k1_point(&self) -> &Secp256k1Point {
        return &self.secp256k1_point;
    }

    pub fn get_bls12_381_point(&self) -> &G1Point {
        return &self.bls12_381_point;
    }
    
    pub fn decrypt(&self, clgroup: &CLGroup, clsk: &SK) -> BigInt{
        cl_dl_public_setup::decrypt(clgroup, clsk, &self.ciphertext)
    }

    pub fn verify(&self, clgroup: &CLGroup, clpk: &PK) -> anyhow::Result<()> {
        self.proof.verify(
            clgroup, 
            clpk, 
            &self.ciphertext, 
            &self.secp256k1_point
        ).map_err(|_| anyhow::anyhow!("failed to verify proof"))
        //TODO: equality proof
    }
}

#[cfg(test)]
mod tests{
    use class_group::primitives::cl_dl_public_setup::{CLGroup, sample_prime_by_length};
    use curv::{BigInt, arithmetic::Zero, elliptic::curves::{bls12_381::scalar::FieldScalar, ECScalar}};

    use super::PuzzleStatement;

    #[test]
    fn test_statement(){
        let clgroup = CLGroup::new_from_setup(&3845, &BigInt::zero(), &sample_prime_by_length(800));
        let (clsk, clpk) = clgroup.keygen();
        let witness = FieldScalar::random().to_bigint();
        let statement =  PuzzleStatement::from_witness(&witness, &clgroup, &clpk);

        statement.verify(&clgroup, &clpk).unwrap();

        let extracted = statement.decrypt(&clgroup, &clsk);
        assert_eq!(extracted, witness)
    }
}