//! Implementation verifiable encryption of discrete logarithms in the Castagnos
//! and Laguillaumie cryptosystem where the CL group has a public setup.
//!
//!
//! The advantage of the CL cryptosystem is that you can generate a CL-group of
//! unknown order by where the discrete logarithm is **easy** for a subgroup of
//! an order of your choosing. For example, this allows you to generate a group
//! where you can verifiably encrypt the private key of a Bitcoin public key.
//!
//! 1. CL-groups were defined in https://eprint.iacr.org/2015/047.pdf, along
//!    with the original CPA-secure encryption scheme.
//! 2. The particular group generation algorithm, where you pass in the order of
//!    the DL-easy subgroup was shown in https://eprint.iacr.org/2019/503.pdf.
//! 3. The proof of equivalence between the discrete logarithm of a DL group
//!    element and the plaintext of a CL ciphertext in a CL-group with a public
//!    setup is given in https://eprint.iacr.org/2020/084.pdf (see section 5.2)

use super::ErrorReason;
use crate::pari_init;
use crate::primitives::numerical_log;
use crate::primitives::prng;
use crate::BinaryQF;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::Digest;
// use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use curv::elliptic::curves::ECPoint;
use curv::elliptic::curves::ECScalar;
use curv::elliptic::curves::Point;
use curv::elliptic::curves::Secp256k1;
use curv::elliptic::curves::secp256_k1::Secp256k1Point;
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;
use sha2::Sha256;
use std::ops::AddAssign;
use std::ops::Neg;

const SECURITY_PARAMETER: usize = 128;
const C: usize = 10;

pub fn sample_prime_by_length(bit_length: u32) -> BigInt {
    let mut q = BigInt::sample_range(
        &BigInt::from(2).pow(bit_length - 1),
        &BigInt::from(2).pow(bit_length).sub(&BigInt::one())
    );
    while !q.is_probable_prime(200) {
        q.add_assign(&BigInt::one());
    }
    // dbg!(&q);
    q
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLGroup {
    pub delta_k: BigInt,
    pub delta_q: BigInt,
    pub gq: BinaryQF,
    pub stilde: BigInt,
    pub q: BigInt
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Ciphertext {
    pub c1: BinaryQF,
    pub c2: BinaryQF,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TTriplets {
    pub t1: BinaryQF,
    pub t2: BinaryQF,
    pub T: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct U1U2 {
    pub u1: BigInt,
    pub u2: BigInt,
}

#[derive(Debug, Clone)]
pub struct ProofError;

impl CLGroup {
    pub fn new_from_setup(lam: &usize, seed: &BigInt, q: &BigInt) -> Self {
        unsafe { pari_init(100000000, 2) };
        let mu = q.bit_length();
        assert!(lam > &(mu + 2));
        let k = lam - mu;
        let two = BigInt::from(2);
        let mut r = BigInt::sample_range(
            &two.pow((k - 1) as u32),
            &(two.pow(k as u32) - BigInt::one()),
        );

        let mut qtilde = next_probable_prime(&r);

        while (q * &qtilde).mod_floor(&BigInt::from(4)) != BigInt::from(3)
            || jacobi(q, &qtilde).unwrap() != -1
        {
            r = BigInt::sample_range(
                &two.pow((k - 1) as u32),
                &(two.pow(k as u32) - BigInt::one()),
            );
            qtilde = next_probable_prime(&r);
        }

        debug_assert!(BigInt::from(4) * q < qtilde);

        let delta_k = -q * &qtilde;
        let delta_q = &delta_k * q.pow(2);

        let delta_k_abs: BigInt = -(&delta_k);
        let log_delta_k_abs = numerical_log(&delta_k_abs);
        let delta_k_abs_sqrt = delta_k_abs.sqrt();
        let stilde = log_delta_k_abs * delta_k_abs_sqrt;

        // Assuming GRH the prime forms f_p with p<=6 ln^2(|delta_k|) generate the class group cf.
        // Cohen course comp. algebraic. number theory 5.5.1.
        // In practice we take only ln(-deltak)/ln(ln(-deltak))  primes and exponents up to 20 (cf. 5.5.2)
        // But as in https://eprint.iacr.org/2018/705.pdf page 20 we need pairwise coprime exponents
        // for the strong root assumption to hold so we take greater exponents to ensure that,
        // say up to 15 bits. (in fact for our purposes exponents globally coprime might be sufficient instead of pairwise coprimes)
        let mut prime_forms_vec: Vec<BinaryQF> = Vec::new();
        let mut r = BigInt::from(3);
        let ln_delta_k = numerical_log(&(-&delta_k));

        let num_of_prime_forms = ln_delta_k.div_floor(&numerical_log(&ln_delta_k));

        let mut i = BigInt::zero();
        while i < num_of_prime_forms {
            while jacobi(&delta_k, &r).unwrap() != 1 {
                r = next_probable_small_prime(&r)
            }
            prime_forms_vec.push(BinaryQF::primeform(&delta_k, &r));
            r = next_probable_small_prime(&r);
            i += 1;
        }
        let mut rgoth = BinaryQF::binary_quadratic_form_principal(&delta_k);

        //pseudo random element of class group Cl(delta_k) : prod f_p^e_p, with pairwise coprime exponents
        // generate enough pseudo randomness : 15 bits per exponents e_p

        // find exponent
        let mut i = 0;
        let mut rand_bits_i: BigInt;
        let mut prod_exponent = BigInt::one();
        while i < prime_forms_vec.len() {
            // extract 15bits
            rand_bits_i = prng(seed, i, 15);
            while rand_bits_i.gcd(&prod_exponent) != BigInt::one() {
                rand_bits_i += 1;
            }
            rgoth = rgoth
                .compose(&prime_forms_vec[i].exp(&rand_bits_i))
                .reduce();
            prod_exponent *= &rand_bits_i;
            i += 1;
        }

        let rgoth_square = rgoth.compose(&rgoth).reduce();

        let gq_tmp = rgoth_square.phi_q_to_the_minus_1(q).reduce();

        let gq = gq_tmp.exp(q);

        CLGroup {
            delta_k,
            delta_q,
            gq,
            stilde,
            q: q.clone()
        }
    }

    //repeat random element g_q generation using seed and delta_k
    pub fn setup_verify(&self, seed: &BigInt) -> Result<(), ErrorReason> {
        unsafe { pari_init(100000000, 2) };

        let mut prime_forms_vec: Vec<BinaryQF> = Vec::new();
        let ln_delta_k = numerical_log(&(-&self.delta_k));
        let num_of_prime_forms = ln_delta_k.div_floor(&numerical_log(&ln_delta_k));

        let mut r = BigInt::from(3);
        let mut i = BigInt::zero();
        while i < num_of_prime_forms {
            while jacobi(&self.delta_k, &r).unwrap() != 1 {
                r = next_probable_small_prime(&r)
            }
            prime_forms_vec.push(BinaryQF::primeform(&self.delta_k, &r));
            r = next_probable_small_prime(&r);
            i += 1;
        }

        let mut rgoth = BinaryQF::binary_quadratic_form_principal(&self.delta_k);

        //pseudo random element of class group Cl(delta_k) : prod f_p^e_p, with pairwise coprime exponents
        // generate enough pseudo randomness : 15 bits per exponents e_p

        // find exponent
        let mut i = 0;
        let mut rand_bits_i: BigInt;
        let mut prod_exponent = BigInt::one();
        while i < prime_forms_vec.len() {
            // extract 15bits
            rand_bits_i = prng(seed, i, 15);
            while rand_bits_i.gcd(&prod_exponent) != BigInt::one() {
                rand_bits_i += 1;
            }
            rgoth = rgoth
                .compose(&prime_forms_vec[i].exp(&rand_bits_i))
                .reduce();
            prod_exponent *= &rand_bits_i;
            i += 1;
        }

        let rgoth_square = rgoth.compose(&rgoth).reduce();

        let gq_tmp = rgoth_square
            .phi_q_to_the_minus_1(&self.q)
            .reduce();

        let gq = gq_tmp.exp(&self.q);
        match gq == self.gq {
            true => Ok(()),
            false => Err(ErrorReason::SetupError),
        }
    }

    /// randomly sample a scalar (secret key) and compute its corresponding group element (public key) by multiplying g_q
    pub fn keygen(&self) -> (SK, PK) {
        let sk = SK(BigInt::sample_below(
            &(&self.stilde * BigInt::from(2).pow(40)),
        ));
        let pk = self.pk_for_sk(&sk);
        (sk, pk)
    }

    /// Return the CL public key for a given secret key
    pub fn pk_for_sk(&self, sk: &SK) -> PK {
        let group_element = self.gq.exp(&sk.0);
        PK(group_element)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PK(BinaryQF);
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SK(BigInt);

impl From<SK> for BigInt {
    fn from(sk: SK) -> Self {
        sk.0
    }
}

impl From<BigInt> for SK {
    fn from(bi: BigInt) -> Self {
        Self(bi)
    }
}

// copied from https://docs.rs/crate/quadratic/0.3.1/source/src/lib.rs
// changed to support BigInt
// TODO: put in utility module, expend to Kronecker
fn jacobi(a: &BigInt, n: &BigInt) -> Option<i8> {
    let zero = BigInt::zero();
    // jacobi symbol is only defined for odd positive moduli
    if n.mod_floor(&BigInt::from(2)) == zero || n <= &BigInt::zero() {
        return None;
    }

    // Raise a mod n, then start the unsigned algorithm
    let mut acc = 1;
    let mut num = a.mod_floor(n);
    let mut den = n.clone();
    loop {
        // reduce numerator
        num = num.mod_floor(&den);
        if num == zero {
            return Some(0);
        }

        // extract factors of two from numerator
        while num.mod_floor(&BigInt::from(2)) == zero {
            acc *= two_over(&den);
            num = num.div_floor(&BigInt::from(2));
        }
        // if numerator is 1 => this sub-symbol is 1
        if num == BigInt::one() {
            return Some(acc);
        }
        // shared factors => one sub-symbol is zero
        if num.gcd(&den) > BigInt::one() {
            return Some(0);
        }
        // num and den are now odd co-prime, use reciprocity law:
        acc *= reciprocity(&num, &den);
        let tmp = num;
        num = den.clone();
        den = tmp;
    }
}

fn two_over(n: &BigInt) -> i8 {
    if n.mod_floor(&BigInt::from(8)) == BigInt::one()
        || n.mod_floor(&BigInt::from(8)) == BigInt::from(7)
    {
        1
    } else {
        -1
    }
}

fn reciprocity(num: &BigInt, den: &BigInt) -> i8 {
    if num.mod_floor(&BigInt::from(4)) == BigInt::from(3)
        && den.mod_floor(&BigInt::from(4)) == BigInt::from(3)
    {
        -1
    } else {
        1
    }
}

fn next_probable_prime(r: &BigInt) -> BigInt {
    let one = BigInt::from(1);
    let mut qtilde = r + &one;
    while !qtilde.is_probable_prime(200) {
        qtilde.add_assign(&one);
    }
    qtilde
}

// used for testing small primes where our prime test fails. We use Pari isprime which provides
// determinstic perfect primality checking.
fn next_probable_small_prime(r: &BigInt) -> BigInt {
    let one = BigInt::from(1);
    let mut qtilde = r + &one;
    while !qtilde.is_probable_prime(200) {
        qtilde += &one;
    }
    qtilde
}

/// CL encrypts the message under the public key.
///
/// Returns the secret randomness used.
pub fn encrypt(group: &CLGroup, public_key: &PK, m: &BigInt) -> (Ciphertext, SK) {
    let (r, R) = group.keygen();
    let exp_f = BinaryQF::expo_f(
        &group.q,
        &group.delta_q,
        m,
    );
    let h_exp_r = public_key.0.exp(&r.0);

    (
        Ciphertext {
            c1: R.0,
            c2: h_exp_r.compose(&exp_f).reduce(),
        },
        r,
    )
}

pub fn encrypt_predefined_randomness(
    group: &CLGroup,
    public_key: &PK,
    m: &BigInt,
    r: &SK,
) -> Ciphertext {
    let exp_f = BinaryQF::expo_f(
        &group.q,
        &group.delta_q,
        m,
    );
    let h_exp_r = public_key.0.exp(&r.0);

    Ciphertext {
        c1: group.gq.exp(&r.0),
        c2: h_exp_r.compose(&exp_f).reduce(),
    }
}

pub fn verifiably_encrypt(
    group: &CLGroup,
    public_key: &PK,
    DL_pair: (&Secp256k1Scalar, &Secp256k1Point),
) -> (Ciphertext, CLDLProof) {
    let (x, X) = DL_pair;
    let (ciphertext, r) = encrypt(group, public_key, &x.to_bigint());

    let proof = CLDLProof::prove(group, (&x.to_bigint(), &r), (public_key, &ciphertext, X));
    (ciphertext, proof)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLDLProof {
    t_triple: TTriplets,
    u1u2: U1U2,
}

impl CLDLProof {
    fn prove(
        group: &CLGroup,
        witness: (&BigInt, &SK),
        statement: (&PK, &Ciphertext, &Secp256k1Point),
    ) -> Self {
        let (x, r) = witness;
        let (public_key, ciphertext, X) = statement;

        let r1 = BigInt::sample_below(
            &(&group.stilde
                * BigInt::from(2).pow(40)
                * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2).pow(40)),
        );
        let r2 = BigInt::sample_below(&Secp256k1Scalar::group_order().mul(&group.q));
        let r2_fe = Secp256k1Scalar::from_bigint(&r2);
        // let r2 = r2_fe.to_bigint();
        let fr2 = BinaryQF::expo_f(&group.q, &group.delta_q, &r2);
        let pkr1 = public_key.0.exp(&r1);
        let t2 = fr2.compose(&pkr1).reduce();
        let T = Secp256k1Point::generator().scalar_mul(&r2_fe);
        let t1 = group.gq.exp(&r1);
        let t_triple = TTriplets { t1, t2, T: Point::<Secp256k1>::from_raw(T).unwrap() };

        let k = Self::challenge(public_key, &t_triple, ciphertext, X);

        let u1 = r1 + &k * &r.0;
        let u2 = BigInt::mod_add(
            &r2,
            &(&k * x),
            &Secp256k1Scalar::group_order().mul(&group.q),
        );
        let u1u2 = U1U2 { u1, u2 };

        Self { t_triple, u1u2 }
    }

    /// Compute the Fiat-Shamir challenge for the proof.
    fn challenge(
        public_key: &PK,
        t: &TTriplets,
        ciphertext: &Ciphertext,
        X: &Secp256k1Point,
    ) -> BigInt {
        let hash256 = Sha256::new()
            // hash the statement i.e. the discrete log of Q is encrypted in (c1,c2) under encryption key h.
            .chain(X.serialize_compressed())
            .chain(ciphertext.c1.to_bytes())
            .chain(ciphertext.c2.to_bytes())
            .chain(public_key.0.to_bytes())
            // hash Sigma protocol commitments
            .chain(t.t1.to_bytes())
            .chain(t.t2.to_bytes())
            .chain(&t.T.as_raw().serialize_compressed())
            .finalize();

        BigInt::from_bytes(&hash256[..SECURITY_PARAMETER / 8])
    }

    pub fn verify(
        &self,
        group: &CLGroup,
        public_key: &PK,
        ciphertext: &Ciphertext,
        X: &Secp256k1Point,
    ) -> Result<(), ProofError> {
        let mut flag = true;

        // reconstruct k
        let k = Self::challenge(public_key, &self.t_triple, ciphertext, X);

        let sample_size = &group.stilde
            * (BigInt::from(2).pow(40))
            * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
            * (BigInt::from(2).pow(40) + BigInt::one());

        //length test u1:
        if self.u1u2.u1 > sample_size || self.u1u2.u1 < BigInt::zero() {
            flag = false;
        }
        // length test u2:
        if &self.u1u2.u2 > &Secp256k1Scalar::group_order().mul(&group.q) || self.u1u2.u2 < BigInt::zero() {
            flag = false;
        }

        let c1k = ciphertext.c1.exp(&k);
        let t1c1k = self.t_triple.t1.compose(&c1k).reduce();
        let gqu1 = group.gq.exp(&self.u1u2.u1);
        if t1c1k != gqu1 {
            flag = false;
        };

        let k_bias_fe: Secp256k1Scalar = Secp256k1Scalar::from_bigint(&(&k + BigInt::one()));
        let g = Secp256k1Point::generator();
        let t2kq = (&self.t_triple.T.as_raw().add_point(&X.scalar_mul(&k_bias_fe))).sub_point(&X);
        let u2p = g.scalar_mul(&Secp256k1Scalar::from_bigint(&self.u1u2.u2));
        if t2kq != u2p {
            flag = false;
        }

        let pku1 = public_key.0.exp(&self.u1u2.u1);
        let fu2 = BinaryQF::expo_f(
            &group.q,
            &group.delta_q,
            &self.u1u2.u2.mod_floor(&Secp256k1Scalar::group_order().mul(&group.q)),
        );
        let c2k = ciphertext.c2.exp(&k);
        let t2c2k = self.t_triple.t2.compose(&c2k).reduce();
        let pku1fu2 = pku1.compose(&fu2).reduce();
        if t2c2k != pku1fu2 {
            flag = false;
        }
        match flag {
            true => Ok(()),
            false => Err(ProofError),
        }
    }
}

// implement algorithm 6: zkPoKEncProof', used in 2-party ecdsa
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLDLNewProof {
    S1: BinaryQF,
    S2: BinaryQF,
    S_hat: Point<Secp256k1>,
    D1: BinaryQF,
    D2: BinaryQF,
    u_m: BigInt,
    e_rho: BigInt,
    Q1: BinaryQF,
    Q2: BinaryQF,
    r_rho: BigInt,
    // c: BigInt,
}

impl CLDLNewProof{
    pub fn prove(
        clgroup: &CLGroup, 
        clpk: &PK,
        m: &BigInt, 
        rho: &BigInt, 
        sample_bound: &BigInt,
    ) -> Self {

        let B = sample_bound;
        let minus_B = sample_bound.clone().neg();

        // let rho = BigInt::sample_below(&(&clpk.stilde * BigInt::from(2).pow(40))); //according to line 140, the same sampling with sk
        let s_rho = BigInt::sample_range(&minus_B, &B);

        //sample s_m, to check
        let s_m = BigInt::sample_below(&clgroup.q.mul(Secp256k1Scalar::group_order())); //according to line 519
        let s_m_fe = Secp256k1Scalar::from_bigint(&s_m);

        // calculate commit
        let fsm = BinaryQF::expo_f(&clgroup.q, &clgroup.delta_q, &s_m.mod_floor(&clgroup.q)); //f^s_m
        // let c2sk = C2.exp(&s_k);  // C2^s_k
        // let S1 = fsm.compose(&c2sk).reduce();
        let pksrho = clpk.0.exp(&s_rho); // pk^s_rho
        let S1 = fsm.compose(&pksrho);
        let S2 = clgroup.gq.exp(&s_rho); // seems no need to reduce for exp
        let S_hat = Secp256k1Point::generator_mul(&s_m_fe); //S_hat = P_hat^s_m

        //use fiat shamir transform to calculate challenge c
        let fs1 = sha2::Sha256::digest(&[
            &S1.to_bytes()[..],
            &S2.to_bytes()[..],
            &S_hat.serialize_compressed()[..],
        ].concat()).to_vec();
        let c = BigInt::from_bytes(&fs1).mod_floor(&clgroup.q);

        let u_rho = s_rho + &c * rho;
        // let u_k = BigInt::mod_add(&s_k, &(&c * &clsk), &FE::q());
        // let s_m = sm_fe.to_big_int(); //according to line 519
        let u_m = BigInt::mod_add(&s_m, &(&c * m), &clgroup.q.mul(Secp256k1Scalar::group_order())); // seems FE::q() is the order, how to make sure = q?

        let (d_rho, e_rho) = u_rho.div_mod_floor(&clgroup.q);

        // let D1 = C2.exp(&d_k);
        let D1 = clpk.0.exp(&d_rho); // D1 = pk^d_rho
        let D2 = clgroup.gq.exp(&d_rho);

        //use fiat shamir transform to calculate l
        let fs2 = sha2::Sha256::digest(&[
            &D1.to_bytes()[..],
            &D2.to_bytes()[..],
            &u_m.to_bytes(),
            &e_rho.to_bytes(),
        ].concat());

        // reconstruct prime l <- Primes(87), 
        // For our case, we need to ensure that we have 2^80 primes 
        // in the challenge set. In order to generate enough prime, 
        // we need to find X such that "80 = X - log_2 X”. 
        // Then X is the number of bits outputted by the Primes() function.
        // X \in (86, 87), so we adopt 87

        let ell_bits = 87; 
        let two_pow_ellbits = BigInt::from(2).pow(ell_bits);
        let r = BigInt::from_bytes(&fs2).mod_floor(&two_pow_ellbits);
        let l = next_probable_small_prime(&r);
        // println!("verifier side's SHA256 mod 2^87: {}",r);
        // println!("verifier side's prime l: {}",l);

        let (q_rho, r_rho) = u_rho.div_mod_floor(&l);

        // let Q1 = C2.exp(&q_k);
        let Q1 = clpk.0.exp(&q_rho); // Q1 = pk^q_rho
        let Q2 = clgroup.gq.exp(&q_rho);

        CLDLNewProof {
            S1,
            S2,
            S_hat: Point::<Secp256k1>::from_raw(S_hat).unwrap(),
            D1,
            D2,
            u_m,
            e_rho,
            Q1,
            Q2,
            r_rho,
            // c,
        }
    }

    pub fn verify(
        &self,
        clgroup: &CLGroup,
        clpk: &PK,
        ciphertext: &Ciphertext,
        binding_point: &Secp256k1Point, 
    ) -> Result<(), ProofError>{
        // println!("zkpokenc_cl_dl_lcm executed");
        let mut flag = true;
        // if HSMCL::setup_verify(&self.pk, &self.seed).is_err() {
        //     flag = false;
        // }

        // use fiat shamir transform to calculate challenge c
        let fs1 = sha2::Sha256::digest(&[
            &self.S1.to_bytes()[..],
            &self.S2.to_bytes()[..],
            &self.S_hat.as_raw().serialize_compressed()[..],
        ].concat()).to_vec();
        let c = BigInt::from_bytes(&fs1).mod_floor(&clgroup.q);
        // let c = self.c;

        // VERIFY STEP 4
        // range check for u_m, e_rhp, e_k
        if &self.u_m > &Secp256k1Scalar::group_order().mul(&clgroup.q)
            || &self.u_m < &BigInt::zero() 
            || &self.e_rho > &clgroup.q
            || &self.e_rho < &BigInt::zero()
        {
            flag = false;
        }

        // first condition
        let um_fe = Secp256k1Scalar::from_bigint(&self.u_m);
        let phatum = Secp256k1Point::generator().scalar_mul(&um_fe); //P_hat^u_m, GE::generator() is P_hat
        let c_fe = Secp256k1Scalar::from_bigint(&c);
        let shatchatc = self.S_hat.as_raw().add_point(&binding_point.scalar_mul(&c_fe));
        if shatchatc != phatum {
            flag = false;
        }
        if !flag {
            dbg!("cldl verification failed - condition 1");
            return Err(ProofError{});
        }

        // // second condition, C2 version
        // let fum = BinaryQF::expo_f(&clgroup.q, &self.pk.delta_q, &self.u_m);
        // let c2ek = self.C2.exp(&self.e_k);
        // let c2ekfum = fum.compose(&c2ek).reduce();
        // let d1q = self.D1.exp(&clgroup.q);
        // let d1qc2ekfum = c2ekfum.compose(&d1q).reduce();
        // let c1c = self.C1.exp(&c);
        // let s1c1c = c1c.compose(&self.S1).reduce();
        // if d1qc2ekfum != s1c1c {
        //     flag = false;
        // }
        // assert!(flag == true, "verification failed");

        // second condition: C2^ek -> pk^erho
        let fum = BinaryQF::expo_f(&clgroup.q, &clgroup.delta_q, &self.u_m.mod_floor(&clgroup.q));
        let pkerho = clpk.0.exp(&self.e_rho);
        let pkerhofum = fum.compose(&pkerho);
        let d1q = self.D1.exp(&clgroup.q);
        let d1qpkerhofum = pkerhofum.compose(&d1q);
        let c1c = ciphertext.c2.exp(&c);
        let s1c1c = c1c.compose(&self.S1);
        if d1qpkerhofum != s1c1c {
            flag = false;
        }
        if !flag {
            dbg!("cldl verification failed - condition 2");
            return Err(ProofError{});
        }

        // third condition
        let gqerho = clgroup.gq.exp(&self.e_rho);
        let d2q = self.D2.exp(&clgroup.q);
        let d2qgqerho = d2q.compose(&gqerho).reduce();
        let c2c = ciphertext.c1.exp(&c);
        let s2c2c = c2c.compose(&self.S2).reduce();
        if d2qgqerho != s2c2c {
            flag = false;
        }
        if !flag {
            dbg!("cldl verification failed - condition 3");
            return Err(ProofError{});
        }

        //use fiat shamir transform

        let fs2 = sha2::Sha256::digest(&[
            &self.D1.to_bytes()[..],
            &self.D2.to_bytes()[..],
            &self.u_m.to_bytes(),
            &self.e_rho.to_bytes(),
        ].concat());
        // reconstruct prime l <- Primes(87), 
        // For our case, we need to ensure that we have 2^80 primes 
        // in the challenge set. In order to generate enough prime, 
        // we need to find X such that "80 = X - log_2 X”. 
        // Then X is the number of bits outputted by the Primes() function.
        // X \in (86, 87), so we adopt 87

        let ell_bits = 87;
        let two_pow_ellbits = BigInt::pow(&BigInt::from(2),ell_bits);
        let r = BigInt::from_bytes(&fs2).mod_floor(&two_pow_ellbits);
        let l = next_probable_small_prime(&r);
        // println!("verifier side's SHA256 mod 2^87: {}",r);
        // println!("verifier side's prime l: {}",l);

        //VERIFY STEP 6
        // check whether r_rho, r_k is in [0, l-1]
        if self.r_rho < BigInt::zero() 
            || self.r_rho > l 
        {
            flag = false;
        }
        if !flag {
            dbg!("cldl verification failed - condition 4");
            return Err(ProofError{});
        }

        // // first condition: c2 version
        // let c2rk = self.C2.exp(&self.r_k);
        // let c2rkfum = fum.compose(&c2rk).reduce();
        // let q1l = self.Q1.exp(&l);
        // let q1lc2rkfum = c2rkfum.compose(&q1l).reduce();
        // if q1lc2rkfum != s1c1c {
        //     flag = false;
        // }
        // assert!(flag == true, "verification failed");

        // first condition: pk version
        let pkrrho = clpk.0.exp(&self.r_rho);
        let pkrrhofum = fum.compose(&pkrrho).reduce();
        let q1l = self.Q1.exp(&l);
        let q1lpkrrhofum = pkrrhofum.compose(&q1l).reduce();
        if q1lpkrrhofum != s1c1c {
            flag = false;
        }
        if !flag {
            dbg!("cldl verification failed - condition 5");
            return Err(ProofError{});
        }

        // second condition
        let gqrrho = clgroup.gq.exp(&self.r_rho);
        let q2l = self.Q2.exp(&l);
        let q2lgqrrho = q2l.compose(&gqrrho).reduce();
        if q2lgqrrho != s2c2c {
            flag = false;
        }
        if !flag {
            dbg!("cldl verification failed - condition 6");
            return Err(ProofError{});
        }

        Ok(())
    }
}

pub fn decrypt(group: &CLGroup, secret_key: &SK, c: &Ciphertext) -> BigInt {
    let c1_x = c.c1.exp(&secret_key.0);
    let c1_x_inv = c1_x.inverse();
    let tmp = c.c2.compose(&c1_x_inv).reduce();
    let plaintext =
        BinaryQF::discrete_log_f(&group.q, &group.delta_q, &tmp);
    debug_assert!(&plaintext < &group.q);
    plaintext
}

/// Multiplies the encrypted value by `val`.
pub fn eval_scal(c: &Ciphertext, val: &BigInt) -> Ciphertext {
    Ciphertext {
        c1: c.c1.exp(val),
        c2: c.c2.exp(val),
    }
}

/// Homomorphically adds two ciphertexts so that the resulting ciphertext is the sum of the two input ciphertexts
pub fn eval_sum(c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    Ciphertext {
        c1: c1.c1.compose(&c2.c1).reduce(),
        c2: c1.c2.compose(&c2.c2).reduce(),
    }
}

#[cfg(test)]
mod test {
    use std::time::SystemTime;

    use super::*;

    const seed: &str =  "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848";

    fn sample_q() -> BigInt{
        sample_prime_by_length(800)
    }

    #[test]
    fn encrypt_and_decrypt() {
        
        let group = CLGroup::new_from_setup(&3845, &BigInt::from_str_radix(seed, 10).unwrap(), &sample_q());
        let (secret_key, public_key) = group.keygen();
        let message = Secp256k1Scalar::random();
        let (ciphertext, _) = encrypt(&group, &public_key, &message.to_bigint());
        let plaintext = decrypt(&group, &secret_key, &ciphertext);
        assert_eq!(plaintext, message.to_bigint());
    }

    #[test]
    fn compute_discrete_log_in_DLEasy_subgroup() {
        let group = CLGroup::new_from_setup(&3845, &BigInt::from_str_radix(seed, 10).unwrap(), &sample_q());
        let m = BigInt::from(10000);
        let exp_f = BinaryQF::expo_f(&group.q, &group.delta_q, &m);
        let m_tag =
            BinaryQF::discrete_log_f(&group.q, &group.delta_q, &exp_f);
        assert_eq!(m, m_tag);
    }

    #[test]
    fn verifiably_encrypt_verify_and_decrypt() {
        let group = CLGroup::new_from_setup(&3845, &BigInt::from_str_radix(seed, 10).unwrap(), &sample_q());
        let (secret_key, public_key) = group.keygen();
        let dl_keypair = {
            let sk = Secp256k1Scalar::random();
            let pk = Secp256k1Point::generator().scalar_mul(&sk);
            (sk, pk)
        };
        let (ciphertext, proof) =
            verifiably_encrypt(&group, &public_key, (&dl_keypair.0, &dl_keypair.1));

        let wrong_dl_pk = &dl_keypair.1.add_point(&Secp256k1Point::generator());

        assert!(
            proof
                .verify(&group, &public_key, &ciphertext, &dl_keypair.1)
                .is_ok(),
            "proof is valid against valid DL key"
        );

        assert!(
            proof
                .verify(&group, &public_key, &ciphertext, &wrong_dl_pk)
                .is_err(),
            "proof is invalid against invalid DL key"
        );

        assert_eq!(
            decrypt(&group, &secret_key, &ciphertext),
            dl_keypair.0.to_bigint(),
            "plaintext matches what was encrypted"
        );
    }

    #[test]
    fn multiply_ciphertext_by_scalar() {
        let group = CLGroup::new_from_setup(&3845, &BigInt::from_str_radix(seed, 10).unwrap(), &sample_q());
        let (secret_key, public_key) = group.keygen();
        let scalar = Secp256k1Scalar::random();

        let (ciphertext, _) = encrypt(&group, &public_key, &scalar.to_bigint());

        let multiply_by = Secp256k1Scalar::random();
        let mutated_ciphertext = eval_scal(&ciphertext, &multiply_by.to_bigint());
        let plaintext = decrypt(&group, &secret_key, &mutated_ciphertext);
        let expected = scalar.mul(&multiply_by);

        assert_eq!(plaintext.modulus(Secp256k1Scalar::group_order()), expected.to_bigint(), "plaintext was multiplied");
    }

    #[test]
    fn add_ciphertexts() {
        let group = CLGroup::new_from_setup(&3845, &BigInt::from_str_radix(seed, 10).unwrap(), &sample_q());
        let (secret_key, public_key) = group.keygen();
        let scalar1 = Secp256k1Scalar::random();
        let scalar2 = Secp256k1Scalar::random();

        let (ciphertext1, _) = encrypt(&group, &public_key, &scalar1.to_bigint());
        let (ciphertext2, _) = encrypt(&group, &public_key, &scalar2.to_bigint());

        let combined = eval_sum(&ciphertext1, &ciphertext2);
        let plaintext = decrypt(&group, &secret_key, &combined);
        let expected = scalar1.add(&scalar2);

        assert_eq!(plaintext.modulus(Secp256k1Scalar::group_order()), expected.to_bigint(), "ciphertexts were added");
    }

    #[test]
    fn cl_dl_test_setup() {
        let parsed_seed = BigInt::from_str_radix(seed, 10).unwrap();
        let group = CLGroup::new_from_setup(&3845, &parsed_seed, &sample_q());
        assert!(group.setup_verify(&parsed_seed).is_ok());
    }

    #[test]
    fn cl_dl_test_new_version() {
        let group = CLGroup::new_from_setup(&3845, &BigInt::from_str_radix(seed, 10).unwrap(), &sample_q());
        let (_, public_key) = group.keygen();
        let m = Secp256k1Scalar::random();
        let (ciphertext, rho) = encrypt(&group, &public_key, &m.to_bigint());
        let sample_bound = BigInt::from(2).pow(100).mul(&group.stilde);
        let binding_point = &Secp256k1Point::generator_mul(&m);

        let timer = SystemTime::now();
        let proof = CLDLProof::prove(&group, (&m.to_bigint(), &rho), (&public_key, &ciphertext, &binding_point));
        proof.verify(&group, &public_key, &ciphertext, &binding_point).unwrap();
        println!("old proof: {} ms", timer.elapsed().unwrap().as_millis());

        let timer = SystemTime::now();
        let proof = CLDLNewProof::prove(&group, &public_key, &m.to_bigint(), &rho.0, &sample_bound);
        proof.verify(&group, &public_key, &ciphertext, &binding_point).unwrap();
        println!("new proof: {} ms", timer.elapsed().unwrap().as_millis());
    }
}
