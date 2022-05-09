// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Naor-Pinkas oblivious transfer protocol (cf.
//! <https://dl.acm.org/citation.cfm?id=365502>).
//!
//! This implementation uses the Ristretto prime order elliptic curve group from
//! the `curve25519-dalek` library.

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
};
use curv::elliptic::curves::{secp256_k1::{Secp256k1Point, Secp256k1Scalar}, ECPoint, ECScalar};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest};

/// Oblivious transfer sender.
pub struct Sender {}
/// Oblivious transfer receiver.
pub struct Receiver {}

impl OtSender for Sender {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        _: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let mut ds = Vec::with_capacity(m);
        let mut hs = Vec::with_capacity(m);
        for _ in 0..m {
            let d = Secp256k1Point::generator_mul(&Secp256k1Scalar::random());
            channel.write_pt(&d)?;
            ds.push(d);
        }
        channel.flush()?;
        for d in ds.into_iter() {
            let h0 = channel.read_pt()?;
            hs.push((h0, d.sub_point(&h0)));
        }
        for (i, (input, h)) in inputs.iter().zip(hs.into_iter()).enumerate() {
            /*
                Use m0 and m1 to mask input
                Receiver will get m_b
                Send Hash_i(m_i) ^ input_i
             */
            let r = Secp256k1Scalar::random();
            let m0 = Secp256k1Point::generator_mul(&Secp256k1Scalar::random());
            let m1 = Secp256k1Point::generator_mul(&Secp256k1Scalar::random());
            channel.write_pt(&h.0.scalar_mul(&r).add_point(&m0))?;
            channel.write_pt(&h.1.scalar_mul(&r).add_point(&m1))?;
            channel.write_pt(&Secp256k1Point::generator_mul(&r))?;
            channel.write_block(&(Block::hash_pt(i as u128, &(&m0)) ^ input.0))?;
            channel.write_block(&(Block::hash_pt(i as u128, &(&m1)) ^ input.1))?;
        }
        channel.flush()?;
        Ok(())
    }
}

impl std::fmt::Display for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Naor-Pinkas Sender")
    }
}

impl OtReceiver for Receiver {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        _: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let m = inputs.len();
        let mut ds = Vec::with_capacity(m);
        let mut alphas = Vec::with_capacity(m);
        for _ in 0..m {
            let d = channel.read_pt()?;
            ds.push(d);
        }
        for (b, d) in inputs.iter().zip(ds.into_iter()) {
            let alpha = Secp256k1Scalar::random();
            let h0 = Secp256k1Point::generator_mul(&alpha);
            let h1 = d.sub_point(&h0);
            match b {
                false => channel.write_pt(&h0)?,
                true => channel.write_pt(&h1)?,
            };
            alphas.push(alpha);
        }
        channel.flush()?;
        inputs
            .iter()
            .zip(alphas.into_iter())
            .enumerate()
            .map(|(i, (b, alpha))| {
                let c0 = channel.read_pt()?;
                let c1 = channel.read_pt()?;
                let c2 = channel.read_pt()?;
                let masked_input0 = channel.read_block()?;
                let masked_input1 = channel.read_block()?;
                match b{
                    false => {
                        let m0 = c2.scalar_mul(&alpha.neg()).add_point(&c0);
                        Ok(masked_input0 ^ Block::hash_pt(i as u128, &(&m0)))
                    },
                    true => {
                        let m1 = c2.scalar_mul(&alpha.neg()).add_point(&c1);
                        Ok(masked_input1 ^ Block::hash_pt(i as u128, &(&m1)))
                    }
                }
            })
            .collect()
    }
}

impl std::fmt::Display for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Naor-Pinkas Receiver")
    }
}

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}
