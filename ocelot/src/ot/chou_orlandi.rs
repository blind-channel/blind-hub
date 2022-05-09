// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Chou-Orlandi oblivious transfer protocol (cf.
//! <https://eprint.iacr.org/2015/267>).
//!
//! This implementation uses the Ristretto prime order elliptic curve group from
//! the `curve25519-dalek` library and works over blocks rather than arbitrary
//! length messages.
//!
//! This version fixes a bug in the current ePrint write-up
//! (<https://eprint.iacr.org/2015/267/20180529:135402>, Page 4): if the value
//! `x^i` produced by the receiver is not randomized, all the random-OTs
//! produced by the protocol will be the same. We fix this by hashing in `i`
//! during the key derivation phase.

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
};
use curv::elliptic::curves::{secp256_k1::{Secp256k1Scalar, Secp256k1Point}, ECPoint, ECScalar};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, Malicious, SemiHonest};

/// Oblivious transfer sender.
pub struct Sender {
    y: Secp256k1Scalar,
    s: Secp256k1Point,
    counter: u128,
}

impl OtSender for Sender {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        let y = Secp256k1Scalar::random();
        let s = Secp256k1Point::generator_mul(&y);
        channel.write_pt(&s)?;
        channel.flush()?;
        Ok(Self { y, s, counter: 0 })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        let ys = self.s.scalar_mul(&self.y);
        let ks = (0..inputs.len())
            .map(|i| {
                let r = channel.read_pt()?;
                let yr = r.scalar_mul(&self.y);
                let k0 = Block::hash_pt(self.counter + i as u128, &yr);
                let k1 = Block::hash_pt(self.counter + i as u128, &(yr.sub_point(&ys)));
                Ok((k0, k1))
            })
            .collect::<Result<Vec<(Block, Block)>, Error>>()?;
        self.counter += inputs.len() as u128;
        for (input, k) in inputs.iter().zip(ks.into_iter()) {
            let c0 = k.0 ^ input.0;
            let c1 = k.1 ^ input.1;
            channel.write_block(&c0)?;
            channel.write_block(&c1)?;
        }
        channel.flush()?;
        Ok(())
    }
}

impl std::fmt::Display for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Chou-Orlandi Sender")
    }
}

/// Oblivious transfer receiver.
pub struct Receiver {
    counter: u128,
    s: Secp256k1Point
}

impl OtReceiver for Receiver {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        let s = channel.read_pt()?;
        Ok(Self { counter: 0, s })
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let zero = &Secp256k1Point::zero();
        let one = &self.s;
        let ks = inputs
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let x = Secp256k1Scalar::random();
                let c = if *b { one } else { zero };
                let r = Secp256k1Point::generator_mul(&x).add_point(&c);
                channel.write_pt(&r)?;
                Ok(Block::hash_pt(self.counter + i as u128, &(&self.s.scalar_mul(&x))))
            })
            .collect::<Result<Vec<Block>, Error>>()?;
        channel.flush()?;
        self.counter += inputs.len() as u128;
        inputs
            .iter()
            .zip(ks.into_iter())
            .map(|(b, k)| {
                let c0 = channel.read_block()?;
                let c1 = channel.read_block()?;
                let c = k ^ if *b { c1 } else { c0 };
                Ok(c)
            })
            .collect()
    }
}

impl std::fmt::Display for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Chou-Orlandi Receiver")
    }
}

impl SemiHonest for Sender {}
impl Malicious for Sender {}
impl SemiHonest for Receiver {}
impl Malicious for Receiver {}
