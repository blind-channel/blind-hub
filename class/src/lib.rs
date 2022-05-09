#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::many_single_char_names)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

static BIGINT_TWO: Lazy<BigInt> = Lazy::new(|| BigInt::from(2));

extern crate libc;
#[macro_use]
extern crate serde_derive;
extern crate curv;
extern crate hmac;
extern crate serde;
extern crate serde_json;
extern crate sha2;

use std::ffi::CStr;
use std::mem::swap;
use std::ops::{Neg, ShrAssign};
use std::str;

use gmp::ffi::{__gmpz_fdiv_q};
use gmp::mpz::{Mpz, __gmpz_gcdext, __gmpz_mul, __gmpz_tdiv_r, __gmpz_sub, __gmpz_add, __gmpz_gcd, __gmpz_neg, __gmpz_set, __gmpz_swap, __gmpz_cmp_ui};
use libc::c_char;

use curv::arithmetic::traits::*;
use curv::BigInt;
use once_cell::sync::Lazy;

mod chinese_reminder_theorem;
pub mod primitives;

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct BinaryQF {
    pub a: BigInt,
    pub b: BigInt,
    pub c: BigInt,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ABDeltaTriple {
    pub a: BigInt,
    pub b: BigInt,
    pub delta: BigInt,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BinaryQFCompressed {
    pub a1: BigInt,
    pub t1: BigInt,
    pub g: BigInt,
    pub b0: BigInt,
    pub e: bool,
    pub delta: BigInt,
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CongruenceContext {
    pub g: Mpz,
    pub d: Mpz,
    pub q: Mpz,
    pub r: Mpz,
}

// #[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
// struct NoCongruence;

impl Default for CongruenceContext {
    fn default() -> Self {
        Self {
            g: Mpz::new(),
            d: Mpz::new(),
            q: Mpz::new(),
            r: Mpz::new(),
        }
    }
}

impl CongruenceContext {
    /// Solves `a*x = b (mod m)`, storing `x` in `mu`
    ///
    /// This function may clobber any or all of `self`’s member variables.
    ///
    /// # Panics
    ///
    /// Panics if the congruence could not be solved.
    pub fn solve_linear_congruence(
        &mut self,
        mu: &mut Mpz,
        v: Option<&mut Mpz>,
        a: &Mpz,
        b: &Mpz,
        m: &Mpz,
    ) {
        unsafe{ 
            __gmpz_gcdext(self.g.inner_mut(),
                self.d.inner_mut(),
                mu.inner_mut(),
                a.inner(),
                m.inner()
            );
        }
        // if cfg!(test) {
        //     println!(
        //         "g = {}, d = {}, e = {}, a = {}, m = {}",
        //         self.g, self.d, mu, a, m
        //     );
        // }
        unsafe{ __gmpz_fdiv_q(self.q.inner_mut(), b.inner(), self.g.inner()); }
        unsafe{ __gmpz_mul(self.r.inner_mut(), self.q.inner(), self.d.inner()); }
        unsafe{ __gmpz_tdiv_r(mu.inner_mut(), self.r.inner(), m.inner()); }
        if let Some(v) = v {
            unsafe{ __gmpz_fdiv_q(v.inner_mut(), m.inner(), self.g.inner()); }
        }
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Hash, Debug)]
pub struct Ctx {
    negative_a: Mpz,
    r: Mpz,
    denom: Mpz,
    old_a: Mpz,
    old_b: Mpz,
    ra: Mpz,
    s: Mpz,
    x: Mpz,
    congruence_context: CongruenceContext,
    h: Mpz,
    w: Mpz,
    m: Mpz,
    u: Mpz,
    a: Mpz,
    l: Mpz,
    j: Mpz,
    b: Mpz,
    k: Mpz,
    t: Mpz,
    mu: Mpz,
    v: Mpz,
    sigma: Mpz,
    lambda: Mpz,
}

impl Default for Ctx {
    fn default() -> Self {
        Self {
            negative_a: Mpz::new(),
            r: Mpz::new(),
            denom: Mpz::new(),
            old_a: Mpz::new(),
            old_b: Mpz::new(),
            ra: Mpz::new(),
            s: Mpz::new(),
            x: Mpz::new(),
            congruence_context: Default::default(),
            w: Mpz::new(),
            m: Mpz::new(),
            u: Mpz::new(),
            l: Mpz::new(),
            j: Mpz::new(),
            t: Mpz::new(),
            a: Mpz::new(),
            b: Mpz::new(),
            k: Mpz::new(),
            h: Mpz::new(),
            mu: Mpz::new(),
            v: Mpz::new(),
            sigma: Mpz::new(),
            lambda: Mpz::new(),
        }
    }
}

impl BinaryQF {
    fn inner_compose(&mut self, rhs: &Self, ctx: &mut Ctx) {
        // g = (b1 + b2) / 2
        unsafe{ __gmpz_add(ctx.congruence_context.g.inner_mut(), self.b.gmp.inner(), rhs.b.gmp.inner()); }
        unsafe{ __gmpz_fdiv_q(ctx.congruence_context.g.inner_mut(), ctx.congruence_context.g.inner(), BIGINT_TWO.gmp.inner()); }

        // h = (b2 - b1) / 2
        unsafe{ __gmpz_sub(ctx.h.inner_mut(), rhs.b.gmp.inner(), self.b.gmp.inner()); }
        unsafe{ __gmpz_fdiv_q(ctx.h.inner_mut(), ctx.h.inner(), BIGINT_TWO.gmp.inner()); }

        // w = gcd(a1, a2, g)
        unsafe {
            __gmpz_gcd(ctx.w.inner_mut(), self.a.gmp.inner(), rhs.a.gmp.inner());
            __gmpz_gcd(ctx.w.inner_mut(), ctx.w.inner(), ctx.congruence_context.g.inner());
        }

        // j = w
        ctx.j.set(&ctx.w);

        // s = a1/w
        unsafe{ __gmpz_fdiv_q(ctx.s.inner_mut(), self.a.gmp.inner(), ctx.w.inner()); }

        // t = a2/w
        unsafe{ __gmpz_fdiv_q(ctx.t.inner_mut(), rhs.a.gmp.inner(), ctx.w.inner()); }

        // u = g/w
        unsafe{ __gmpz_fdiv_q(ctx.u.inner_mut(), ctx.congruence_context.g.inner(), ctx.w.inner()); }

        // a = t*u
        unsafe{ __gmpz_mul(ctx.a.inner_mut(), ctx.t.inner(), ctx.u.inner()); }

        // b = h*u - s*c1
        unsafe{ __gmpz_mul(ctx.b.inner_mut(), ctx.h.inner(), ctx.u.inner()); }
        unsafe{ __gmpz_mul(ctx.m.inner_mut(), ctx.s.inner(), self.c.gmp.inner()); }
        ctx.b += &ctx.m;

        // m = s*t
        unsafe{ __gmpz_mul(ctx.m.inner_mut(), ctx.s.inner(), ctx.t.inner()); }
        ctx.congruence_context.solve_linear_congruence(
            &mut ctx.mu,
            Some(&mut ctx.v),
            &ctx.a,
            &ctx.b,
            &ctx.m,
        );

        // a = t*v
        unsafe{ __gmpz_mul(ctx.a.inner_mut(), ctx.t.inner(), ctx.v.inner()); }

        // b = h - t * mu
        unsafe{ __gmpz_mul(ctx.m.inner_mut(), ctx.t.inner(), ctx.mu.inner()); }
        unsafe{ __gmpz_sub(ctx.b.inner_mut(), ctx.h.inner(), ctx.m.inner()); }

        // m = s
        ctx.m.set(&ctx.s);

        ctx.congruence_context.solve_linear_congruence(
            &mut ctx.lambda,
            Some(&mut ctx.sigma),
            &ctx.a,
            &ctx.b,
            &ctx.m,
        );

        // k = mu + v*lambda
        unsafe{ __gmpz_mul(ctx.a.inner_mut(), ctx.v.inner(), ctx.lambda.inner()); }
        unsafe{ __gmpz_add(ctx.k.inner_mut(), ctx.mu.inner(), ctx.a.inner()); }

        // l = (k*t - h)/s
        unsafe{ __gmpz_mul(ctx.l.inner_mut(), ctx.k.inner(), ctx.t.inner()); }
        unsafe{ __gmpz_sub(ctx.v.inner_mut(), ctx.l.inner(), ctx.h.inner()); }
        unsafe{ __gmpz_fdiv_q(ctx.l.inner_mut(), ctx.v.inner(), ctx.s.inner()); }

        // m = (t*u*k - h*u - c*s) / s*t
        unsafe{ __gmpz_mul(ctx.m.inner_mut(), ctx.t.inner(), ctx.u.inner()); }
        ctx.m *= &ctx.k;
        unsafe{ __gmpz_mul(ctx.a.inner_mut(), ctx.h.inner(), ctx.u.inner()); }
        ctx.m -= &ctx.a;
        unsafe{ __gmpz_mul(ctx.a.inner_mut(), self.c.gmp.inner(), ctx.s.inner()); }
        ctx.m -= &ctx.a;
        unsafe{ __gmpz_mul(ctx.a.inner_mut(), ctx.s.inner(), ctx.t.inner()); }
        unsafe{ __gmpz_fdiv_q(ctx.lambda.inner_mut(), ctx.m.inner(), ctx.a.inner()); }

        // A = s*t - r*u
        unsafe{ __gmpz_mul(self.a.gmp.inner_mut(), ctx.s.inner(), ctx.t.inner()); }

        // B = ju + mr - (kt + ls)
        unsafe{ __gmpz_mul(self.b.gmp.inner_mut(), ctx.j.inner(), ctx.u.inner()); }
        unsafe{ __gmpz_mul(ctx.a.inner_mut(), ctx.k.inner(), ctx.t.inner()); }
        unsafe{ __gmpz_sub(self.b.gmp.inner_mut(), self.b.gmp.inner(), ctx.a.inner()); }
        // self.b -= &ctx.a;
        unsafe{ __gmpz_mul(ctx.a.inner_mut(), ctx.l.inner(), ctx.s.inner()); }
        unsafe{ __gmpz_sub(self.b.gmp.inner_mut(), self.b.gmp.inner(), ctx.a.inner()); }
        // self.b -= &ctx.a;

        // C = kl - jm
        unsafe{ __gmpz_mul(self.c.gmp.inner_mut(), ctx.k.inner(), ctx.l.inner()); }
        unsafe{ __gmpz_mul(ctx.a.inner_mut(), ctx.j.inner(), ctx.lambda.inner()); }
        unsafe{ __gmpz_sub(self.c.gmp.inner_mut(), self.c.gmp.inner(), ctx.a.inner()); }
        // self.c -= &ctx.a;

        self.inner_reduce(ctx);
    }

    fn inner_normalize(&mut self, ctx: &mut Ctx) {
        unsafe{ __gmpz_neg(ctx.negative_a.inner_mut(), self.a.gmp.inner()); }
        // ctx.negative_a = -self.a.gmp.inner();
        let bigint_negative_a = BigInt{ gmp: ctx.negative_a.clone() };
        if self.b > bigint_negative_a && self.b <= self.a {
            return;
        }
        unsafe{ __gmpz_sub(ctx.r.inner_mut(), self.a.gmp.inner(), self.b.gmp.inner()); }
        unsafe{ __gmpz_mul(ctx.denom.inner_mut(), self.a.gmp.inner(), BIGINT_TWO.gmp.inner()); }
        unsafe{ __gmpz_fdiv_q(ctx.negative_a.inner_mut(), ctx.r.inner(), ctx.denom.inner()); }
        unsafe{ __gmpz_swap(ctx.negative_a.inner_mut(), ctx.r.inner_mut()); }
        unsafe{ __gmpz_swap(ctx.old_b.inner_mut(), self.b.gmp.inner_mut()); }
        // (ctx.negative_a, ctx.r) = (ctx.r, ctx.negative_a);
        // (ctx.old_b, self.b.gmp) = (self.b.gmp, ctx.old_b);
        // swap(ctx.negative_a.inner_mut(), ctx.r.inner_mut());
        // swap(ctx.old_b.inner_mut(), self.b.gmp.inner_mut());
        unsafe{ __gmpz_mul(ctx.ra.inner_mut(), ctx.r.inner(), self.a.gmp.inner()); }
        unsafe{ __gmpz_mul(ctx.negative_a.inner_mut(), ctx.ra.inner(), BIGINT_TWO.gmp.inner()); }
        unsafe{ __gmpz_add(self.b.gmp.inner_mut(), ctx.old_b.inner(), ctx.negative_a.inner()); }

        unsafe{ __gmpz_mul(ctx.negative_a.inner_mut(), ctx.ra.inner(), ctx.r.inner()); }
        unsafe{ __gmpz_add(ctx.old_a.inner_mut(), self.c.gmp.inner(), ctx.negative_a.inner()); }

        unsafe{ __gmpz_mul(ctx.ra.inner_mut(), ctx.r.inner(), ctx.old_b.inner()); }
        unsafe{ __gmpz_add(self.c.gmp.inner_mut(), ctx.old_a.inner(), ctx.ra.inner()); }
    }

    fn inner_reduce(&mut self, ctx: &mut Ctx) {
        self.inner_normalize(ctx);

        while if unsafe{ __gmpz_cmp_ui(self.b.gmp.inner(), 0) < 0} {
            self.a >= self.c
        } else {
            self.a > self.c
        } {
            debug_assert!(!self.c.is_zero());
            unsafe{ __gmpz_add(ctx.s.inner_mut(), self.c.gmp.inner(), self.b.gmp.inner()); }
            unsafe{ __gmpz_add(ctx.x.inner_mut(), self.c.gmp.inner(), self.c.gmp.inner()); }
            unsafe{ __gmpz_swap(self.b.gmp.inner_mut(), ctx.old_b.inner_mut()); }
            // (self.b.gmp, ctx.old_b) = (ctx.old_b, self.b.gmp);
            // swap(self.b.gmp.inner_mut(), ctx.old_b.inner_mut());
            unsafe{ __gmpz_fdiv_q(self.b.gmp.inner_mut(), ctx.s.inner(), ctx.x.inner()); }
            unsafe{ __gmpz_swap(self.b.gmp.inner_mut(), ctx.s.inner_mut()); }
            unsafe{ __gmpz_swap(self.a.gmp.inner_mut(), self.c.gmp.inner_mut()); }
            // (self.b.gmp, ctx.s) = (ctx.s, self.b.gmp);
            // (self.a.gmp, self.c.gmp) = (self.c.gmp, self.a.gmp);
            // swap(self.b.gmp.inner_mut(), ctx.s.inner_mut());
            // swap(self.a.gmp.inner_mut(), self.c.gmp.inner_mut());

            // x = 2sc
            unsafe{ __gmpz_mul(self.b.gmp.inner_mut(), ctx.s.inner(), self.a.gmp.inner()); }
            unsafe{ __gmpz_mul(ctx.x.inner_mut(), self.b.gmp.inner(), BIGINT_TWO.gmp.inner()); }

            // b = x - old_b
            unsafe{ __gmpz_sub(self.b.gmp.inner_mut(), ctx.x.inner(), ctx.old_b.inner()); }

            // x = b*s
            unsafe{ __gmpz_mul(ctx.x.inner_mut(), ctx.old_b.inner(), ctx.s.inner()); }

            // s = c*s^2
            unsafe{ __gmpz_mul(ctx.old_b.inner_mut(), ctx.s.inner(), ctx.s.inner()); }
            unsafe{ __gmpz_mul(ctx.s.inner_mut(), self.a.gmp.inner(), ctx.old_b.inner()); }

            // c = s - x
            unsafe{ __gmpz_sub(ctx.old_a.inner_mut(), ctx.s.inner(), ctx.x.inner()); }

            // c += a
            unsafe{ __gmpz_add(self.c.gmp.inner_mut(), self.c.gmp.inner(), ctx.old_a.inner()); }
            // self.c += ctx.old_a.inner();
        }
        self.inner_normalize(ctx);
    }

    fn inner_square_impl(&mut self, ctx: &mut Ctx) {
        ctx.congruence_context.solve_linear_congruence(
            &mut ctx.mu,
            None,
            &self.b.gmp,
            &self.c.gmp,
            &self.a.gmp,
        );
        unsafe{ __gmpz_mul(ctx.m.inner_mut(), self.b.gmp.inner(), ctx.mu.inner()); }
        unsafe{ __gmpz_sub(ctx.m.inner_mut(), ctx.m.inner(), self.c.gmp.inner()); }
        unsafe{ __gmpz_fdiv_q(ctx.m.inner_mut(), ctx.m.inner(), self.a.gmp.inner()); }
        // ctx.m -= &self.c;
        // ctx.m = ctx.m.div_floor(&self.a);

        // New a
        // ctx.old_a.set(&self.a);
        unsafe{ __gmpz_set(ctx.old_a.inner_mut(), self.a.gmp.inner()); }
        unsafe{ __gmpz_mul(self.a.gmp.inner_mut(), ctx.old_a.inner(), ctx.old_a.inner()); }

        // New b
        unsafe{ __gmpz_mul(ctx.a.inner_mut(), ctx.mu.inner(), ctx.old_a.inner()); }
        unsafe{ __gmpz_add(ctx.a.inner_mut(), ctx.a.inner(), ctx.a.inner()); }
        unsafe{ __gmpz_sub(self.b.gmp.inner_mut(), self.b.gmp.inner(), ctx.a.inner()); }
        // self.b -= &ctx.a;

        // New c
        unsafe{ __gmpz_mul(self.c.gmp.inner_mut(), ctx.mu.inner(), ctx.mu.inner()); }
        unsafe{ __gmpz_sub(self.c.gmp.inner_mut(), self.c.gmp.inner(), ctx.m.inner()); }
        // self.c -= &ctx.m;
        // dbg!(self.discriminant());
        self.inner_reduce(ctx);
    }

    // #[cfg_attr(not(debug_assertions), inline(always))]
    // fn inner_square(&mut self, ctx: &mut Ctx) {
    //     if cfg!(debug_assertions) {
    //         let orig_disc = self.discriminant();
    //         self.inner_reduce(ctx);
    //         let mut q = self.clone();
    //         q.inner_multiply(self, ctx);
    //         let comp_disc = q.discriminant();
    //         self.inner_square_impl(ctx);
    //         let squa_disc = self.discriminant();
    //         // debug_assert_eq!(comp_disc, squa_disc);
    //         dbg!(orig_disc);
    //         dbg!(comp_disc);
    //         dbg!(squa_disc);
    //         assert_eq!(*self, q);
    //     } else {
    //         self.inner_square_impl(ctx);
    //     }
    // }
}

// pub struct BinaryQFComposeContext {
//     g: Mpz,
//     h: Mpz,
//     w: Mpz,
//     j: Mpz,
//     s: Mpz,
//     t: Mpz,
//     u: Mpz,
//     tu: Mpz,
//     st: Mpz,
//     gcd_tu_st: Mpz,
//     co_tu: Mpz,
//     co_st: Mpz,
//     sc: Mpz,
//     husc: Mpz,
//     nu: Mpz,
//     mu: Mpz,
//     tnu: Mpz,
//     co_tnu: Mpz,
//     co_s: Mpz,
//     gcd_tnu_s: Mpz,
//     htmu: Mpz,
//     lambda: Mpz,
//     k: Mpz,
//     l: Mpz,
//     m: Mpz,
//     a: Mpz,
//     b: Mpz,
//     c: Mpz
// }

// impl BinaryQFComposeContext {
//     pub fn new() -> Self {
//         Self {
//             g: Mpz::new(),
//             h: Mpz::new(),
//             w: Mpz::new(),
//             j: Mpz::new(),
//             s: Mpz::new(),
//             t: Mpz::new(),
//             u: Mpz::new(),
//             st: Mpz::new(),
//             tu: Mpz::new(),
//             gcd_tu_st: Mpz::new(),
//             co_tu: Mpz::new(),
//             co_st: Mpz::new(),
//             sc: Mpz::new(),
//             husc: Mpz::new(),
//             nu: Mpz::new(),
//             mu: Mpz::new(),
//             tnu: Mpz::new(),
//             co_tnu: Mpz::new(),
//             co_s: Mpz::new(),
//             gcd_tnu_s: Mpz::new(),
//             htmu: Mpz::new(),
//             lambda: Mpz::new(),
//             k: Mpz::new(),
//             l: Mpz::new(),
//             m: Mpz::new(),
//             a: Mpz::new(),
//             b: Mpz::new(),
//             c: Mpz::new(),
//         }
//     }

//     pub fn compose_assign(&mut self, qf1: &mut BinaryQF, qf2: &BinaryQF) {
//         assert_eq!(qf1.discriminant(), qf2.discriminant());
//         unsafe {
//             __gmpz_add(
//                 self.g.inner_mut(),
//                 qf1.b.inner_ref().inner(),
//                 qf2.b.inner_ref().inner(),
//             );
//             __gmpz_fdiv_q(
//                 self.g.inner_mut(),
//                 self.g.inner(),
//                 BIGINT_TWO.inner_ref().inner()
//             );
//         }
//         unsafe {
//             __gmpz_sub(
//                 self.h.inner_mut(),
//                 qf2.b.inner_ref().inner(),
//                 qf1.b.inner_ref().inner(),
//             );
//             __gmpz_fdiv_q(
//                 self.h.inner_mut(),
//                 self.h.inner(),
//                 BIGINT_TWO.inner_ref().inner()
//             );
//         }
//         unsafe {
//             __gmpz_gcd(
//                 self.w.inner_mut(),
//                 qf1.a.inner_ref().inner(),
//                 qf2.a.inner_ref().inner()
//             );
//             __gmpz_gcd(
//                 self.w.inner_mut(),
//                 self.w.inner(),
//                 self.g.inner()
//             );
//         }
//         // let w = BigInt{ gmp: self.w.clone()};
//         // println!{
//         //     "a1 = {}\nb1 = {}\nc1 = {} \n",
//         //     self.a,
//         //     self.b,
//         //     self.c
//         // };
//         // println!{
//         //     "a2 = {}\nb2 = {}\nc2 = {} \n",
//         //     qf2.a,
//         //     qf2.b,
//         //     qf2.c
//         // };

//         unsafe {
//             __gmpz_set(
//                 self.j.inner_mut(),
//                 self.w.inner()
//             );
//         }
//         unsafe {
//             __gmpz_fdiv_q(
//                 self.s.inner_mut(),
//                 qf1.a.inner_ref().inner(),
//                 self.w.inner()
//             );
//         }
//         unsafe {
//             __gmpz_fdiv_q(
//                 self.t.inner_mut(),
//                 qf2.a.inner_ref().inner(),
//                 self.w.inner()
//             );
//         }
//         unsafe {
//             __gmpz_fdiv_q(
//                 self.u.inner_mut(),
//                 self.g.inner(),
//                 self.w.inner()
//             );
//         }

//         // let j = BigInt{ gmp: self.j.clone()};
//         // let s = BigInt{ gmp: self.s.clone()};
//         // let t = BigInt{ gmp: self.t.clone()};
//         // let u = BigInt{ gmp: self.u.clone()};

//         // println!(
//         //     "j = {}\ns = {}\nt = {}\nu = {}\n",
//         //     j,
//         //     s,
//         //     t,
//         //     u
//         // );

//         // let st = s.mul(&t);
//         unsafe {
//             __gmpz_mul(
//                 self.tu.inner_mut(),
//                 self.t.inner(),
//                 self.u.inner()
//             );
//             __gmpz_mul(
//                 self.st.inner_mut(),
//                 self.s.inner(),
//                 self.t.inner()
//             );
//             __gmpz_gcdext(
//                 self.gcd_tu_st.inner_mut(),
//                 self.co_tu.inner_mut(),
//                 self.co_st.inner_mut(),
//                 self.tu.inner(),
//                 self.st.inner()
//             );
//         }
//         // let (gcd_tu_st, co_tu, _) = BigInt::egcd(&t.mul(&u), &st);
//         // println!(
//         //     "gcd(tu,st) = {}\nco_tu = {}\n",
//         //     gcd_tu_st,
//         //     co_tu,
//         // );
//         // let u = BigInt{ gmp: self.u.clone()};

//         unsafe {
//             __gmpz_mul(
//                 self.husc.inner_mut(),
//                 self.h.inner(),
//                 self.u.inner()
//             );
//             __gmpz_mul(
//                 self.sc.inner_mut(),
//                 self.s.inner(),
//                 qf1.c.inner_ref().inner()
//             );
//             __gmpz_add(
//                 self.husc.inner_mut(),
//                 self.husc.inner(),
//                 self.sc.inner()
//             );
//         }

//         // if !husc.modulus(&gcd_tu_st).is_zero() {
//         //     panic!("congruence 1 has no solution")
//         // }
//         unsafe {
//             __gmpz_fdiv_q(
//                 self.nu.inner_mut(),
//                 self.st.inner(),
//                 self.gcd_tu_st.inner()
//             );
//             __gmpz_fdiv_q(
//                 self.mu.inner_mut(),
//                 self.husc.inner(),
//                 self.gcd_tu_st.inner()
//             );
//             __gmpz_mul(
//                 self.mu.inner_mut(),
//                 self.mu.inner(),
//                 self.co_tu.inner()
//             );
//             __gmpz_mod(
//                 self.mu.inner_mut(),
//                 self.mu.inner(),
//                 self.nu.inner()
//             );
//         }
//         // let nu = st.div_floor(&gcd_tu_st);
//         // let mu = co_tu.mul(&husc.div_floor(&gcd_tu_st)).mod_floor(&nu);
//         // println!(
//         //     "tu = {}\nst = {}\nhu+sc = {}\nk = {} + {} * n",
//         //     t.mul(&u),
//         //     st,
//         //     husc,
//         //     mu,
//         //     nu
//         // );

//         unsafe {
//             __gmpz_mul(
//                 self.tnu.inner_mut(),
//                 self.t.inner(),
//                 self.nu.inner()
//             );
//             __gmpz_gcdext(
//                 self.gcd_tnu_s.inner_mut(), 
//                 self.co_tnu.inner_mut(),
//                 self.co_s.inner_mut(),
//                 self.tnu.inner(),
//                 self.s.inner()
//             );
//         }
//         // let gcd_tnu_s = BigInt { gmp: self.gcd_tnu_s.clone() };
//         // let co_tnu = BigInt{ gmp:self.co_tnu.clone() };

//         // let (gcd_tnu_s, co_tnu, _) = BigInt::egcd(&t.mul(&nu), &s);
//         // println!(
//         //     "gcd(tnu, s) = {}\nco_tnu = {}\n",
//         //     gcd_tnu_s,
//         //     co_tnu
//         // );
//         // let htmu = h.sub(&t.mul(&mu));
//         // if !htmu.modulus(&gcd_tnu_s).is_zero() {
//         //     panic!("congruence 2 has no solution")
//         // }
//         unsafe {
//             __gmpz_mul(
//                 self.htmu.inner_mut(),
//                 self.t.inner(),
//                 self.mu.inner()
//             );
//             __gmpz_sub(
//                 self.htmu.inner_mut(),
//                 self.h.inner(),
//                 self.htmu.inner(),
//             );
//             __gmpz_fdiv_q(
//                 self.lambda.inner_mut(),
//                 self.htmu.inner(),
//                 self.gcd_tnu_s.inner()
//             );
//             __gmpz_mul(
//                 self.lambda.inner_mut(),
//                 self.lambda.inner(),
//                 self.co_tnu.inner()
//             );
//             __gmpz_mod(
//                 self.lambda.inner_mut(),
//                 self.lambda.inner(),
//                 self.s.inner()
//             );
//         }
//         // let htmu = BigInt{ gmp:self.htmu.clone() };

//         // println!(
//         //     "tnu = {}\ns = {}\nh - tnu = {}\nlambda = {}\n",
//         //     t.mul(&nu),
//         //     s,
//         //     htmu,
//         //     lambda,
//         // );

//         unsafe {
//             __gmpz_mul(
//                 self.k.inner_mut(),
//                 self.nu.inner(),
//                 self.lambda.inner()
//             );
//             __gmpz_add(
//                 self.k.inner_mut(),
//                 self.k.inner(),
//                 self.mu.inner()
//             );
//             __gmpz_mul(
//                 self.l.inner_mut(),
//                 self.k.inner(),
//                 self.t.inner()
//             );
//             __gmpz_sub(
//                 self.l.inner_mut(),
//                 self.l.inner(),
//                 self.h.inner()
//             );
//             __gmpz_fdiv_q(
//                 self.l.inner_mut(),
//                 self.l.inner(),
//                 self.s.inner()
//             );
//             __gmpz_mul(
//                 self.m.inner_mut(),
//                 self.tu.inner(),
//                 self.k.inner()
//             );
//             __gmpz_sub(
//                 self.m.inner_mut(),
//                 self.m.inner(),
//                 self.husc.inner()
//             );
//             __gmpz_fdiv_q(
//                 self.m.inner_mut(),
//                 self.m.inner(),
//                 self.st.inner()
//             );
//         }

//         unsafe {
//             __gmpz_mul(
//                 self.a.inner_mut(),
//                 self.s.inner(),
//                 self.t.inner()
//             );
//             __gmpz_mul(
//                 self.u.inner_mut(),
//                 self.u.inner(),
//                 self.j.inner()
//             );
//             __gmpz_mul(
//                 self.t.inner_mut(),
//                 self.t.inner(),
//                 self.k.inner()
//             );
//             __gmpz_mul(
//                 self.s.inner_mut(),
//                 self.s.inner(),
//                 self.l.inner()
//             );
//             __gmpz_sub(
//                 self.b.inner_mut(),
//                 self.u.inner(),
//                 self.t.inner()
//             );
//             __gmpz_sub(
//                 self.b.inner_mut(),
//                 self.b.inner(),
//                 self.s.inner()
//             );
//             __gmpz_mul(
//                 self.c.inner_mut(),
//                 self.k.inner(),
//                 self.l.inner()
//             );
//             __gmpz_mul(
//                 self.j.inner_mut(),
//                 self.j.inner(),
//                 self.m.inner()
//             );
//             __gmpz_sub(
//                 self.c.inner_mut(),
//                 self.c.inner(),
//                 self.j.inner()
//             );
//         }

//         // let k = mu.add(&nu.mul(&lambda));
//         // let l = k.mul(&t).sub(&h).div_floor(&s);
//         // let m = t.mul(&u).mul(&k).sub(&h.mul(&u)).sub(&qf1.c.mul(&s)).div_floor(&s.mul(&t));
//         // let k = BigInt{ gmp: self.k.clone() };
//         // let l = BigInt{ gmp: self.l.clone() };
//         // let m = BigInt{ gmp: self.m.clone() };
//         // let result = BinaryQF {
//         //     a: s.mul(&t),
//         //     b: j.mul(&u).sub(&k.mul(&t).add(&l.mul(&s))),
//         //     c: k.mul(&l).sub(&j.mul(&m))
//         // };
//         // result.reduce();
//         unsafe {
//             __gmpz_set(
//                 qf1.a.gmp.inner_mut(),
//                 self.a.inner()
//             );
//             __gmpz_set(
//                 qf1.b.gmp.inner_mut(),
//                 self.b.inner()
//             );
//             __gmpz_set(
//                 qf1.c.gmp.inner_mut(),
//                 self.c.inner()
//             );
//         }
//         qf1.reduce();
//     }

//     pub fn square_assign(&mut self, qf: &mut BinaryQF) {
//         unsafe {
//             __gmpz_gcdext(
//                 self.gcd_tu_st.inner_mut(),
//                 self.co_tu.inner_mut(),
//                 self.co_st.inner_mut(),
//                 qf.b.inner_ref().inner(),
//                 qf.a.inner_ref().inner()
//             );
//             __gmpz_fdiv_q(
//                 self.mu.inner_mut(),
//                 qf.c.inner_ref().inner(),
//                 self.gcd_tu_st.inner()
//             );
//             __gmpz_mul(
//                 self.mu.inner_mut(),
//                 self.mu.inner(),
//                 self.co_tu.inner()
//             );
//             __gmpz_mod(
//                 self.mu.inner_mut(),
//                 self.mu.inner(),
//                 qf.a.inner_ref().inner()
//             );
//             __gmpz_mul(
//                 self.a.inner_mut(),
//                 qf.a.inner_ref().inner(),
//                 qf.a.inner_ref().inner()
//             );
//             __gmpz_mul(
//                 self.b.inner_mut(),
//                 qf.a.inner_ref().inner(),
//                 self.mu.inner()
//             );
//             __gmpz_mul(
//                 self.b.inner_mut(),
//                 self.b.inner(),
//                 BIGINT_TWO.inner_ref().inner()
//             );
//             __gmpz_sub(
//                 self.b.inner_mut(),
//                 qf.b.inner_ref().inner(),
//                 self.b.inner()
//             );
//             __gmpz_mul(
//                 self.c.inner_mut(),
//                 qf.b.inner_ref().inner(),
//                 self.mu.inner()
//             );
//             __gmpz_sub(
//                 self.c.inner_mut(),
//                 self.c.inner(),
//                 qf.c.inner_ref().inner()
//             );
//             __gmpz_fdiv_q(
//                 self.c.inner_mut(),
//                 self.c.inner(),
//                 qf.a.inner_ref().inner()
//             );
//             __gmpz_mul(
//                 self.mu.inner_mut(),
//                 self.mu.inner(),
//                 self.mu.inner()
//             );
//             __gmpz_sub(
//                 self.c.inner_mut(),
//                 self.mu.inner(),
//                 self.c.inner()
//             );
//         }
//         unsafe {
//             __gmpz_set(
//                 qf.a.gmp.inner_mut(),
//                 self.a.inner()
//             );
//             __gmpz_set(
//                 qf.b.gmp.inner_mut(),
//                 self.b.inner()
//             );
//             __gmpz_set(
//                 qf.c.gmp.inner_mut(),
//                 self.c.inner()
//             );
//         }
//         qf.reduce();
//     }
// }

impl BinaryQF {
    pub fn binary_quadratic_form_disc(abdelta_triple: &ABDeltaTriple) -> Self {
        let a = abdelta_triple.a.clone();
        let b = abdelta_triple.b.clone();
        let delta = abdelta_triple.delta.clone();

        assert_eq!(delta.mod_floor(&BigInt::from(4)), BigInt::one());
        assert!(delta < BigInt::zero()); // in general delta can be positive but we don't deal with that case
        let c = (&b.pow(2) - &delta) / (BigInt::from(4) * &a);
        BinaryQF { a, b, c }
    }

    pub fn binary_quadratic_form_principal(delta: &BigInt) -> Self {
        let one = BigInt::one();
        assert_eq!(delta.mod_floor(&BigInt::from(4)), BigInt::one());
        assert!(delta < &BigInt::zero()); // in general delta can be positive but we don't deal with that case
        let a_b_delta = ABDeltaTriple {
            a: one.clone(),
            b: one,
            delta: delta.clone(),
        };
        BinaryQF::binary_quadratic_form_disc(&a_b_delta)
    }

    pub fn discriminant(&self) -> BigInt {
        // for negative delta we compute 4ac - b^2
        let abs_delta = BigInt::from(4) * &self.a * &self.c - &self.b * &self.b;
        assert!(abs_delta > BigInt::zero());
        -abs_delta
    }

    pub fn discriminant_sqrt(&self) -> BigInt {
        let disc = self.discriminant();
        disc.sqrt()
    }

    pub fn is_reduced(&self) -> bool {
        self.is_normal() && self.a <= self.c && !(self.a == self.c && self.b < BigInt::zero())
    }

    pub fn normalize(&self) -> Self {
        // assume delta<0 and a>0
        let a_sub_b: BigInt = &self.a - &self.b;
        let s_f = a_sub_b.div_floor(&(BigInt::from(2) * &self.a));

        BinaryQF {
            a: self.a.clone(),
            b: &self.b + BigInt::from(2) * &s_f * &self.a,
            c: &self.a * &s_f.pow(2) + &self.b * &s_f + &self.c,
        }
    }

    pub fn is_normal(&self) -> bool {
        self.b <= self.a && self.b > -(&self.a)
    }
    pub fn primeform(quad_disc: &BigInt, q: &BigInt) -> Self {
        let quad_disc_gen = bn_to_gen(quad_disc);

        let q_gen = bn_to_gen(q);

        let pf = unsafe { primeform(quad_disc_gen, q_gen, 3i64) };

        let bqf = BinaryQF::pari_qf_to_qf(pf);

        bqf.normalize()
    }

    pub fn compose(&self, qf2: &BinaryQF) -> Self {
        assert_eq!(self.discriminant(), qf2.discriminant());
        let g = (&self.b + &qf2.b).div_floor(&BIGINT_TWO);
        let h = (&self.b - &qf2.b).div_floor(&BIGINT_TWO).neg();
        let w = BigInt::gcd(&BigInt::gcd(&self.a, &qf2.a), &g);
        // println!{
        //     "a1 = {}\nb1 = {}\nc1 = {} \n",
        //     self.a,
        //     self.b,
        //     self.c
        // };
        // println!{
        //     "a2 = {}\nb2 = {}\nc2 = {} \n",
        //     qf2.a,
        //     qf2.b,
        //     qf2.c
        // };

        let j = w.clone();
        let s = self.a.div_floor(&w);
        let t = qf2.a.div_floor(&w);
        let u = g.div_floor(&w);

        // println!(
        //     "j = {}\ns = {}\nt = {}\nu = {}\n",
        //     j,
        //     s,
        //     t,
        //     u
        // );

        let st = s.mul(&t);
        let (gcd_tu_st, co_tu, _) = BigInt::egcd(&t.mul(&u), &st);
        // println!(
        //     "gcd(tu,st) = {}\nco_tu = {}\n",
        //     gcd_tu_st,
        //     co_tu,
        // );

        let husc = h.mul(&u).add(&s.mul(&self.c));
        if !husc.modulus(&gcd_tu_st).is_zero() {
            panic!("congruence 1 has no solution")
        }
        let nu = st.div_floor(&gcd_tu_st);
        let mu = co_tu.mul(&husc.div_floor(&gcd_tu_st)).mod_floor(&nu);
        // println!(
        //     "tu = {}\nst = {}\nhu+sc = {}\nk = {} + {} * n",
        //     t.mul(&u),
        //     st,
        //     husc,
        //     mu,
        //     nu
        // );

        let (gcd_tnu_s, co_tnu, _) = BigInt::egcd(&t.mul(&nu), &s);
        // println!(
        //     "gcd(tnu, s) = {}\nco_tnu = {}\n",
        //     gcd_tnu_s,
        //     co_tnu
        // );
        let htmu = h.sub(&t.mul(&mu));
        if !htmu.modulus(&gcd_tnu_s).is_zero() {
            panic!("congruence 2 has no solution")
        }
        let lambda = co_tnu.mul(&htmu.div_floor(&gcd_tnu_s)).modulus(&s);

        // println!(
        //     "tnu = {}\ns = {}\nh - tnu = {}\nlambda = {}\n",
        //     t.mul(&nu),
        //     s,
        //     htmu,
        //     lambda,
        // );

        let k = mu.add(&nu.mul(&lambda));
        let l = k.mul(&t).sub(&h).div_floor(&s);
        let m = t.mul(&u).mul(&k).sub(&h.mul(&u)).sub(&self.c.mul(&s)).div_floor(&s.mul(&t));
        let result = Self {
            a: s.mul(&t),
            b: j.mul(&u).sub(&k.mul(&t).add(&l.mul(&s))),
            c: k.mul(&l).sub(&j.mul(&m))
        };
        result.reduce()
    }

    pub fn inverse(&self) -> Self {
        BinaryQF {
            a: self.a.clone(),
            b: self.b.clone().neg(),
            c: self.c.clone(),
        }
    }

    pub fn rho(&self) -> Self {
        let qf_new = BinaryQF {
            a: self.c.clone(),
            b: self.b.clone().neg(),
            c: self.a.clone(),
        };

        qf_new.normalize()
    }

    pub fn reduce(&self) -> Self {
        let mut h: BinaryQF;
        let mut h_new = self.clone();
        if !self.is_normal() {
            h_new = self.normalize();
        }
        h = h_new;
        while !h.is_reduced() {
            let h_new = h.rho();
            h = h_new;
        }
        h
    }

    pub fn identity(&self) -> Self {
        let disc = self.discriminant();
        let b = disc.modulus(&BIGINT_TWO);
        Self {
            a: BigInt::one(),
            c: b.sub(&disc).div_floor(&4.into()),
            b: b,
        }
    }

    pub fn exp(&self, n: &BigInt) -> BinaryQF {
        let mut ctx = Ctx::default();
        // assert!(n.ge(&BigInt::zero()));
        let mut current = match n.lt(&BigInt::zero()) {
            true  => BinaryQF { a: self.a.clone(), b: self.b.clone().neg(), c: self.c.clone() }, 
            false => self.clone()
        };
        let mut result = self.identity();
        let mut remain = n.abs();
        loop{
            // dbg!(&result);
            // dbg!(&n);
            if remain.is_zero(){
                break;
            }
            if remain.is_odd() {
                // result = result.compose(&current);
               result.inner_compose(&current, &mut ctx);
            }
            // current = current.square();
            // current = ctx.square(&current);
            // current = current.compose(&current);
            current.inner_square_impl(&mut ctx);
            remain.shr_assign(1);
        }
        result
        // let pari_qf = self.qf_to_pari_qf();
        // let pari_n = bn_to_gen(n);

        // let pari_qf_exp = unsafe { nupow(pari_qf, pari_n, ptr::null_mut()) };

        // BinaryQF::pari_qf_to_qf(pari_qf_exp)
    }
    // gotoNonMax: outputs: f=phi_q^(-1)(F), a binary quadratic form of disc. delta*conductor^2
    //      f is non normalized
    pub fn phi_q_to_the_minus_1(&self, conductor: &BigInt) -> BinaryQF {
        let two_a = &self.a * BigInt::from(2);
        let b_conductor: BigInt = &self.b * conductor;
        let b_new = b_conductor.mod_floor(&two_a);
        let disc = self.discriminant();
        let cond_square = conductor.pow(2);
        let delta = disc * cond_square;
        let abdelta = ABDeltaTriple {
            a: self.a.clone(),
            b: b_new,
            delta,
        };

        BinaryQF::binary_quadratic_form_disc(&abdelta)
    }

    // compute (p^(2),p,-)^k in class group of disc. delta
    pub fn expo_f(p: &BigInt, delta: &BigInt, k: &BigInt) -> BinaryQF {
        if k == &BigInt::zero() {
            return BinaryQF::binary_quadratic_form_principal(delta);
        }
        let mut k_inv = BigInt::mod_inv(k, p).unwrap();
        if k_inv.mod_floor(&BigInt::from(2)) == BigInt::zero() {
            k_inv -= p;
        };
        let k_inv_p = k_inv * p;
        let abdelta = ABDeltaTriple {
            a: p * p,
            b: k_inv_p,
            delta: delta.clone(),
        };

        BinaryQF::binary_quadratic_form_disc(&abdelta)
    }

    pub fn discrete_log_f(p: &BigInt, delta: &BigInt, c: &BinaryQF) -> BigInt {
        let principal_qf = BinaryQF::binary_quadratic_form_principal(delta);
        if c == &principal_qf {
            BigInt::zero()
        } else {
            let Lk = c.b.div_floor(p);

            BigInt::mod_inv(&Lk, p).unwrap()
        }
    }

    //we construct a pari qf from qf
    pub fn qf_to_pari_qf(&self) -> GEN {
        let a = bn_to_gen(&self.a);
        let b = bn_to_gen(&self.b);
        let c = bn_to_gen(&self.c);

        //  GEN qfi(GEN a, GEN b, GEN c) (assumes b^2 − 4ac < 0)
        unsafe { qfi(a, b, c) }
    }

    // construct BinaryQF from pari GEN encoded qfb
    pub fn pari_qf_to_qf(pari_qf: GEN) -> Self {
        // TODO: add check that GEN is indeed a qfb
        let a_string = pari_qf_comp_to_decimal_string(pari_qf, 1);
        let b_string = pari_qf_comp_to_decimal_string(pari_qf, 2);
        let c_string = pari_qf_comp_to_decimal_string(pari_qf, 3);

        let a: BigInt = BigInt::from_str_radix(&a_string, 10).unwrap();
        let b: BigInt = BigInt::from_str_radix(&b_string, 10).unwrap();
        let c: BigInt = BigInt::from_str_radix(&c_string, 10).unwrap();

        BinaryQF { a, b, c }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut a_vec = BigInt::to_bytes(&self.a);
        let b_vec = BigInt::to_bytes(&self.b);
        let c_vec = BigInt::to_bytes(&self.c);
        a_vec.extend_from_slice(&b_vec[..]);
        a_vec.extend_from_slice(&c_vec[..]);
        a_vec
    }

    /// Takes point in reduced form and returns its compressed
    /// representation.
    ///
    /// Follows Algorithm 1 from [paper](https://eprint.iacr.org/2020/196.pdf).
    ///
    /// Returns `None` if Self is not in reduced form. Use
    /// [is_reduced](Self::is_reduced) to determine if it can be comressed
    /// and [reduce](Self::reduce) to find equivalent in reduced form
    /// for any BinaryQF.
    pub fn to_compressed(&self) -> Option<BinaryQFCompressed> {
        if !self.is_reduced() {
            return None;
        }

        // 1. (s, u, t) <- PartialXGCD(|a|, |b|, sqrt(|a|)
        let (_s, _u, mut t) = partial_xgcd(&self.a.abs(), &self.b.abs());
        // 2. if b < 0 then t <- -t
        if self.b < BigInt::zero() {
            t = -t
        }

        // 3. g <- gcd(a,t)
        let (g, _, _) = BigInt::egcd(&self.a, &t);
        // 4. a' <- a/g
        let a1 = &self.a / &g;
        // 5-8. if a = b then t' <- 0 else t' <- t/g
        let t1 = if self.a == self.b {
            BigInt::zero()
        } else {
            &t / &g
        };
        // 9. b0 <- b mod g
        let b0 = self.b.modulus(&g);
        // 10. ε <- [b >= 0]
        let e = self.b >= BigInt::zero();

        let delta = self.discriminant();
        Some(BinaryQFCompressed {
            a1,
            t1,
            g,
            b0,
            e,
            delta,
        })
    }

    pub fn from_compressed(compressed: BinaryQFCompressed) -> Option<Self> {
        Some(Self::binary_quadratic_form_disc(
            &ABDeltaTriple::from_compressed(compressed)?,
        ))
    }
}

impl ABDeltaTriple {
    pub fn from_compressed(compressed: BinaryQFCompressed) -> Option<Self> {
        let BinaryQFCompressed {
            a1,
            t1,
            g,
            b0,
            e,
            delta,
        } = compressed;

        // 1. a <- g * a'
        let a = &g * &a1;
        // 2. t <- g * t'
        let t = &g * &t1;
        // 3. if t = 0 then return (a,a)
        if t.is_zero() {
            return Some(Self {
                a: a.clone(),
                b: a,
                delta,
            });
        }
        // 4. x <- t^2 * ∆ (mod a)
        let t2 = BigInt::mod_mul(&t, &t, &a);
        let x = BigInt::mod_mul(&t2, &delta, &a);
        // 5. s <- sqrt(x)
        let s = x.sqrt();
        // 6. s' <- s/g
        let s1 = &s / &g;
        // 7. b' <- s' * t^−1 (mod a')
        let t_inv = BigInt::mod_inv(&t, &a1)?;
        let b1 = BigInt::mod_mul(&s1, &t_inv, &a1);
        // 8. b <- CRT((b', a'), (b0, g))
        let mut b: BigInt =
            chinese_reminder_theorem::chinese_remainder_theorem(&[b1, b0], &[a1, g])?;
        // 9. if ε = False then b <- −b (mod a)
        if !e {
            b = -b
        }
        // 10. return (a,b)
        Some(Self { a, b, delta })
    }
}

/// Takes a,b (a > b > 0), produces r,s,t such as `r = s * a + t * b` where `|r|,|t| < sqrt(a)`
fn partial_xgcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let mut r = (a.clone(), b.clone());
    let mut s = (BigInt::one(), BigInt::zero());
    let mut t = (BigInt::zero(), BigInt::one());

    let a_sqrt = a.sqrt();
    while r.1 >= a_sqrt {
        let q = &r.0 / &r.1;
        let r1 = &r.0 - &q * &r.1;
        let s1 = &s.0 - &q * &s.1;
        let t1 = &t.0 - &q * &t.1;

        swap(&mut r.0, &mut r.1);
        r.1 = r1;
        swap(&mut s.0, &mut s.1);
        s.1 = s1;
        swap(&mut t.0, &mut t.1);
        t.1 = t1;
    }

    (r.1, s.1, t.1)
}

// helper functions:
// this function turns a bigint into GEN (native Pari type)
pub fn bn_to_gen(bn: &BigInt) -> GEN {
    let neg1 = if bn < &BigInt::zero() { -1 } else { 1 };
    let neg_bn: BigInt = if bn < &BigInt::zero() {
        -BigInt::one()
    } else {
        BigInt::one()
    };
    let bn: BigInt = bn * &neg_bn;

    let bn_len = bn.bit_length();
    let num_int_bound: usize;
    if bn_len % 8 == 0 {
        num_int_bound = bn_len / 8;
    } else {
        num_int_bound = bn_len / 8 + 1;
    }
    let size_int = 32;
    let two_bn = BigInt::from(2);
    let all_ones_32bits = two_bn.pow(size_int as u32) - BigInt::one();
    let mut array = [0u8; 4];
    let ints_vec = (0..num_int_bound)
        .map(|i| {
            let masked_valued_bn = (&bn & &all_ones_32bits << (i * size_int)) >> (i * size_int);

            let mut masked_value_bytes = BigInt::to_bytes(&masked_valued_bn);
            // padding if int has leading zero bytes
            let mut template = vec![0; 4 - masked_value_bytes.len()];
            template.extend_from_slice(&masked_value_bytes);
            masked_value_bytes = template;

            array.copy_from_slice(&masked_value_bytes[..]);

            u32::from_be_bytes(array) as i64
        })
        .collect::<Vec<i64>>();

    let mut i = 0;
    let mut gen = unsafe { mkintn(1i64, 0i64) };
    unsafe {
        while i < num_int_bound {
            let elem1 = mkintn(1i64, ints_vec[num_int_bound - i - 1]);
            let elem2 = shifti(gen, (size_int) as i64);
            gen = gadd(elem1, elem2);
            i += 1
        }

        if neg1 == -1 {
            gen = gneg(gen);
        }

        gen
    }
}

pub fn pari_qf_comp_to_decimal_string(pari_qf: GEN, index: usize) -> String {
    let comp = unsafe { compo(pari_qf, index as i64) };

    let comp_char_ptr = unsafe { GENtostr(comp) };
    let c_buf: *const c_char = comp_char_ptr;
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let comp_str_slice: &str = c_str.to_str().unwrap();
    comp_str_slice.to_string()
}

#[cfg(test)]
mod tests {
    use std::str;

    use proptest::prelude::*;

    use super::*;
    use crate::curv::arithmetic::traits::Samplable;

    #[test]
    fn test_qf_to_pari_qf_to_qf() {
        unsafe {
            pari_init(10000000, 2);
        }
        let a: BigInt = BigInt::from_str_radix("1347310664179468558147371727982960102805371574927252724399119343247182932538452304549609704350360058405827948976558722087559341859252338031258062288910984654814255199874816496621961922792890687089794760104660404141195904459619180668507135317125790028783030121033883873501532619563806411495141846196437", 10).unwrap();

        let b = BigInt::from(2);
        let delta = -BigInt::from(3) * BigInt::from(201);
        let abd = ABDeltaTriple { a, b, delta };
        let pf = BinaryQF::binary_quadratic_form_disc(&abd);
        let pari_qf = pf.qf_to_pari_qf();
        let pf2 = BinaryQF::pari_qf_to_qf(pari_qf);
        assert_eq!(pf, pf2);
    }

    #[test]
    fn test_bn_to_gen_to_bn() {
        unsafe {
            pari_init(10000000, 2);
        }
        let test: BigInt = BigInt::sample(1600);
        let gen = bn_to_gen(&test);

        let char_ptr = unsafe { GENtostr(gen) };
        let c_buf: *const c_char = char_ptr;
        let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
        let str_slice: &str = c_str.to_str().unwrap();
        let string_slice = str_slice.to_string();
        let test2: BigInt = BigInt::from_str_radix(&string_slice, 10).unwrap();

        assert_eq!(test, test2);
    }

    #[test]
    fn test_compose_exp() {
        unsafe {
            pari_init(10000000, 2);
        }
        let mut det: BigInt;

        det = -BigInt::sample(1600);
        while det.mod_floor(&BigInt::from(4)) != BigInt::one() || !det.is_probable_prime(300){
            det = -BigInt::sample(1600);
        }
        let a_b_delta = ABDeltaTriple {
            a: BigInt::from(2),
            b: BigInt::from(1),
            delta: det,
        };
        let group = BinaryQF::binary_quadratic_form_disc(&a_b_delta);
        let x = BigInt::sample(100);
        let g = group.exp(&x).reduce();
        let gg1 = g.compose(&g).reduce();
        let gg2 = g.exp(&BigInt::from(2)).reduce();
        assert_eq!(gg1, gg2);
    }

    #[test]
    fn test_principal_exp() {
        unsafe {
            pari_init(10000000, 2);
        }
        let mut det: BigInt;

        det = -BigInt::sample(1600);
        while det.mod_floor(&BigInt::from(4)) != BigInt::one() || !det.clone().neg().is_probable_prime(100) {
            det = -BigInt::sample(1600);
        }
        let f = BinaryQF::binary_quadratic_form_principal(&det);
        let x = BigInt::sample(100);
        let f_exp = f.exp(&x);
        assert_eq!(f, f_exp);
    }

    proptest::proptest! {
        #[test]
        fn fuzz_partial_xgcd(a in any::<u32>(), b in any::<u32>()) {
            proptest::prop_assume!(a > b && b > 0);
            test_partial_xgcd(BigInt::from(a), BigInt::from(b))
        }
        #[test]
        fn fuzz_compression(d in 1u32..) {
            let delta = BigInt::from(d) * BigInt::from(-4) + BigInt::one();
            test_compression(delta)
        }
    }

    fn test_partial_xgcd(a: BigInt, b: BigInt) {
        let (r, s, t) = partial_xgcd(&a, &b);
        println!("r={}, s={}, t={}", r, s, t);

        // We expect that r = a * s + b * t
        assert_eq!(r, &a * &s + &b * &t);

        // We expect both |r| and |t| to be less than sqrt(a)
        let a_sqrt = a.sqrt();
        assert!(
            r.abs() < a_sqrt,
            "r is not less than sqrt(a), diff = {}",
            &r - &a_sqrt
        );
        assert!(
            t.abs() < a_sqrt,
            "t is not less than sqrt(a), diff = {}",
            &t - &a_sqrt
        );
    }

    fn test_compression(delta: BigInt) {
        let uncompressed = BinaryQF::binary_quadratic_form_principal(&delta).reduce();
        let compressed = uncompressed.to_compressed().expect("failed to compress");
        let uncompressed2 = BinaryQF::from_compressed(compressed).expect("failed to decompress");

        assert_eq!(uncompressed, uncompressed2);
    }
}
