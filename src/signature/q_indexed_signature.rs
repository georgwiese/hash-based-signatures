use crate::signature::{Signature, SignatureScheme};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::marker::PhantomData;

pub struct QIndexedSignatureScheme<Scheme, S>
where
    Scheme: SignatureScheme<S>,
    S: Signature,
{
    available_q: Vec<bool>,
    signature_schemes: Vec<Scheme>,
    // needed as no use of type parameter S
    // https://doc.rust-lang.org/std/marker/struct.PhantomData.html
    signature_type: PhantomData<S>,
}

impl<Scheme, S> QIndexedSignatureScheme<Scheme, S>
where
    Scheme: SignatureScheme<S>,
    S: Signature,
{
    pub fn new(q: usize, seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut seed_for_sub_scheme: [u8; 32] = [0; 32];
        let mut signature_schemes: Vec<Scheme> = Vec::new();
        for _ in 0..q {
            rng.fill_bytes(&mut seed_for_sub_scheme);
            signature_schemes.push(Scheme::new(seed_for_sub_scheme));
        }
        Self {
            available_q: vec![true; q],
            signature_schemes,
            signature_type: PhantomData,
        }
    }
    pub fn sign(&mut self, q: usize, message: &[u8; 32]) -> S {
        if !self.available_q[q] {
            panic!("Cannot use q twice! {}", q)
        }
        self.available_q[q] = false;
        self.signature_schemes[q].sign(message)
    }
}
