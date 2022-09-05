use crate::signature::basic_lamport::{
    BasicLamportKey, BasicLamportSignature, BasicLamportSignatureScheme,
};
use crate::signature::{HashType, SignatureScheme};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

pub struct QIndexedSignatureScheme {
    one_time_signatures: Vec<BasicLamportSignatureScheme>,
}

impl QIndexedSignatureScheme {
    pub fn new(q: usize, seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut seed_for_sub_scheme: [u8; 32] = [0; 32];
        let mut one_time_signatures = Vec::new();
        for _ in 0..q {
            rng.fill_bytes(&mut seed_for_sub_scheme);
            one_time_signatures.push(BasicLamportSignatureScheme::new(seed_for_sub_scheme));
        }

        Self {
            one_time_signatures,
        }
    }
}

impl SignatureScheme<Vec<BasicLamportKey>, (usize, HashType), (usize, BasicLamportSignature)>
    for QIndexedSignatureScheme
{
    fn public_key(&self) -> Vec<BasicLamportKey> {
        self.one_time_signatures
            .iter()
            .map(|s| s.public_key())
            .collect()
    }

    fn sign(&mut self, message: (usize, HashType)) -> (usize, BasicLamportSignature) {
        let (q, message) = message;
        (q, self.one_time_signatures[q].sign(message))
    }

    fn verify(
        pk: Vec<BasicLamportKey>,
        message: (usize, HashType),
        signature: (usize, BasicLamportSignature),
    ) -> bool {
        let (q_m, message) = message;
        let (q_s, signature) = signature;

        if q_m != q_s {
            false
        } else {
            BasicLamportSignatureScheme::verify(pk[q_m], message, signature)
        }
    }
}
