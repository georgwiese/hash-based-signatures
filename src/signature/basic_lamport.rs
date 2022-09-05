use orion::hash::digest;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

use crate::digest_to_bytes::digest_to_bytes;
use crate::signature::{Signature, SignatureScheme};

pub struct BasicLamportSignature {
    pk: [[[u8; 32]; 2]; 256],
    signature: [[u8; 32]; 256],
}

impl Signature for BasicLamportSignature {
    fn verify(&self, message: &[u8; 32]) -> bool {
        let mut is_correct = true;
        for byte_index in 0..32 {
            let byte = message[byte_index];
            for local_bit_index in 0..8 {
                let bit_index = byte_index * 8 + local_bit_index;
                let hash = digest_to_bytes(digest(&self.signature[bit_index]).unwrap());
                let pk_index_to_expect = (byte & (1 << local_bit_index) != 0) as usize;
                is_correct &= hash == self.pk[bit_index][pk_index_to_expect];
            }
        }
        is_correct
    }
}

pub struct BasicLamportSignatureScheme {
    // 2v
    // x : 256 bit
    sk: [[[u8; 32]; 2]; 256],
    pk: [[[u8; 32]; 2]; 256],
}

impl SignatureScheme<BasicLamportSignature> for BasicLamportSignatureScheme {
    fn new(seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut sk: [[[u8; 32]; 2]; 256] = [[[0; 32]; 2]; 256];

        // create secrets
        for bit_to_sign in 0..256 {
            for bit in 0..2 {
                rng.fill_bytes(&mut sk[bit_to_sign][bit]);
            }
        }

        // hash secrets to public keys
        let mut pk: [[[u8; 32]; 2]; 256] = [[[0; 32]; 2]; 256];
        for bit_to_sign in 0..256 {
            for bit in 0..2 {
                pk[bit_to_sign][bit] = digest_to_bytes(digest(&sk[bit_to_sign][bit]).unwrap());
            }
        }
        BasicLamportSignatureScheme { sk, pk }
    }
    fn sign(&self, message: &[u8; 32]) -> BasicLamportSignature {
        let mut signature: [[u8; 32]; 256] = [[0; 32]; 256];
        for byte_index in 0..32 {
            let byte = message[byte_index];
            for local_bit_index in 0..8 {
                let bit_index = byte_index * 8 + local_bit_index;
                if byte & (1 << local_bit_index) != 0 {
                    signature[bit_index] = self.sk[bit_index][1];
                } else {
                    signature[bit_index] = self.sk[bit_index][0];
                }
            }
        }
        BasicLamportSignature {
            pk: self.pk,
            signature,
        }
    }
}
