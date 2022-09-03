use orion::hash::{digest, Digest};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

use crate::digest_to_bytes::digest_to_bytes;


pub struct BasicLamportSignature {
    // 2v
    // x : 256 bit
    sk: [[[u8; 32]; 2]; 256],
    pk: [[[u8; 32]; 2]; 256]
}

impl BasicLamportSignature {
    pub fn new(seed: [u8; 32]) -> Self {
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
        BasicLamportSignature{ sk, pk }
    }

    pub fn sign(&self, message: &[u8; 32]) -> [[u8; 32]; 256] {
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
        signature
    }
}