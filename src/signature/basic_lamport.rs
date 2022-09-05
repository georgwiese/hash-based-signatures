use orion::hash::digest;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

use crate::signature::{HashType, SignatureScheme};
use crate::utils::digest_to_bytes;

pub type BasicLamportKey = [[[u8; 32]; 2]; 256];
pub type BasicLamportSignature = [[u8; 32]; 256];

pub struct BasicLamportSignatureScheme {
    sk: BasicLamportKey,
    pk: BasicLamportKey,
    message: Option<HashType>,
}

impl BasicLamportSignatureScheme {
    pub fn new(seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut sk = [[[0; 32]; 2]; 256];

        // create secrets
        for bit_to_sign in 0..256 {
            for bit in 0..2 {
                rng.fill_bytes(&mut sk[bit_to_sign][bit]);
            }
        }

        // hash secrets to public keys
        let mut pk = [[[0; 32]; 2]; 256];
        for bit_to_sign in 0..256 {
            for bit in 0..2 {
                pk[bit_to_sign][bit] = digest_to_bytes(digest(&sk[bit_to_sign][bit]).unwrap());
            }
        }
        Self {
            pk,
            sk,
            message: None,
        }
    }
}

impl SignatureScheme<BasicLamportKey, HashType, BasicLamportSignature>
    for BasicLamportSignatureScheme
{
    fn public_key(&self) -> BasicLamportKey {
        self.pk
    }

    fn sign(&mut self, message: HashType) -> BasicLamportSignature {
        if let Some(existing_message) = self.message {
            if existing_message != message {
                panic!("One-time signature has been used to sign more than one message!")
            }
        }
        self.message = Some(message);

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

    fn verify(pk: BasicLamportKey, message: HashType, signature: &BasicLamportSignature) -> bool {
        let mut is_correct = true;
        for byte_index in 0..32 {
            let byte = message[byte_index];
            for local_bit_index in 0..8 {
                let bit_index = byte_index * 8 + local_bit_index;
                let hash = digest_to_bytes(digest(&signature[bit_index]).unwrap());
                let pk_index_to_expect = (byte & (1 << local_bit_index) != 0) as usize;
                is_correct &= hash == pk[bit_index][pk_index_to_expect];
            }
        }
        is_correct
    }
}
