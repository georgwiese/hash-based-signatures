pub mod domination_free_function;

use crate::signature::winternitz::domination_free_function::{domination_free_function, D};
use crate::signature::{HashType, SignatureScheme};
use crate::utils::{bits_to_unsigned_ints, get_least_significant_bits};
use hmac_sha256::Hash;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

pub type WinternitzKey = Vec<[u8; 32]>;
pub type WinternitzSignature = (u64, Vec<[u8; 32]>);

#[derive(Clone)]
pub struct WinternitzSignatureScheme {
    sk: WinternitzKey,
    pk: WinternitzKey,
    d: D,
}

fn hash_chain(input: HashType, start: usize, end: usize) -> HashType {
    let mut current_hash_value = input;
    let mut counter_buffer = [0u8; 32];

    assert!(end < (1 << 32));

    for i in start..end {
        // Encode i as a 32-bit value into the buffer
        let index_bitstring = get_least_significant_bits(i, 32);
        let index_bytes = bits_to_unsigned_ints(&index_bitstring);
        assert_eq!(index_bytes.len(), 4);
        for i in 0..4 {
            counter_buffer[i] = index_bytes[i];
        }

        current_hash_value = Hash::hash(&[counter_buffer, current_hash_value].concat());
    }
    current_hash_value
}

impl WinternitzSignatureScheme {
    pub fn new(seed: [u8; 32], d: D) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);

        let mut buffer = [0u8; 32];
        let mut sk = Vec::with_capacity(d.signature_and_key_size());
        let mut pk = Vec::with_capacity(d.signature_and_key_size());

        // create secrets
        for _ in 0..d.signature_and_key_size() {
            rng.fill_bytes(&mut buffer);
            sk.push(buffer);

            pk.push(hash_chain(buffer, 0, d.d as usize));
        }

        Self { sk, pk, d }
    }
}

impl SignatureScheme<WinternitzKey, HashType, WinternitzSignature> for WinternitzSignatureScheme {
    fn public_key(&self) -> WinternitzKey {
        self.pk.clone()
    }

    fn sign(&mut self, message: HashType) -> WinternitzSignature {
        let mut signature = Vec::with_capacity(self.sk.len());
        let times_to_hash = domination_free_function(message, &self.d);

        assert_eq!(times_to_hash.len(), self.sk.len());

        for (sk_value, n) in self.sk.iter().zip(times_to_hash) {
            signature.push(hash_chain(*sk_value, 0, n as usize))
        }

        (self.d.d, signature)
    }

    fn verify(pk: WinternitzKey, message: HashType, signature: &WinternitzSignature) -> bool {
        let (d, signature) = signature;
        let times_to_hash = domination_free_function(message, &D::new(*d));
        let mut expected_pk = Vec::with_capacity(pk.len());

        if times_to_hash.len() != signature.len() {
            return false;
        }

        for (signature_value, times_hashed) in signature.iter().zip(times_to_hash) {
            expected_pk.push(hash_chain(
                *signature_value,
                times_hashed as usize,
                *d as usize,
            ))
        }
        expected_pk == pk
    }
}

#[cfg(test)]
mod tests {
    use crate::signature::winternitz::domination_free_function::D;
    use crate::signature::winternitz::WinternitzSignatureScheme;
    use crate::signature::SignatureScheme;

    fn get_signature_scheme(d: D) -> WinternitzSignatureScheme {
        let seed = [0u8; 32];
        WinternitzSignatureScheme::new(seed, d)
    }

    #[test]
    fn test_correct_signature_d1() {
        let mut signature_scheme = get_signature_scheme(D::new(1));
        let signature = signature_scheme.sign([1u8; 32]);
        assert!(WinternitzSignatureScheme::verify(
            signature_scheme.public_key(),
            [1u8; 32],
            &signature
        ))
    }

    #[test]
    fn test_correct_signature_d3() {
        let mut signature_scheme = get_signature_scheme(D::new(3));
        let signature = signature_scheme.sign([1u8; 32]);
        assert!(WinternitzSignatureScheme::verify(
            signature_scheme.public_key(),
            [1u8; 32],
            &signature
        ))
    }

    #[test]
    fn test_correct_signature_d15() {
        let mut signature_scheme = get_signature_scheme(D::new(15));
        let signature = signature_scheme.sign([1u8; 32]);
        assert!(WinternitzSignatureScheme::verify(
            signature_scheme.public_key(),
            [1u8; 32],
            &signature
        ))
    }

    #[test]
    fn test_correct_signature_d255() {
        let mut signature_scheme = get_signature_scheme(D::new(255));
        let signature = signature_scheme.sign([1u8; 32]);
        assert!(WinternitzSignatureScheme::verify(
            signature_scheme.public_key(),
            [1u8; 32],
            &signature
        ))
    }
}
