use hmac_sha256::Hash;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

use crate::signature::{HashType, SignatureScheme};

pub type BasicLamportKey = [[[u8; 32]; 2]; 256];
pub type BasicLamportSignature = [[u8; 32]; 256];

/// The basic Lamport one-time signature, as described in Section 14.1
/// in the [textbook](http://toc.cryptobook.us/) by Boneh & Shoup.
///
/// In short:
/// - The key generation algorithm generates `2 * 256` random integers, used as the signing key.
///   Also, hashes of these integers are published as the public key.
/// - To sign a 256-bit message, the 256 integers of the signing key (corresponding to the
///   256 bits of the message) are released as the signature
/// - The verifier can easily verify that they hash to the right values in the public key
///
/// # Examples
///
/// ```
/// use hash_based_signatures::signature::basic_lamport::BasicLamportSignatureScheme;
/// use hash_based_signatures::signature::SignatureScheme;
///
/// let mut signature_scheme = BasicLamportSignatureScheme::new([0u8; 32]);
/// let signature = signature_scheme.sign([1u8; 32]);
/// assert!(BasicLamportSignatureScheme::verify(
///     signature_scheme.public_key(),
///     [1u8; 32],
///     &signature
/// ))
/// ```
#[derive(Clone)]
pub struct BasicLamportSignatureScheme {
    sk: BasicLamportKey,
    pk: BasicLamportKey,
    message: Option<HashType>,
}

impl BasicLamportSignatureScheme {
    /// Generates a new one-time key pair from the given `seed` and instantiates the scheme.
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
                pk[bit_to_sign][bit] = Hash::hash(&sk[bit_to_sign][bit]);
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

    /// Signs a message.
    ///
    /// # Panics
    ///
    /// Panics if the scheme is used more than once to sign *different* messages.
    /// Note that there could still be a different instance with the same secret key,
    /// which would not be detected.
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
                let hash = Hash::hash(&signature[bit_index]);
                let pk_index_to_expect = (byte & (1 << local_bit_index) != 0) as usize;
                is_correct &= hash == pk[bit_index][pk_index_to_expect];
            }
        }
        is_correct
    }
}

#[cfg(test)]
mod tests {
    use crate::signature::basic_lamport::BasicLamportSignatureScheme;
    use crate::signature::SignatureScheme;

    fn get_signature_scheme() -> BasicLamportSignatureScheme {
        let seed = [0u8; 32];
        BasicLamportSignatureScheme::new(seed)
    }

    #[test]
    fn test_correct_signature() {
        let mut signature_scheme = get_signature_scheme();
        let signature = signature_scheme.sign([1u8; 32]);
        assert!(BasicLamportSignatureScheme::verify(
            signature_scheme.public_key(),
            [1u8; 32],
            &signature
        ))
    }

    #[test]
    fn test_incorrect_signature() {
        let signature_scheme = get_signature_scheme();
        assert!(!BasicLamportSignatureScheme::verify(
            signature_scheme.public_key(),
            [1u8; 32],
            &[[0u8; 32]; 256]
        ))
    }

    #[test]
    fn test_can_sign_same_message() {
        let mut signature_scheme = get_signature_scheme();
        signature_scheme.sign([1u8; 32]);
        signature_scheme.sign([1u8; 32]);
    }

    #[test]
    #[should_panic]
    fn test_cant_sign_different_messages() {
        let mut signature_scheme = get_signature_scheme();
        signature_scheme.sign([1u8; 32]);
        signature_scheme.sign([2u8; 32]);
    }
}
