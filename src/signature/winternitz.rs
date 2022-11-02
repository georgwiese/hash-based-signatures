pub mod d;
pub mod domination_free_function;

use crate::signature::winternitz::d::D;
use crate::signature::winternitz::domination_free_function::domination_free_function;
use crate::signature::{HashType, SignatureScheme};
use crate::utils::{bits_to_unsigned_ints, get_least_significant_bits, hash};
use anyhow::{bail, Result};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::iter;

/// Private or Public key.
/// The length depends on Winternitz parameter `d` and is roughly
/// `256 / log2(d)`.
pub type WinternitzKey = Vec<[u8; 32]>;

/// Winternitz signature.
/// The first element is Winternitz parameter `d`, the second is the actual signature.
pub type WinternitzSignature = (u64, Vec<[u8; 32]>);

/// Winternitz signatures, as described in Section 14.3
/// in the [textbook](http://toc.cryptobook.us/) by Boneh & Shoup.
///
/// To create a one-time signature, the scheme hashes secret key values
/// a number of times, as determined by the `domination_free_function`.
/// The parameter `d` trades off signature size (the higher, the smaller the signature)
/// and computation time (the higher, the longer the time).
///
/// # Examples
///
/// ```
/// use hash_based_signatures::signature::SignatureScheme;
/// use hash_based_signatures::signature::winternitz::d::D;
/// use hash_based_signatures::signature::winternitz::WinternitzSignatureScheme;
///
/// let mut signature_scheme = WinternitzSignatureScheme::new([0u8; 32], D::new(15));
/// let signature0 = signature_scheme.sign([0u8; 32]);
/// assert!(WinternitzSignatureScheme::verify(
///     signature_scheme.public_key(),
///     [0u8; 32],
///     &signature0
/// ));
/// ```
#[derive(Clone)]
pub struct WinternitzSignatureScheme {
    sk: WinternitzKey,
    pk: WinternitzKey,
    d: D,
}

/// Computes the hash chain of a given (intermediate) input.
/// To do so, hash `i` is computed as `Sha256(i, <input>)`, with `i` going from
/// `start` (inclusive) to `end` (exclusive).
fn hash_chain(input: HashType, start: u8, end: u8) -> HashType {
    let mut current_hash_value = input;
    let mut counter_buffer = [0u8; 32];

    for i in start..end {
        // Encode i as a 32-bit value into the buffer
        let index_bitstring = get_least_significant_bits(i as usize, 32);
        let index_bytes = bits_to_unsigned_ints(&index_bitstring);
        assert_eq!(index_bytes.len(), 4);
        for i in 0..4 {
            counter_buffer[i] = index_bytes[i];
        }

        current_hash_value = hash(&[counter_buffer, current_hash_value].concat());
    }
    current_hash_value
}

#[cfg(not(target_arch = "wasm32"))]
fn hash_chain_parallel(
    inputs: &Vec<HashType>,
    starts: impl Iterator<Item = u8>,
    ends: impl Iterator<Item = u8>,
) -> Vec<HashType> {
    // Materialize starts and ends, to allow for parallelization
    let starts: Vec<u8> = starts.take(inputs.len()).collect();
    let ends: Vec<u8> = ends.take(inputs.len()).collect();

    inputs
        .par_iter()
        .zip(starts.par_iter())
        .zip(ends.par_iter())
        .map(|((input, start), end)| hash_chain(*input, *start, *end))
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn hash_chain_parallel(
    inputs: &Vec<HashType>,
    starts: impl Iterator<Item = u8>,
    ends: impl Iterator<Item = u8>,
) -> Vec<HashType> {
    // Same as above, but using `iter()` instead of `par_iter()` to avoid spawning threads.
    let starts: Vec<u8> = starts.take(inputs.len()).collect();
    let ends: Vec<u8> = ends.take(inputs.len()).collect();

    inputs
        .iter()
        .zip(starts.iter())
        .zip(ends.iter())
        .map(|((input, start), end)| hash_chain(*input, *start, *end))
        .collect()
}

impl WinternitzSignatureScheme {
    /// Builds a Winternitz signature scheme from the given `seed`.
    pub fn new(seed: [u8; 32], d: D) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);

        let mut buffer = [0u8; 32];
        let mut sk = Vec::with_capacity(d.signature_and_key_size());

        // create secrets
        for _ in 0..d.signature_and_key_size() {
            rng.fill_bytes(&mut buffer);
            sk.push(buffer);
        }
        let pk = hash_chain_parallel(&sk, iter::repeat(0), iter::repeat(d.d as u8));

        Self { sk, pk, d }
    }

    /// Given a message and signature, computes the public key belonging to the private
    /// key that signed the message.
    pub fn public_key_from_message_and_signature(
        message: HashType,
        signature: &WinternitzSignature,
    ) -> Result<WinternitzKey> {
        let (d, signature) = signature;
        let d = D::try_from(*d)?;

        let times_to_hash = domination_free_function(message, &d);

        if times_to_hash.len() != signature.len() {
            bail!("Signature has invalid length");
        }

        let expected_pk = hash_chain_parallel(
            &signature,
            times_to_hash.into_iter(),
            iter::repeat(d.d as u8),
        );

        Ok(expected_pk)
    }
}

impl SignatureScheme<WinternitzKey, HashType, WinternitzSignature> for WinternitzSignatureScheme {
    fn public_key(&self) -> WinternitzKey {
        self.pk.clone()
    }

    fn sign(&mut self, message: HashType) -> WinternitzSignature {
        let times_to_hash = domination_free_function(message, &self.d);
        assert_eq!(times_to_hash.len(), self.sk.len());

        let signature = hash_chain_parallel(&self.sk, iter::repeat(0), times_to_hash.into_iter());

        (self.d.d, signature)
    }

    fn verify(pk: WinternitzKey, message: HashType, signature: &WinternitzSignature) -> bool {
        match WinternitzSignatureScheme::public_key_from_message_and_signature(message, signature) {
            Ok(expected_public_key) => expected_public_key == pk,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::signature::winternitz::d::D;
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
