use crate::signature::q_indexed_signature::{QIndexedSignature, QIndexedSignatureScheme};
use crate::signature::winternitz::domination_free_function::D;
use crate::signature::{HashType, SignatureScheme};
use crate::utils::{hash, hmac, string_to_hash};
use data_encoding::HEXLOWER;
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

#[derive(Serialize, Deserialize)]
pub struct StatelessMerklePrivateKey {
    pub seed_hex: String,
    pub width: usize,
    pub depth: usize,
    pub d: u64,
    // This can be derived from the seed, but might be useful for someone who inspects the JSON
    pub public_key: String,
}

/// Stateless Merkle signatures, as described in Section 14.6.3
/// in the [textbook](http://toc.cryptobook.us/) by Boneh & Shoup.
///
/// Builds a tree of depth `depth` and width `q`. For each signature,
/// a pseudo-random path is selected.
/// Then, the signature contains a series of q-indexed signatures,
/// each signing the public key of the next one. The leaf node signs
/// the hash of the message.
///
/// # Examples
///
/// ```
/// use hash_based_signatures::signature::stateless_merkle::StatelessMerkleSignatureScheme;
/// use hash_based_signatures::signature::SignatureScheme;
/// use hash_based_signatures::signature::winternitz::domination_free_function::D;
///
/// let mut signature_scheme = StatelessMerkleSignatureScheme::new([0; 32], 16, 5, D::new(255));
/// let signature0 = signature_scheme.sign([0u8; 32]);
/// let signature1 = signature_scheme.sign([1u8; 32]);
///
/// assert!(StatelessMerkleSignatureScheme::verify(
///     signature_scheme.public_key(),
///     [0u8; 32],
///     &signature0
/// ));
/// assert!(StatelessMerkleSignatureScheme::verify(
///     signature_scheme.public_key(),
///     [1u8; 32],
///     &signature1
/// ));
/// assert!(!StatelessMerkleSignatureScheme::verify(
///     signature_scheme.public_key(),
///     [2u8; 32],
///     &signature1
/// ));
/// ```
pub struct StatelessMerkleSignatureScheme {
    seed: HashType,
    seed_prf_key: HashType,
    path_prf_key: HashType,
    root_signature: QIndexedSignatureScheme,
    q: usize,
    depth: usize,
    d: D,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct StatelessMerkleSignature {
    public_key_signatures: Vec<(HashType, QIndexedSignature)>,
    message_signature: QIndexedSignature,
}

impl Debug for StatelessMerkleSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut result = String::from("Stateless signature:\n");
        for (message, signature) in &self.public_key_signatures {
            result += &format!(
                "- ({}, {})\n",
                signature.proof.index,
                HEXLOWER.encode(message)
            );
        }
        result += &format!(
            "- ({}, <hashed message>)\n",
            self.message_signature.proof.index,
        );
        write!(f, "{}", result)
    }
}

impl StatelessMerkleSignatureScheme {
    /// Instantiates the new stateless Merkle signature scheme as a tree with width `q` and depth `depth`.
    ///
    /// The resulting tree will have `q**depth` leafs. Because the scheme is broken if the same leaf is
    /// chosen for two different messages, the expected number of signed messages should not exceed
    /// `sqrt(q**depth)`.
    ///
    /// # Panics
    ///
    /// Panics if `q` is not a power of two.
    pub fn new(seed: HashType, q: usize, depth: usize, d: D) -> Self {
        // Derive keys by using HMAC as a PRF
        let root_seed = hmac(&seed, &[0]);
        let seed_prf_key = hmac(&seed, &[1]);
        let path_prf_key = hmac(&seed, &[2]);
        Self {
            seed,
            root_signature: QIndexedSignatureScheme::new(q, root_seed, d),
            seed_prf_key,
            path_prf_key,
            q,
            depth,
            d,
        }
    }

    pub fn from_private_key(key: &StatelessMerklePrivateKey) -> Self {
        Self::new(
            string_to_hash(&key.seed_hex),
            key.width,
            key.depth,
            D::new(key.d),
        )
    }

    pub fn private_key(&self) -> StatelessMerklePrivateKey {
        StatelessMerklePrivateKey {
            seed_hex: HEXLOWER.encode(&self.seed),
            public_key: HEXLOWER.encode(&self.public_key()),
            width: self.q,
            depth: self.depth,
            d: self.d.d,
        }
    }

    fn signature_scheme(&self, path: &[usize]) -> QIndexedSignatureScheme {
        if path.len() == 0 {
            self.root_signature.clone()
        } else {
            let path_bytes: Vec<u8> = path.iter().map(|x| x.to_be_bytes()).flatten().collect();
            let seed = hmac(&self.seed_prf_key, &path_bytes);
            QIndexedSignatureScheme::new(self.q, seed, self.d)
        }
    }
}

impl SignatureScheme<HashType, HashType, StatelessMerkleSignature>
    for StatelessMerkleSignatureScheme
{
    fn public_key(&self) -> HashType {
        self.root_signature.public_key()
    }

    fn sign(&mut self, message: HashType) -> StatelessMerkleSignature {
        // Generate pseudo-random path, using hmac(path_prf_key, message) as the seed
        let mut rng = ChaCha20Rng::from_seed(hmac(&self.path_prf_key, &message));
        let path: Vec<usize> = (0..self.depth).map(|_| rng.gen_range(0..self.q)).collect();

        let mut public_key_signatures = Vec::with_capacity(self.depth);
        let mut current_signing_scheme = self.root_signature.clone();
        for (path_index, signature_index) in path.iter().enumerate() {
            // Internal node, instantiate next indexed signature and sign its public key
            let next_signature_scheme = self.signature_scheme(&path[..path_index + 1]);
            let one_time_signature =
                current_signing_scheme.sign((*signature_index, next_signature_scheme.public_key()));

            public_key_signatures.push((next_signature_scheme.public_key(), one_time_signature));
            current_signing_scheme = next_signature_scheme;
        }

        // Even though the message might be a hash already, hash it again to prevent extension attacks:
        // Otherwise an adversary could create his own q-indexed public key, trick the signer to
        // sign it and then extend the signature to sign arbitrary messages.
        let hashed_message = hash(&message);

        // Leaf node, sign message
        let message_signature =
            current_signing_scheme.sign((*path.last().unwrap(), hashed_message));

        StatelessMerkleSignature {
            public_key_signatures,
            message_signature,
        }
    }

    fn verify(pk: HashType, message: HashType, signature: &StatelessMerkleSignature) -> bool {
        let mut current_public_key = pk;

        // Verify public keys along path
        for (public_key, one_time_signature) in &signature.public_key_signatures {
            if !QIndexedSignatureScheme::verify(
                current_public_key,
                (one_time_signature.proof.index, *public_key),
                one_time_signature,
            ) {
                return false;
            }
            current_public_key = *public_key;
        }

        // Verify message signature
        QIndexedSignatureScheme::verify(
            current_public_key,
            (signature.message_signature.proof.index, hash(&message)),
            &signature.message_signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::signature::stateless_merkle::StatelessMerkleSignatureScheme;
    use crate::signature::winternitz::domination_free_function::D;
    use crate::signature::SignatureScheme;

    fn get_signature_scheme() -> StatelessMerkleSignatureScheme {
        let seed = [0u8; 32];
        StatelessMerkleSignatureScheme::new(seed, 16, 5, D::new(255))
    }

    #[test]
    fn test_correct_signature() {
        let mut signature_scheme = get_signature_scheme();
        let signature = signature_scheme.sign([1u8; 32]);
        assert!(StatelessMerkleSignatureScheme::verify(
            signature_scheme.public_key(),
            [1u8; 32],
            &signature
        ))
    }

    #[test]
    fn is_deterministic() {
        let mut signature_scheme = get_signature_scheme();
        let signature1 = signature_scheme.sign([1u8; 32]);
        let signature2 = signature_scheme.sign([1u8; 32]);
        assert_eq!(signature1, signature2)
    }

    #[test]
    fn test_incorrect_signature() {
        let mut signature_scheme = get_signature_scheme();
        let signature = signature_scheme.sign([1u8; 32]);
        assert!(!StatelessMerkleSignatureScheme::verify(
            signature_scheme.public_key(),
            [2u8; 32],
            &signature
        ))
    }
}
