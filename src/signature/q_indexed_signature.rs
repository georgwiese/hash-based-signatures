use crate::merkle_tree::{MerkleProof, MerkleTree};
use crate::signature::winternitz::d::D;
use crate::signature::winternitz::{WinternitzKey, WinternitzSignature, WinternitzSignatureScheme};
use crate::signature::{HashType, SignatureScheme};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

/// The q-indexed signature scheme, as described in Section 14.6.1
/// in the [textbook](http://toc.cryptobook.us/) by Boneh & Shoup.
///
/// It instantiates `q` one-time signatures schemes (currently `WinternitzSignatureScheme`)
/// and uses it to sign up to `q` messages.
/// To shrink the public key to a single hash, a `MerkleTree` is used:
/// The signatures contains the one-time public key that was used, along with a Merkle
/// proof.
///
/// # Examples
///
/// ```
/// use hash_based_signatures::signature::q_indexed_signature::QIndexedSignatureScheme;
/// use hash_based_signatures::signature::SignatureScheme;
/// use hash_based_signatures::signature::winternitz::d::D;
///
/// let mut signature_scheme = QIndexedSignatureScheme::new(2, [0; 32], D::new(255));
/// let signature0 = signature_scheme.sign((0, [0u8; 32]));
/// let signature1 = signature_scheme.sign((1, [1u8; 32]));
///
/// assert!(QIndexedSignatureScheme::verify(
///     signature_scheme.public_key(),
///     (0, [0u8; 32]),
///     &signature0
/// ));
/// assert!(QIndexedSignatureScheme::verify(
///     signature_scheme.public_key(),
///     (1, [1u8; 32]),
///     &signature1
/// ));
/// ```
#[derive(Clone)]
pub struct QIndexedSignatureScheme {
    one_time_signatures: Vec<WinternitzSignatureScheme>,
    public_key_merkle_tree: MerkleTree,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct QIndexedSignature {
    pub proof: MerkleProof,
    pub one_time_signature: WinternitzSignature,
}

impl QIndexedSignatureScheme {
    /// Builds a q-indexed signature scheme from the given `seed`.
    ///
    /// # Panics
    ///
    /// Panics if `q` is not a power of two.
    pub fn new(q: usize, seed: [u8; 32], d: D) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut seed_for_sub_scheme: [u8; 32] = [0; 32];
        let mut one_time_signatures = Vec::new();
        for _ in 0..q {
            rng.fill_bytes(&mut seed_for_sub_scheme);
            one_time_signatures.push(WinternitzSignatureScheme::new(seed_for_sub_scheme, d));
        }

        let public_keys_flat = one_time_signatures
            .iter()
            .map(|s| Vec::from(s.public_key().concat()))
            .collect();

        let public_key_merkle_tree = MerkleTree::new(public_keys_flat);

        Self {
            one_time_signatures,
            public_key_merkle_tree,
        }
    }
}

impl SignatureScheme<HashType, (usize, HashType), QIndexedSignature> for QIndexedSignatureScheme {
    fn public_key(&self) -> HashType {
        *self.public_key_merkle_tree.get_root_hash()
    }

    /// Signs a message.
    ///
    /// # Panics
    ///
    /// Panics if the scheme is used more than once to sign *different* messages with the
    /// same index.
    /// Note that there could still be a different instance with the same secret key,
    /// which would not be detected.
    fn sign(&mut self, message: (usize, HashType)) -> QIndexedSignature {
        let (i, message) = message;
        let proof = self.public_key_merkle_tree.get_proof(i);
        QIndexedSignature {
            proof,
            one_time_signature: self.one_time_signatures[i].sign(message),
        }
    }

    fn verify(pk: HashType, message: (usize, HashType), signature: &QIndexedSignature) -> bool {
        let (i_m, message) = message;

        if i_m != signature.proof.index {
            return false;
        }

        if !signature.proof.verify(pk) {
            return false;
        }

        // Parse Winternitz key by "reshaping" it from Vec<u8> to Vec<[u8; 32]>
        // TODO: I'm sure there is a better way...
        let mut winternitz_key: WinternitzKey = Vec::new();
        for i in 0..(signature.proof.data.len() / 32) {
            let mut data = [0u8; 32];
            for j in 0..32 {
                data[j] = signature.proof.data[i * 32 + j];
            }
            winternitz_key.push(data);
        }

        WinternitzSignatureScheme::verify(winternitz_key, message, &signature.one_time_signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::signature::q_indexed_signature::QIndexedSignatureScheme;
    use crate::signature::winternitz::d::D;
    use crate::signature::SignatureScheme;

    fn get_signature_scheme() -> QIndexedSignatureScheme {
        let seed = [0u8; 32];
        QIndexedSignatureScheme::new(4, seed, D::new(255))
    }

    #[test]
    fn test_correct_signatures() {
        let mut signature_scheme = get_signature_scheme();

        let signature0 = signature_scheme.sign((0, [0u8; 32]));
        assert!(QIndexedSignatureScheme::verify(
            signature_scheme.public_key(),
            (0, [0u8; 32]),
            &signature0
        ));

        let signature3 = signature_scheme.sign((3, [3u8; 32]));
        assert!(QIndexedSignatureScheme::verify(
            signature_scheme.public_key(),
            (3, [3u8; 32]),
            &signature3
        ))
    }

    #[test]
    fn test_incorrect_signature() {
        let mut signature_scheme = get_signature_scheme();
        let signature = signature_scheme.sign((0, [0u8; 32]));
        assert!(!QIndexedSignatureScheme::verify(
            signature_scheme.public_key(),
            (0, [1u8; 32]), // Different data
            &signature
        ));
        assert!(!QIndexedSignatureScheme::verify(
            signature_scheme.public_key(),
            (1, [0u8; 32]), // Different index
            &signature
        ))
    }

    #[test]
    fn test_can_sign_same_message() {
        let mut signature_scheme = get_signature_scheme();
        signature_scheme.sign((0, [0u8; 32]));
        signature_scheme.sign((0, [0u8; 32]));
    }
}
