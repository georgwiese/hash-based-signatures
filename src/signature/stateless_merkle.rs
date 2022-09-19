use crate::signature::q_indexed_signature::{QIndexedSignature, QIndexedSignatureScheme};
use crate::signature::{HashType, SignatureScheme};
use crate::utils::hash_to_string;
use hmac_sha256::{Hash, HMAC};
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::fmt::{Debug, Formatter};

struct StatelessMerkleSignatureScheme {
    seed_prf_key: HashType,
    path_prf_key: HashType,
    root_signature: QIndexedSignatureScheme,
    q: usize,
    depth: usize,
}

#[derive(PartialEq)]
struct StatelessMerkleSignature {
    public_key_signatures: Vec<(HashType, QIndexedSignature)>,
    message_signature: QIndexedSignature,
}

impl Debug for StatelessMerkleSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut result = String::from("Stateless signature:\n");
        for (message, signature) in &self.public_key_signatures {
            result += &format!("- ({}, {})\n", signature.i, hash_to_string(&message));
        }
        result += &format!("- ({}, <hashed message>)\n", self.message_signature.i,);
        write!(f, "{}", result)
    }
}

impl StatelessMerkleSignatureScheme {
    fn new(seed: HashType, q: usize, depth: usize) -> Self {
        let root_seed = HMAC::mac(&[0], &seed);
        let seed_prf_key = HMAC::mac(&[1], &seed);
        let path_prf_key = HMAC::mac(&[1], &seed);
        Self {
            root_signature: QIndexedSignatureScheme::new(q, root_seed),
            seed_prf_key,
            path_prf_key,
            q,
            depth,
        }
    }

    fn signature_scheme(&self, path: &[usize]) -> QIndexedSignatureScheme {
        if path.len() == 0 {
            self.root_signature.clone()
        } else {
            let path_bytes: Vec<u8> = path.iter().map(|x| x.to_be_bytes()).flatten().collect();
            let seed = HMAC::mac(path_bytes, self.seed_prf_key);
            QIndexedSignatureScheme::new(self.q, seed)
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
        // Generate pseudo-random path, using HMAC(path_prf_key, message) as the seed
        let mut rng = ChaCha20Rng::from_seed(HMAC::mac(&message, self.path_prf_key));
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
        let hashed_message = Hash::hash(&message);

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
                (one_time_signature.i, *public_key),
                one_time_signature,
            ) {
                return false;
            }
            current_public_key = *public_key;
        }

        // Verify message signature
        QIndexedSignatureScheme::verify(
            current_public_key,
            (signature.message_signature.i, Hash::hash(&message)),
            &signature.message_signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::signature::stateless_merkle::StatelessMerkleSignatureScheme;
    use crate::signature::SignatureScheme;

    fn get_signature_scheme() -> StatelessMerkleSignatureScheme {
        let seed = [0u8; 32];
        StatelessMerkleSignatureScheme::new(seed, 16, 5)
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
