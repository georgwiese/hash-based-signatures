use crate::merkle_tree::MerkleProof;
use crate::signature::basic_lamport::BasicLamportSignature;
use crate::signature::q_indexed_signature::QIndexedSignatureScheme;
use crate::signature::{HashType, SignatureScheme};
use rand::{thread_rng, Rng};

struct StatelessMerkleSignature {
    root_signature: QIndexedSignatureScheme,
    q: usize,
    depth: usize,
}

impl StatelessMerkleSignature {
    fn new(seed: HashType, q: usize, depth: usize) -> Self {
        Self {
            root_signature: QIndexedSignatureScheme::new(q, seed),
            q,
            depth,
        }
    }

    fn signature_scheme(&self, path: &[usize]) -> QIndexedSignatureScheme {
        if path.len() == 0 {
            self.root_signature.clone()
        } else {
            // TODO: Derive seed from PRF as F(self.seed, path)
            let seed = [0u8; 32];
            QIndexedSignatureScheme::new(self.q, seed)
        }
    }
}

impl
    SignatureScheme<
        HashType,
        HashType,
        Vec<(HashType, (usize, MerkleProof, BasicLamportSignature))>,
    > for StatelessMerkleSignature
{
    fn public_key(&self) -> HashType {
        self.root_signature.public_key()
    }

    fn sign(
        &mut self,
        message: HashType,
    ) -> Vec<(HashType, (usize, MerkleProof, BasicLamportSignature))> {
        // Generate random path
        let mut rng = thread_rng();
        let path: Vec<usize> = (0..self.depth).map(|_| rng.gen_range(0..self.q)).collect();

        let mut signature = Vec::with_capacity(self.depth);
        let mut current_signing_scheme = self.root_signature.clone();
        for (path_index, signature_index) in path.iter().enumerate() {
            if path_index < path.len() - 1 {
                // Internal node, instantiate next indexed signature and sign its public key
                let next_signature_scheme = self.signature_scheme(&path[..path_index + 1]);
                let one_time_signature = current_signing_scheme
                    .sign((*signature_index, next_signature_scheme.public_key()));

                signature.push((next_signature_scheme.public_key(), one_time_signature));
                current_signing_scheme = next_signature_scheme;
            } else {
                // Leaf node, sign message
                let one_time_signature = current_signing_scheme.sign((*signature_index, message));
                signature.push((message, one_time_signature));
            }
        }

        signature
    }

    fn verify(
        pk: HashType,
        message: HashType,
        signature: &Vec<(HashType, (usize, MerkleProof, BasicLamportSignature))>,
    ) -> bool {
        // TODO: Do I have to verify depth and q?

        for (current_message, one_time_signature) in signature {
            if !QIndexedSignatureScheme::verify(
                pk,
                (one_time_signature.0, *current_message),
                one_time_signature,
            ) {
                return false;
            }
        }

        // All signatures are valid, now check that the last message is actually correct
        signature[signature.len() - 1].0 == message
    }
}

#[cfg(test)]
mod tests {
    use crate::signature::stateless_merkle::StatelessMerkleSignature;
    use crate::signature::SignatureScheme;

    fn get_signature_scheme() -> StatelessMerkleSignature {
        let seed = [0u8; 32];
        StatelessMerkleSignature::new(seed, 16, 5)
    }

    #[test]
    fn test_correct_signature() {
        let mut signature_scheme = get_signature_scheme();
        let signature = signature_scheme.sign([1u8; 32]);
        assert!(StatelessMerkleSignature::verify(
            signature_scheme.public_key(),
            [1u8; 32],
            &signature
        ))
    }

    #[test]
    fn test_incorrect_signature() {
        // TODO
    }
}
