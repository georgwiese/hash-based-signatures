use crate::merkle_tree::{MerkleProof, MerkleTree};
use crate::signature::basic_lamport::{BasicLamportSignature, BasicLamportSignatureScheme};
use crate::signature::{HashType, SignatureScheme};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

pub struct QIndexedSignatureScheme {
    one_time_signatures: Vec<BasicLamportSignatureScheme>,
    public_key_merkle_tree: MerkleTree,
}

impl QIndexedSignatureScheme {
    pub fn new(q: usize, seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut seed_for_sub_scheme: [u8; 32] = [0; 32];
        let mut one_time_signatures = Vec::new();
        for _ in 0..q {
            rng.fill_bytes(&mut seed_for_sub_scheme);
            one_time_signatures.push(BasicLamportSignatureScheme::new(seed_for_sub_scheme));
        }

        let public_keys_flat: Vec<Vec<u8>> = one_time_signatures
            .iter()
            .map(|s| Vec::from(s.public_key().concat().concat()))
            .collect();

        let public_key_merkle_tree = MerkleTree::new(public_keys_flat);

        Self {
            one_time_signatures,
            public_key_merkle_tree,
        }
    }
}

impl SignatureScheme<HashType, (usize, HashType), (usize, MerkleProof, BasicLamportSignature)>
    for QIndexedSignatureScheme
{
    fn public_key(&self) -> HashType {
        *self.public_key_merkle_tree.get_root_hash()
    }

    fn sign(&mut self, message: (usize, HashType)) -> (usize, MerkleProof, BasicLamportSignature) {
        let (q, message) = message;
        let proof = self.public_key_merkle_tree.get_proof(q);
        (q, proof, self.one_time_signatures[q].sign(message))
    }

    fn verify(
        pk: HashType,
        message: (usize, HashType),
        signature: &(usize, MerkleProof, BasicLamportSignature),
    ) -> bool {
        let (q_m, message) = message;
        let (q_s, proof, signature) = signature;

        if q_m != *q_s {
            return false;
        }

        if !proof.verify(pk) {
            return false;
        }

        // Parse Basic Lamport public key
        // TODO: I'm sure there is a better way...
        let mut basic_lamport_key = [[[0u8; 32]; 2]; 256];
        assert_eq!(proof.data.len(), 32 * 2 * 256);
        for i in 0..256 {
            for j in 0..2 {
                for k in 0..32 {
                    let index = i * 32 * 2 + j * 32 + k;
                    basic_lamport_key[i][j][k] = proof.data[index];
                }
            }
        }

        BasicLamportSignatureScheme::verify(basic_lamport_key, message, signature)
    }
}
