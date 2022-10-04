use crate::utils::get_least_significant_bits;
use data_encoding::HEXLOWER;
use hmac_sha256::Hash;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::str::from_utf8;

/// A Merkle tree.
///
/// # Examples
/// ```
/// use hash_based_signatures::merkle_tree::MerkleTree;
///
/// let elements = (0u8..128).map(|x| vec![x]).collect();
/// let tree = MerkleTree::new(elements);
/// let proof = tree.get_proof(17);
/// assert!(proof.verify(*tree.get_root_hash()));
/// ```
#[derive(Clone)]
pub struct MerkleTree {
    root_hash: [u8; 32],
    root_node: Node,
    depth: usize,
}

#[derive(Clone)]
enum Node {
    Leaf(Vec<u8>),
    InternalNode(Box<MerkleTree>, Box<MerkleTree>),
}

/// A proof that a given datum is at a given index.
#[derive(PartialEq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub data: Vec<u8>,
    pub index: usize,
    pub hash_chain: Vec<[u8; 32]>,
}

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    // For leafs, we need to use a different hash function for security:
    // https://crypto.stackexchange.com/questions/2106/what-is-the-purpose-of-using-different-hash-functions-for-the-leaves-and-interna
    // So, we append a zero to all leafes before hashing them
    let zero = [0u8];
    let all_elements = [data, &zero as &[u8]].concat();
    Hash::hash(&all_elements)
}

pub fn internal_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let all_elements = [*left, *right].concat();
    Hash::hash(&all_elements)
}

impl MerkleTree {
    /// Construct a new Merkle tree from a list of `elements`.
    ///
    /// A single element is of type `Vec<u8>`, so any complex data structure has
    /// to be serialized to a variable-length byte array.
    /// The tree owns the values.
    ///
    /// # Panics
    ///
    /// Panics if the number of elements is not a power of two.
    pub fn new(elements: Vec<Vec<u8>>) -> MerkleTree {
        let depth = (elements.len() as f64).log2() as usize;

        let mut elements = elements;

        if 1 << depth != elements.len() {
            panic!(
                "Number of elements needs to be a power of 2, got {}",
                elements.len()
            )
        }

        let (root_node, root_hash) = if elements.len() == 1 {
            let element_hash = leaf_hash(&elements[0]);
            (Node::Leaf(elements.pop().unwrap()), element_hash)
        } else {
            let mid = elements.len() / 2;
            let elements_right = elements.split_off(mid);
            let left_tree = Box::new(MerkleTree::new(elements));
            let right_tree = Box::new(MerkleTree::new(elements_right));

            let root_hash = internal_node_hash(&left_tree.root_hash, &right_tree.root_hash);
            let root_node = Node::InternalNode(left_tree, right_tree);

            (root_node, root_hash)
        };

        MerkleTree {
            root_hash,
            root_node,
            depth,
        }
    }

    /// Get the root hash of the tree.
    pub fn get_root_hash(&self) -> &[u8; 32] {
        &self.root_hash
    }

    /// Get a Merkle proof for a given index `i`.
    pub fn get_proof(&self, i: usize) -> MerkleProof {
        assert!(i < 1 << self.depth);

        match &self.root_node {
            Node::Leaf(element) => MerkleProof {
                data: element.clone(),
                index: i,
                hash_chain: vec![],
            },
            Node::InternalNode(left_tree, right_tree) => {
                let mut proof = if i < 1 << (self.depth - 1) {
                    // Element is in left child
                    let mut proof = left_tree.get_proof(i);
                    proof.hash_chain.push(right_tree.root_hash);
                    proof
                } else {
                    // Element is in left child
                    let mut proof = right_tree.get_proof(i - (1 << (self.depth - 1)));
                    proof.hash_chain.push(left_tree.root_hash);
                    proof
                };
                proof.index = i;
                proof
            }
        }
    }

    fn representation_string(&self, indent: usize) -> String {
        let mut result = String::new();
        let indent_str = "  ".repeat(indent).to_string();
        result += &format!("{}{}\n", indent_str, HEXLOWER.encode(&self.root_hash));

        match &self.root_node {
            Node::Leaf(data) => {
                result += &format!("{}  Data: {}\n", indent_str, from_utf8(data).unwrap());
            }
            Node::InternalNode(left, right) => {
                result += &left.representation_string(indent + 1);
                result += &right.representation_string(indent + 1);
            }
        }

        result
    }
}

impl Debug for MerkleTree {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.representation_string(0))
    }
}

impl<'a> MerkleProof {
    /// Verifies that the given root hash can be reconstructed from the Merkle proof.
    pub fn verify(&self, root_hash: [u8; 32]) -> bool {
        let index_bits = get_least_significant_bits(self.index, self.hash_chain.len());
        let mut expected_root_hash = leaf_hash(&self.data);
        for (hash, index_bit) in self.hash_chain.iter().zip(index_bits.iter().rev()) {
            expected_root_hash = match index_bit {
                false => internal_node_hash(&expected_root_hash, hash),
                true => internal_node_hash(hash, &expected_root_hash),
            }
        }

        expected_root_hash == root_hash
    }
}

impl Debug for MerkleProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut representation = format!(
            "Data: {}\nIndex: {}\nProof:\n",
            from_utf8(&self.data).unwrap(),
            self.index
        );
        for hash in self.hash_chain.iter() {
            representation += &format!("  {}\n", HEXLOWER.encode(hash));
        }
        write!(f, "{}", representation)
    }
}

#[cfg(test)]
mod tests {
    use crate::merkle_tree::{MerkleProof, MerkleTree};

    fn merkle_tree() -> MerkleTree {
        let elements = (0u8..128).map(|x| vec![x]).collect();
        MerkleTree::new(elements)
    }

    #[test]
    fn test_valid_proofs() {
        let tree = merkle_tree();
        let proof = tree.get_proof(43);

        assert_eq!(proof.data, vec![43u8]);
        assert!(proof.verify(*tree.get_root_hash()));
    }

    #[test]
    fn test_invalid_proofs() {
        let tree = merkle_tree();
        let proof1 = tree.get_proof(43);
        let proof2 = tree.get_proof(123);

        let invalid_proof_wrong_index = MerkleProof {
            data: proof1.data.clone(),
            hash_chain: proof1.hash_chain.clone(),
            index: proof2.index,
        };
        assert!(!invalid_proof_wrong_index.verify(tree.root_hash));

        let invalid_proof_wrong_hash_chain = MerkleProof {
            data: proof1.data.clone(),
            hash_chain: proof2.hash_chain.clone(),
            index: proof1.index,
        };
        assert!(!invalid_proof_wrong_hash_chain.verify(tree.root_hash));

        let invalid_proof_wrong_index_wrong_hash_chain = MerkleProof {
            data: proof1.data.clone(),
            hash_chain: proof2.hash_chain.clone(),
            index: proof2.index,
        };
        assert!(!invalid_proof_wrong_index_wrong_hash_chain.verify(tree.root_hash));
    }
}
