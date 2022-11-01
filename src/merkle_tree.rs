use crate::signature::HashType;
use crate::utils::{get_least_significant_bits, hash};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

/// A Merkle tree.
///
/// # Examples
/// ```
/// use hash_based_signatures::merkle_tree::MerkleTree;
///
/// let elements = (0..128).collect();
/// let tree = MerkleTree::new(elements);
/// let proof = tree.get_proof(17);
/// assert!(proof.verify(*tree.get_root_hash(), &17));
/// ```
#[derive(Clone)]
pub struct MerkleTree<T: Serialize> {
    root_hash: [u8; 32],
    root_node: Node<T>,
    depth: usize,

    /// Phantom to keep the information of the element type.
    phantom: PhantomData<T>,
}

#[derive(Clone)]
enum Node<T: Serialize> {
    Leaf(),
    InternalNode(Box<MerkleTree<T>>, Box<MerkleTree<T>>),
}

/// A proof that a given datum is at a given index.
/// Note that the proof does not store the data itself, but it needs to be
/// provided to `MerkleProof::verify()`.
#[derive(PartialEq, Serialize, Deserialize)]
pub struct MerkleProof<T: Serialize> {
    /// The index of the datum for which this is the proof.
    pub index: usize,
    /// Hash chain leading up to the root node
    pub hash_chain: Vec<[u8; 32]>,

    /// Phantom to keep the information of the element type.
    phantom: PhantomData<T>,
}

/// Hash function applied to leaves of the Merkle tree
///
/// # Panics
/// Panics if the data can't be serialized.
pub fn leaf_hash<T: Serialize>(data: &T) -> [u8; 32] {
    let data = rmp_serde::to_vec(data).expect("Failed to serialize data");

    // For leafs, we need to use a different hash function for security:
    // https://crypto.stackexchange.com/questions/2106/what-is-the-purpose-of-using-different-hash-functions-for-the-leaves-and-interna
    // So, we append a zero to all leaves before hashing them
    let zero = [0u8];
    let all_elements = [&data, &zero as &[u8]].concat();
    hash(&all_elements)
}

/// Hash function applied to internal nodes of the Merkle tree
pub fn internal_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let all_elements = [*left, *right].concat();
    hash(&all_elements)
}

impl<T: Serialize + Debug> MerkleTree<T> {
    /// Construct a new Merkle tree from a list of `elements`.
    ///
    /// A single element is of type `Vec<u8>`, so any complex data structure has
    /// to be serialized to a variable-length byte array.
    /// The tree owns the values.
    ///
    /// # Panics
    ///
    /// Panics if the number of elements is not a power of two or if the provided data can't be serialized.
    pub fn new(elements: &[T]) -> MerkleTree<T> {
        let depth = (elements.len() as f64).log2() as usize;

        if 1 << depth != elements.len() {
            panic!(
                "Number of elements needs to be a power of 2, got {}",
                elements.len()
            )
        }

        let (root_node, root_hash) = if elements.len() == 1 {
            let element_hash = leaf_hash(&elements[0]);
            (Node::Leaf(), element_hash)
        } else {
            let mid = elements.len() / 2;
            let elements_left = &elements[..mid];
            let elements_right = &elements[mid..];
            let left_tree = Box::new(MerkleTree::new(elements_left));
            let right_tree = Box::new(MerkleTree::new(elements_right));

            let root_hash = internal_node_hash(&left_tree.root_hash, &right_tree.root_hash);
            let root_node = Node::InternalNode(left_tree, right_tree);

            (root_node, root_hash)
        };

        MerkleTree {
            root_hash,
            root_node,
            depth,
            phantom: PhantomData,
        }
    }

    /// Get the root hash of the tree.
    pub fn get_root_hash(&self) -> &[u8; 32] {
        &self.root_hash
    }

    /// Get a Merkle proof for a given index `i`.
    pub fn get_proof(&self, i: usize) -> MerkleProof<T> {
        assert!(i < 1 << self.depth);

        match &self.root_node {
            Node::Leaf() => MerkleProof {
                index: i,
                hash_chain: vec![],
                phantom: PhantomData,
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
            Node::Leaf() => {
                result += &format!("{}  Leaf\n", indent_str);
            }
            Node::InternalNode(left, right) => {
                result += &left.representation_string(indent + 1);
                result += &right.representation_string(indent + 1);
            }
        }

        result
    }
}

impl<T: Serialize + Debug> Debug for MerkleTree<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.representation_string(0))
    }
}

impl<T: Serialize> MerkleProof<T> {
    /// Verifies that the given root hash can be reconstructed from the Merkle proof.
    ///
    /// # Panics
    /// Panics if the data can't be serialized.
    pub fn verify(&self, root_hash: HashType, data: &T) -> bool {
        let index_bits = get_least_significant_bits(self.index, self.hash_chain.len());
        let mut expected_root_hash = leaf_hash(data);
        for (hash, index_bit) in self.hash_chain.iter().zip(index_bits.iter().rev()) {
            expected_root_hash = match index_bit {
                false => internal_node_hash(&expected_root_hash, hash),
                true => internal_node_hash(hash, &expected_root_hash),
            }
        }

        expected_root_hash == root_hash
    }
}

impl<T: Serialize> Debug for MerkleProof<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut representation = format!("Index: {}\nProof:\n", self.index);
        for hash in self.hash_chain.iter() {
            representation += &format!("  {}\n", HEXLOWER.encode(hash));
        }
        write!(f, "{}", representation)
    }
}

#[cfg(test)]
mod tests {
    use crate::merkle_tree::{MerkleProof, MerkleTree};
    use std::marker::PhantomData;

    fn merkle_tree() -> MerkleTree<Vec<u8>> {
        let elements: Vec<Vec<u8>> = (0u8..128).map(|x| vec![x]).collect();
        MerkleTree::new(&elements)
    }

    #[test]
    fn test_valid_proofs() {
        let tree = merkle_tree();
        let proof = tree.get_proof(43);

        assert!(proof.verify(*tree.get_root_hash(), &vec![43]));
    }

    #[test]
    fn test_invalid_proofs() {
        let tree = merkle_tree();
        let proof1 = tree.get_proof(43);
        let proof2 = tree.get_proof(123);

        let invalid_proof_wrong_index = MerkleProof {
            hash_chain: proof1.hash_chain.clone(),
            index: proof2.index,
            phantom: PhantomData,
        };
        assert!(!invalid_proof_wrong_index.verify(tree.root_hash, &vec![43]));

        let invalid_proof_wrong_hash_chain = MerkleProof {
            hash_chain: proof2.hash_chain.clone(),
            index: proof1.index,
            phantom: PhantomData,
        };
        assert!(!invalid_proof_wrong_hash_chain.verify(tree.root_hash, &vec![43]));

        let invalid_proof_wrong_data = MerkleProof {
            hash_chain: proof2.hash_chain.clone(),
            index: proof2.index,
            phantom: PhantomData,
        };
        assert!(!invalid_proof_wrong_data.verify(tree.root_hash, &vec![43]));
    }

    #[test]
    fn test_works_with_complex_data() {
        let elements: Vec<(u32, u32, (u32,))> = (0..128).map(|x| (x, x + 1, (x + 2,))).collect();
        let tree = MerkleTree::new(&elements);
        let proof = tree.get_proof(43);
        assert!(proof.verify(*tree.get_root_hash(), &(43, 44, (45,))));
    }
}
