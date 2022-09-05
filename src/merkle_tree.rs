use crate::utils::{digest_to_bytes, hash_to_string};
use orion::hash::digest;
use std::fmt::{Debug, Formatter};
use std::str::from_utf8;

#[derive(Debug)]
enum Direction {
    Left,
    Right,
}

pub struct MerkleProof {
    pub data: Vec<u8>,
    hash_chain: Vec<(Direction, [u8; 32])>,
    root_hash: [u8; 32],
}

enum Node {
    Leaf(Vec<u8>),
    InternalNode(Box<MerkleTree>, Box<MerkleTree>),
}

pub struct MerkleTree {
    root_hash: [u8; 32],
    root_node: Node,
    depth: usize,
}

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    // For leafs, we need to use a different hash function for security:
    // https://crypto.stackexchange.com/questions/2106/what-is-the-purpose-of-using-different-hash-functions-for-the-leaves-and-interna
    // So, we append a zero to all leafes before hashing them
    let zero = [0u8];
    let all_elements = [data, &zero as &[u8]].concat();
    digest_to_bytes(digest(&all_elements).unwrap())
}

pub fn internal_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let all_elements = [*left, *right].concat();
    digest_to_bytes(digest(&all_elements).unwrap())
}

impl MerkleTree {
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

    pub fn get_root_hash(&self) -> &[u8; 32] {
        &self.root_hash
    }

    pub fn get_proof(&self, i: usize) -> MerkleProof {
        assert!(i < 1 << self.depth);

        match &self.root_node {
            Node::Leaf(element) => MerkleProof {
                data: element.clone(),
                hash_chain: vec![],
                root_hash: self.root_hash,
            },
            Node::InternalNode(left_tree, right_tree) => {
                let mut proof = if i < 1 << (self.depth - 1) {
                    // Element is in left child
                    let mut proof = left_tree.get_proof(i);
                    proof
                        .hash_chain
                        .push((Direction::Right, right_tree.root_hash));
                    proof
                } else {
                    // Element is in left child
                    let mut proof = right_tree.get_proof(i - (1 << (self.depth - 1)));
                    proof
                        .hash_chain
                        .push((Direction::Left, left_tree.root_hash));
                    proof
                };
                proof.root_hash = self.root_hash;
                proof
            }
        }
    }

    fn representation_string(&self, indent: usize) -> String {
        let mut result = String::new();
        let indent_str = "  ".repeat(indent).to_string();
        result += &format!("{}{}\n", indent_str, hash_to_string(&self.root_hash));

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
    pub fn verify(&self, root_hash: [u8; 32]) -> bool {
        let mut expected_root_hash = leaf_hash(&self.data);
        for (direction, hash) in &self.hash_chain {
            expected_root_hash = match direction {
                Direction::Left => internal_node_hash(hash, &expected_root_hash),
                Direction::Right => internal_node_hash(&expected_root_hash, hash),
            }
        }

        expected_root_hash == root_hash
    }
}

impl Debug for MerkleProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut representation = format!("Data: {}\nProof:\n", from_utf8(&self.data).unwrap());
        for (direction, hash) in &self.hash_chain {
            representation += &format!("  ({:?}, {})\n", direction, hash_to_string(hash));
        }
        representation += &format!("Verifies: {}", self.verify(self.root_hash));
        write!(f, "{}", representation)
    }
}
