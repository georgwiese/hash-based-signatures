use orion::hash::{digest, Digest};
use crate::digest_to_bytes::digest_to_bytes;

pub enum MerkleTree {
    Leaf([u8; 32]),
    InternalNode(Box<MerkleTree>, Box<MerkleTree>),
}


impl MerkleTree {
    pub fn new(elements: &[[u8; 32]]) -> MerkleTree {
        let depth = (elements.len() as f64).log2() as u8;
        assert_eq!(1 << depth, elements.len());

        if elements.len() == 1 {
            MerkleTree::Leaf(elements[0])
        } else {
            let mid = elements.len() / 2;
            MerkleTree::InternalNode(
                Box::new(MerkleTree::new(&elements[0..mid])),
                Box::new(MerkleTree::new(&elements[mid..])),
            )
        }
    }

    pub fn root(&self) -> [u8; 32] {
        match self {
            MerkleTree::Leaf(element) => *element,
            MerkleTree::InternalNode(left, right) => {
                let all_elements = [left.root(), right.root()].concat();
                digest_to_bytes(digest(&all_elements).unwrap())
            }
        }
    }
}
