use crate::MerkleTree::{InternalNode, Leaf};
use orion::hash::{digest, Digest};

pub enum MerkleTree {
    Leaf([u8; 32]),
    InternalNode(Box<MerkleTree>, Box<MerkleTree>),
}

fn digest_to_bytes(digest: Digest) -> [u8; 32] {
    assert_eq!(digest.len(), 32);

    let mut res: [u8; 32] = [0; 32];
    for i in 0..32 {
        res[i] = digest.as_ref()[i];
    }
    res
}

impl MerkleTree {
    pub fn new(elements: &[[u8; 32]]) -> MerkleTree {
        let depth = (elements.len() as f64).log2() as u8;
        assert_eq!(1 << depth, elements.len());

        if elements.len() == 1 {
            Leaf(elements[0])
        } else {
            let mid = elements.len() / 2;
            InternalNode(
                Box::new(MerkleTree::new(&elements[0..mid])),
                Box::new(MerkleTree::new(&elements[mid..])),
            )
        }
    }

    pub fn root(&self) -> [u8; 32] {
        match self {
            Leaf(element) => *element,
            InternalNode(left, right) => {
                let all_elements = [left.root(), right.root()].concat();
                digest_to_bytes(digest(&all_elements).unwrap())
            }
        }
    }
}
