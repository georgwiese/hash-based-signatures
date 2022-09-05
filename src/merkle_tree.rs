use crate::digest_to_bytes::digest_to_bytes;
use orion::hash::digest;

enum Direction {
    Left,
    Right,
}

pub struct MerkleProof<'a> {
    data: &'a [u8],
    hash_chain: Vec<(Direction, [u8; 32])>,
    root_hash: [u8; 32],
}

enum Node<'a> {
    Leaf(&'a [u8; 32]),
    InternalNode(Box<MerkleTree<'a>>, Box<MerkleTree<'a>>),
}

pub struct MerkleTree<'a> {
    root_hash: [u8; 32],
    root_node: Node<'a>,
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

impl<'a> MerkleTree<'a> {
    pub fn new(elements: &'a [[u8; 32]]) -> MerkleTree {
        let depth = (elements.len() as f64).log2() as usize;

        if 1 << depth != elements.len() {
            panic!(
                "Number of elements needs to be a power of 2, got {}",
                elements.len()
            )
        }

        let (root_node, root_hash) = if elements.len() == 1 {
            (Node::Leaf(&elements[0]), leaf_hash(&elements[0]))
        } else {
            let mid = elements.len() / 2;
            let left_tree = Box::new(MerkleTree::new(&elements[0..mid]));
            let right_tree = Box::new(MerkleTree::new(&elements[mid..]));

            let root_node = Node::InternalNode(
                Box::new(MerkleTree::new(&elements[0..mid])),
                Box::new(MerkleTree::new(&elements[mid..])),
            );
            let root_hash = internal_node_hash(&left_tree.root_hash, &right_tree.root_hash);

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
                data: *element,
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
                    let mut proof = right_tree.get_proof(i - 1 << (self.depth - 1));
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
}

impl<'a> MerkleProof<'a> {
    pub fn verify(&self) -> bool {
        let mut expected_root_hash = leaf_hash(self.data);
        for (direction, hash) in &self.hash_chain {
            expected_root_hash = match direction {
                Direction::Left => internal_node_hash(hash, &expected_root_hash),
                Direction::Right => internal_node_hash(&expected_root_hash, hash),
            }
        }

        expected_root_hash == self.root_hash
    }
}
