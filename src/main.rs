use hash_based_signatures::merkle_tree::MerkleTree;
use hash_based_signatures::signature::basic_lamport::BasicLamportSignatureScheme;
use hash_based_signatures::signature::{Signature, SignatureScheme};

fn main() {
    let element = [0u8; 32];
    let elements = [element, element, element, element];
    let tree = MerkleTree::new(&elements);
    let root_hash = tree.root();

    for i in root_hash {
        println!("{}", i);
    }
    let basic_signature = BasicLamportSignatureScheme::new([0; 32]);
    let signature = basic_signature.sign(&root_hash);
    println!("Verify signature of root {}", signature.verify(&root_hash));
    println!("Verify signature of garbage {}", signature.verify(&[0; 32]));
}
