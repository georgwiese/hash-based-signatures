use hash_based_signatures::merkle_tree::MerkleTree;
use hash_based_signatures::signature::basic_lamport::{
    BasicLamportSignature, BasicLamportSignatureScheme,
};
use hash_based_signatures::signature::q_indexed_signature::QIndexedSignatureScheme;
use hash_based_signatures::signature::{Signature, SignatureScheme};

fn main() {
    let element = [0u8; 32];
    let elements = [element, element, element, element];
    let tree = MerkleTree::new(&elements);
    let root_hash = tree.root();

    for i in root_hash {
        println!("{}", i);
    }

    // basic lamport
    let basic_signature = BasicLamportSignatureScheme::new([0; 32]);
    let signature = basic_signature.sign(&root_hash);
    println!("Verify signature of root {}", signature.verify(&root_hash));
    println!("Verify signature of garbage {}", signature.verify(&[0; 32]));

    // q-indexed with basic lamport
    let mut q_indexed_basic_lamport: QIndexedSignatureScheme<
        BasicLamportSignatureScheme,
        BasicLamportSignature,
    > = QIndexedSignatureScheme::new(2, [0; 32]);
    let signature = q_indexed_basic_lamport.sign(0, &root_hash);
    println!(
        "Verify q-indexed basic lamport index 0 {}",
        signature.verify(&root_hash)
    );
    let signature = q_indexed_basic_lamport.sign(1, &root_hash);
    println!(
        "Verify q-indexed basic lamport index 1 {}",
        signature.verify(&root_hash)
    );
}
