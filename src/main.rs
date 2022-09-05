use hash_based_signatures::merkle_tree::MerkleTree;
use hash_based_signatures::signature::basic_lamport::{
    BasicLamportSignature, BasicLamportSignatureScheme,
};
use hash_based_signatures::signature::q_indexed_signature::QIndexedSignatureScheme;
use hash_based_signatures::signature::{Signature, SignatureScheme};

fn main() {
    let element_strings: Vec<String> = (0..8).map(|x| format!("{}", x)).collect();
    let elements = element_strings
        .iter()
        .map(|x| x.as_bytes())
        .collect::<Vec<&[u8]>>();
    let tree = MerkleTree::new(&elements);
    let root_hash = tree.get_root_hash();

    println!("Merkle Tree:\n{:?}", tree);

    let proof = tree.get_proof(4);
    println!("{:?}", proof);

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
