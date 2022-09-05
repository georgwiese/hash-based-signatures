use hash_based_signatures::merkle_tree::MerkleTree;
use hash_based_signatures::signature::basic_lamport::BasicLamportSignatureScheme;
use hash_based_signatures::signature::q_indexed_signature::QIndexedSignatureScheme;
use hash_based_signatures::signature::SignatureScheme;

fn main() {
    let element_strings: Vec<String> = (0..8).map(|x| format!("{}", x)).collect();
    let elements = element_strings
        .iter()
        .map(|x| Vec::from(x.as_bytes()))
        .collect();
    let tree = MerkleTree::new(elements);
    let root_hash = tree.get_root_hash();

    println!("Merkle Tree:\n{:?}", tree);

    let proof = tree.get_proof(4);
    println!("{:?}", proof);

    // basic lamport
    let mut basic_signature = BasicLamportSignatureScheme::new([0; 32]);
    let signature = basic_signature.sign(*root_hash);
    println!(
        "Verify signature of root {}",
        BasicLamportSignatureScheme::verify(basic_signature.public_key(), *root_hash, &signature)
    );
    println!(
        "Verify signature of garbage {}",
        BasicLamportSignatureScheme::verify(
            basic_signature.public_key(),
            *root_hash,
            &[[0u8; 32]; 256]
        )
    );

    // q-indexed with basic lamport
    let mut q_indexed_basic_lamport = QIndexedSignatureScheme::new(2, [0; 32]);
    let signature0 = q_indexed_basic_lamport.sign((0, *root_hash));
    println!(
        "Verify q-indexed basic lamport index 0 {}",
        QIndexedSignatureScheme::verify(
            q_indexed_basic_lamport.public_key(),
            (0, *root_hash),
            &signature0
        )
    );
    let signature2 = q_indexed_basic_lamport.sign((1, *root_hash));
    println!(
        "Verify q-indexed basic lamport index 1 {}",
        QIndexedSignatureScheme::verify(
            q_indexed_basic_lamport.public_key(),
            (1, *root_hash),
            &signature2
        )
    );
    println!(
        "Verify q-indexed basic lamport index 1 (wrong message) {}",
        QIndexedSignatureScheme::verify(
            q_indexed_basic_lamport.public_key(),
            (0, *root_hash),
            &signature2
        )
    );
}
