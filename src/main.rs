use hash_based_signatures::merkle_tree::MerkleTree;

fn main() {
    let element_strings: Vec<String> = (0..8).map(|x| format!("{}", x)).collect();
    let elements = element_strings
        .iter()
        .map(|x| Vec::from(x.as_bytes()))
        .collect();
    let tree = MerkleTree::new(elements);

    println!("Merkle Tree:\n{:?}", tree);

    let proof = tree.get_proof(4);
    println!("{:?}", proof);
    println!("Verfies: {}", proof.verify(*tree.get_root_hash()));
}
