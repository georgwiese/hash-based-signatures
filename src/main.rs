use hash_based_signatures::MerkleTree;

fn main() {
    let element = [0u8; 32];
    let elements = [element, element, element, element];
    let tree = MerkleTree::new(&elements);
    let root_hash = tree.root();

    for i in root_hash {
        println!("{}", i);
    }
}
