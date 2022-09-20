use hash_based_signatures::merkle_tree::{MerkleProof, MerkleTree};
use hash_based_signatures::signature::stateless_merkle::{
    StatelessMerklePrivateKey, StatelessMerkleSignatureScheme,
};
use hash_based_signatures::signature::{HashType, SignatureScheme};
use hash_based_signatures::utils::hash_to_string;
use hmac_sha256::Hash;
use rand;
use rand::RngCore;
use rmp_serde;
use serde::Deserializer;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn keygen(width: usize, depth: usize) {
    let mut seed = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut seed);

    let private_key = StatelessMerklePrivateKey { seed, width, depth };
    let public_key = StatelessMerkleSignatureScheme::from_private_key(&private_key).public_key();

    let private_key_json = serde_json::to_string(&private_key).unwrap();
    let output_path = ".private_key.json";
    fs::write(output_path, private_key_json);

    println!("Public key:       {}", hash_to_string(&public_key));
    println!("Private key path: {}", output_path);
}

fn sign(path: PathBuf) {
    let data = fs::read(&path).expect("Unable to read file");
    let private_key_json = fs::read_to_string(".private_key.json").unwrap();
    let private_key = serde_json::from_str(&private_key_json).unwrap();

    let file_hash = Hash::hash(&data);
    let mut signature_scheme = StatelessMerkleSignatureScheme::from_private_key(&private_key);

    println!("Signing file:   {}", &path.to_str().unwrap());
    println!("Hash:           {}", hash_to_string(&file_hash));
    println!(
        "Public key:     {}",
        hash_to_string(&signature_scheme.public_key())
    );
    let signature = signature_scheme.sign(file_hash);

    let output_path = format!("{}.signature", path.to_str().unwrap());
    println!("Signature path: {}", output_path);

    let signature_bytes = rmp_serde::to_vec(&signature).unwrap();
    fs::write(output_path, &signature_bytes).expect("Could not write signature");
}

fn main() {
    keygen(16, 5);
    sign(PathBuf::from("Cargo.toml"));
}
