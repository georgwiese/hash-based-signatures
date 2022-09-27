use clap::{Parser, Subcommand};
use hash_based_signatures::signature::stateless_merkle::StatelessMerkleSignatureScheme;
use hash_based_signatures::signature::{HashType, SignatureScheme};
use hash_based_signatures::utils::{hash_to_string, string_to_hash};
use hmac_sha256::Hash;
use rand;
use rand::RngCore;
use rmp_serde;
use std::fs;

use hash_based_signatures::signature::winternitz::domination_free_function::D;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Arguments {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    KeyGen {
        #[clap(default_value_t = 16)]
        width: usize,
        #[clap(default_value_t = 32)]
        depth: usize,
        #[clap(default_value_t = 255)]
        d: u64,
    },
    Sign {
        path: PathBuf,
    },
    Verify {
        file_path: PathBuf,
        signature_path: PathBuf,
        public_key: String,
    },
}

fn keygen(width: usize, depth: usize, d: u64) {
    println!();
    println!(" #######################");
    println!("   Generating key");
    println!(" #######################");
    println!();

    let mut seed = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut seed);

    let signature_scheme = StatelessMerkleSignatureScheme::new(seed, width, depth, D::new(d));
    let private_key = signature_scheme.private_key();
    let public_key = signature_scheme.public_key();

    let private_key_json =
        serde_json::to_string_pretty(&private_key).expect("Error serializing private key");
    let output_path = ".private_key.json";
    fs::write(output_path, private_key_json).expect("Could not write private key");

    println!("Public key:       {}", hash_to_string(&public_key));
    println!("Private key path: {}", output_path);
}

fn sign(path: PathBuf) {
    println!();
    println!(" #######################");
    println!("   Signing File");
    println!(" #######################");
    println!();

    let data = fs::read(&path).expect("Unable to read file");
    let private_key_json =
        fs::read_to_string(".private_key.json").expect("Error reading private key");
    let private_key = serde_json::from_str(&private_key_json).expect("Error parsing private key");

    let file_hash = Hash::hash(&data);
    let mut signature_scheme = StatelessMerkleSignatureScheme::from_private_key(&private_key);

    if string_to_hash(&private_key.public_key) != signature_scheme.public_key() {
        panic!(
            "The public key referenced in .private_key.json cannot be derived from the private key. \
                This is probably because of an incompatible implementation change. \
                Re-run key generation or manually change the public key to {}",
            hash_to_string(&signature_scheme.public_key())
        )
    }

    println!("File Path:      {}", &path.to_str().unwrap());
    println!("Hash:           {}", hash_to_string(&file_hash));
    println!(
        "Public key:     {}",
        hash_to_string(&signature_scheme.public_key())
    );
    let signature = signature_scheme.sign(file_hash);

    let output_path = format!("{}.signature", path.to_str().unwrap());
    println!("Signature path: {}", output_path);

    let signature_bytes = rmp_serde::to_vec(&signature).expect("Error serializing signature");
    fs::write(&output_path, &signature_bytes).expect("Could not write signature");

    // TODO: Remove debug output
    let signature_json =
        serde_json::to_string_pretty(&signature).expect("Error serializing signature");
    fs::write(format!("{}.json", &output_path), signature_json)
        .expect("Could not write signature_json");
}

fn verify(file_path: PathBuf, signature_path: PathBuf, public_key: HashType) -> bool {
    println!();
    println!(" #######################");
    println!("   Verifying file");
    println!(" #######################");
    println!();

    let data = fs::read(&file_path).expect("Unable to read file");
    let file_hash = Hash::hash(&data);

    let signature_bytes = fs::read(&signature_path).expect("Error reading signature");
    let signature = rmp_serde::from_slice(&signature_bytes).expect("Error parsing signature");

    let verifies = StatelessMerkleSignatureScheme::verify(public_key, file_hash, &signature);

    println!("File Path:      {}", &file_path.to_str().unwrap());
    println!("Signature Path: {}", &signature_path.to_str().unwrap());
    println!("Valid:          {}", verifies);

    verifies
}

fn main() {
    let args: Arguments = Arguments::parse();

    match args.command {
        Commands::KeyGen { width, depth, d } => keygen(width, depth, d),
        Commands::Sign { path } => sign(path),
        Commands::Verify {
            file_path,
            signature_path,
            public_key,
        } => {
            verify(file_path, signature_path, string_to_hash(&public_key));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::verify;
    use hash_based_signatures::utils::string_to_hash;
    use std::path::PathBuf;

    #[test]
    fn example_verifies() {
        let verifies = verify(
            PathBuf::from("example/readme.md"),
            PathBuf::from("example/readme.md.signature"),
            string_to_hash(&String::from(
                "d4c280791e7712789c21babb323c8b9ab5631f36bcef75c8ec4a2466d69057fe",
            )),
        );
        assert!(verifies)
    }
}
