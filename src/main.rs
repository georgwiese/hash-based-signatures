use clap::{Parser, Subcommand};
use hash_based_signatures::cli::{keygen, sign, verify};
use hash_based_signatures::utils::string_to_hash;
use std::path::PathBuf;

#[derive(Parser)]
#[clap(name = "Hash-based signatures")]
#[clap(version)]
#[clap(author)]
#[clap(about)]
struct Arguments {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new public / private key pair
    KeyGen {
        /// The width of the tree used in Merkle signatures.
        /// This needs to be a power of 2.
        /// The signing time correlates (roughly) linearly with the the width.
        /// The total amount of supported signatures is roughly `sqrt(width^depth)`
        #[clap(default_value_t = 16, long)]
        width: usize,
        /// The depth of the tree used in Merkle signatures.
        /// Both the signing time and signature size correlate linearly with the depth.
        /// The total amount of supported signatures is roughly `sqrt(width^depth)`
        #[clap(default_value_t = 32, long)]
        depth: usize,
        /// The parameter `d` used for Winternitz signatures.
        /// Needs to be of the form `2^(2^x) - 1`, so possible values are: 1, 3, 15, and 255.
        /// Signing time is proportional to `d`, while the signature size is inversely proportional
        /// to `log(d)`.
        #[clap(default_value_t = 15, long)]
        d: u64,
    },
    /// Sign a message
    Sign {
        /// Path of the file to sign. The signature will be placed next to the file.
        path: PathBuf,
    },
    /// Verify a signature
    Verify {
        /// Path of the file to verify
        file_path: PathBuf,
        /// Path of the signature
        signature_path: PathBuf,
        /// Public key (should be a hex-encoded 256-bit hash)
        public_key: String,
    },
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
