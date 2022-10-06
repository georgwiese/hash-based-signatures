use crate::io::hash_file;
use crate::signature::stateless_merkle::StatelessMerkleSignatureScheme;
use crate::signature::winternitz::domination_free_function::D;
use crate::signature::{HashType, SignatureScheme};
use crate::utils::{slice_to_hash, string_to_hash};
use anyhow::{bail, Context, Result};
use data_encoding::HEXLOWER;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn timed<F, T>(f: F) -> (Duration, T)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let elapsed_time = start.elapsed();
    (elapsed_time, result)
}

pub fn keygen(width: usize, depth: usize, d: u64) -> Result<()> {
    println!();
    println!(" #######################");
    println!("   Generating key");
    println!(" #######################");
    println!();

    let mut seed = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut seed);

    let d = D::try_from(d)?;
    let (time, signature_scheme) =
        timed(move || StatelessMerkleSignatureScheme::new(seed, width, depth, d));
    println!("  (Key generation took: {:?})\n", time);

    let private_key = signature_scheme.private_key();
    let public_key = signature_scheme.public_key();

    let private_key_json =
        serde_json::to_string_pretty(&private_key).context("Error serializing private key.")?;
    let output_path = ".private_key.json";
    fs::write(output_path, private_key_json).context("Could not write private key.")?;

    println!("Public key:       {}", HEXLOWER.encode(&public_key));
    println!("Private key path: {}", output_path);

    println!(
        "\n\nRemember that you should generate a new key pair well before having \
    signed sqrt(width^depth) messages, which in your case is about {:0.2e}.",
        (width as f32).powf(depth as f32 / 2.0)
    );

    Ok(())
}

pub fn sign(path: PathBuf) -> Result<()> {
    println!();
    println!(" #######################");
    println!("   Signing File");
    println!(" #######################");
    println!();

    let private_key_json =
        fs::read_to_string(".private_key.json").context("Error reading private key")?;
    let private_key =
        serde_json::from_str(&private_key_json).context("Error parsing private key")?;

    let file_hash = hash_file(&path)?;
    let mut signature_scheme = StatelessMerkleSignatureScheme::from_private_key(&private_key)
        .context("Error instantiating signature scheme from private key in .private_key.json.")?;

    if string_to_hash(&private_key.public_key) != signature_scheme.public_key() {
        bail!(
            "The public key referenced in .private_key.json cannot be derived from the private key. \
                This is probably because of an incompatible implementation change. \
                Re-run key generation or manually change the public key to {}",
            HEXLOWER.encode(&signature_scheme.public_key())
        )
    }

    let (time, signature) = timed(|| signature_scheme.sign(slice_to_hash(file_hash.as_ref())));
    println!("  (Signing took: {:?})\n", time);

    println!("File Path:      {}", path.display());
    println!("Hash:           {}", HEXLOWER.encode(file_hash.as_ref()));
    println!(
        "Public key:     {}",
        HEXLOWER.encode(&signature_scheme.public_key())
    );

    let output_path = format!("{}.signature", path.display());
    println!("Signature path: {}", output_path);

    let signature_bytes = rmp_serde::to_vec(&signature).context("Error serializing signature")?;
    fs::write(&output_path, &signature_bytes)
        .with_context(|| format!("Could not write signature to {:?}", output_path))?;

    Ok(())
}

pub fn verify(file_path: PathBuf, signature_path: PathBuf, public_key: HashType) -> Result<bool> {
    println!();
    println!(" #######################");
    println!("   Verifying file");
    println!(" #######################");
    println!();

    let file_hash = hash_file(&file_path)?;

    let signature_bytes = fs::read(&signature_path).with_context(|| {
        format!(
            "Cannot signature file at {:?}. Does it exist?",
            &signature_path
        )
    })?;
    let signature = rmp_serde::from_slice(&signature_bytes)
        .with_context(|| format!("Signature at {:?} is malformed.", &signature_path))?;

    let (time, verifies) = timed(|| {
        StatelessMerkleSignatureScheme::verify(
            public_key,
            slice_to_hash(file_hash.as_ref()),
            &signature,
        )
    });
    println!("  (Verification took: {:?})\n", time);

    println!("File Path:      {}", file_path.display());
    println!("Signature Path: {}", signature_path.display());
    println!("Valid:          {}", verifies);

    Ok(verifies)
}
