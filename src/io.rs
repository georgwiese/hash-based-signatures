use anyhow::Context as _;
use anyhow::Result;
use ring::digest::{Context, Digest, SHA256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn hash_file(path: &Path) -> Result<Digest> {
    let mut reader = File::open(path)
        .with_context(|| format!("Failed to open file at {:?}. Does it exist?", path))?;
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader
            .read(&mut buffer)
            .with_context(|| format!("Cannot read file at {:?}.", path))?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}
