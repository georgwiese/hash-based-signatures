use ring::digest::{Context, Digest, SHA256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn hash_file(path: &Path) -> Digest {
    let mut reader = File::open(path).expect("Unable to open file");
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer).expect("Unable to read file");
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    context.finish()
}
