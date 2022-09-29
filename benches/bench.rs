use criterion::{criterion_group, criterion_main, Bencher, Criterion};

use hash_based_signatures::signature::stateless_merkle::StatelessMerkleSignatureScheme;
use hash_based_signatures::signature::winternitz::domination_free_function::D;
use hash_based_signatures::signature::SignatureScheme;
use rand::prelude::*;

fn key_generation(b: &mut Bencher) {
    b.iter(|| {
        let mut seed = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut seed);
        StatelessMerkleSignatureScheme::new(seed, 16, 32, D::new(255));
    })
}

fn signing(b: &mut Bencher) {
    let mut signature_scheme = StatelessMerkleSignatureScheme::new([0u8; 32], 16, 32, D::new(255));
    b.iter(|| {
        // Sign a random message
        let mut hash = [0u8; 32];
        let mut rng = thread_rng();
        rng.fill_bytes(&mut hash);
        signature_scheme.sign(hash);
    })
}

fn verification(b: &mut Bencher) {
    let mut signature_scheme = StatelessMerkleSignatureScheme::new([0u8; 32], 16, 32, D::new(255));
    let mut hash = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut hash);
    let signature = signature_scheme.sign(hash);
    b.iter(|| {
        StatelessMerkleSignatureScheme::verify(signature_scheme.public_key(), hash, &signature)
    })
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("benches");
    group.sample_size(10);

    group.bench_function("key_generation", key_generation);
    group.bench_function("signing", signing);
    group.bench_function("verification", verification);
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
