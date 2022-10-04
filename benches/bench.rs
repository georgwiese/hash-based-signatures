use criterion::{criterion_group, criterion_main, Bencher, Criterion};

use hash_based_signatures::signature::stateless_merkle::StatelessMerkleSignatureScheme;
use hash_based_signatures::signature::winternitz::domination_free_function::D;
use hash_based_signatures::signature::{HashType, SignatureScheme};
use rand::prelude::*;

fn get_random_256bits() -> HashType {
    let mut result = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut result);
    result
}

fn make_signature_scheme() -> StatelessMerkleSignatureScheme {
    let seed = get_random_256bits();
    StatelessMerkleSignatureScheme::new(seed, 16, 32, D::new(15))
}

fn key_generation(b: &mut Bencher) {
    b.iter(|| make_signature_scheme())
}

fn signing(b: &mut Bencher) {
    let mut signature_scheme = make_signature_scheme();
    b.iter(|| {
        let msg = get_random_256bits();
        signature_scheme.sign(msg);
    })
}

fn verification(b: &mut Bencher) {
    let mut signature_scheme = make_signature_scheme();
    let msg = get_random_256bits();
    let signature = signature_scheme.sign(msg);
    b.iter(|| {
        StatelessMerkleSignatureScheme::verify(signature_scheme.public_key(), msg, &signature)
    })
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("benches");
    group.sample_size(20);

    group.bench_function("key_generation", key_generation);
    group.bench_function("signing", signing);
    group.bench_function("verification", verification);
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
