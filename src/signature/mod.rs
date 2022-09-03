pub mod basic_lamport;
pub mod q_indexed_signature;


pub trait Signature {
    fn verify(&self, message: &[u8; 32]) -> bool;
}

pub trait SignatureScheme<S: Signature> {
    fn new(seed: [u8; 32]) -> Self;
    fn sign(&self, message: &[u8; 32]) -> S;
}
