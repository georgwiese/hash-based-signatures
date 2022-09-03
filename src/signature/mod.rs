pub mod basic_lamport;
pub mod q_indexed_signature;


pub trait Signature {
    fn verify(&self, message: &[u8; 32]) -> bool;
}

pub trait SignatureScheme<S: Signature> {
    fn sign(&self, message: &[u8; 32]) -> S;
}
