pub mod basic_lamport;
pub mod q_indexed_signature;

pub type HashType = [u8; 32];

pub trait SignatureScheme<PK, M, SIG> {
    fn public_key(&self) -> PK;
    fn sign(&mut self, message: M) -> SIG;
    fn verify(pk: PK, message: M, signature: SIG) -> bool;
}
