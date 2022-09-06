pub mod basic_lamport;
pub mod q_indexed_signature;

pub type HashType = [u8; 32];

/// A generic trait that describes a signature scheme.
///
/// The general workflow is:
/// - Instantiating a signature scheme generates a new key pair.
///   Concrete instantiations have to provide their own way of instantiating
///   themselves.
/// - The public key is exposed via `public_key()`
/// - Messages can be signed using `sign()`
/// - Signatures can be verified using `verify()`
pub trait SignatureScheme<PK, M, SIG> {
    /// Returns a copy of the public key
    fn public_key(&self) -> PK;

    /// Signs a message
    fn sign(&mut self, message: M) -> SIG;

    /// Verifies a signature.
    /// Note that this function does not require need `self`, hence does not need
    /// an instance of the signature scheme.
    /// This is because an instance of a signature scheme contains the signing key
    /// which is typically not available for the verifier.
    fn verify(pk: PK, message: M, signature: &SIG) -> bool;
}
