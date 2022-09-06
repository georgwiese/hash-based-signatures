# Hash-based signatures

A Rust implementation of hash-based signatures.

***Disclaimer:** This repository is a toy project to play around with Rust and cryptographic primitives.
It implements some ideas of Chapter 14 of ["A Graduate Course in
Applied Cryptography"](http://toc.cryptobook.us/) by Dan Boneh and Victor Shoup.*

Hash-based signatures - unlike signature schemes based on RSA or ECC - do not rely on number-theoretic assumptions that are known to be broken by Quantum computers.

Stateless many-time signature schemes can be built in a three-step process:
1. A one-time signature scheme can be built purely from hash functions.
2. From there, we build an indexed signature scheme.
   Using a Merkle tree, the otherwise very large public key can be reduced to a single hash
   (at the expense of a larger signature).
3. Finally, Merkle signatures build a tree of indexed signature schemes.

## Current status

This is the current list of finished & planned steps:
- One-time signatures:
  - [x] Implement basic Lamport signature scheme
  - [ ] Implement Winternitz one-time signatures to reduce signature sizes
- [x] q-indexed signatures
- [ ] Merkle signatures
- [ ] (De)Serialization of signatures and keys
- [ ] Command-line interface to sign arbitrary files & verify signatures