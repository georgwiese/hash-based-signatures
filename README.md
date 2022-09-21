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
- q-indexed signatures:
  - [x] Basic q-indexed signature scheme from one-time signature scheme
  - [x] Public key compression via Merkle tree
- [x] Merkle signatures
- [x] (De)Serialization of signatures and keys
- [x] Command-line interface to sign arbitrary files & verify signatures

## Command line interface

To get started with signature verification, check out [the example](./example)!

To sign files, run:
```bash
$ cargo run -- key-gen
```

This will create a `.private_key.json` in your working directory and print the corresponding public key.
Keep it private!

To sign a file, make sure that you have a `.private_key.json` in your working directory and run:
```bash
$ cargo run -- sign example/readme.md
```