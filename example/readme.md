# Example

This very readme will be signed by the following public key:

```
9e2543961faafa9a021752ad7598170472e688988ad1fa66a33dc65945385194
```

You can verify the signature by running:
```bash
$ cargo run -- verify \
  example/readme.md \
  example/readme.md.signature \
  9e2543961faafa9a021752ad7598170472e688988ad1fa66a33dc65945385194
```