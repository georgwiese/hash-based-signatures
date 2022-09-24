# Example

This very readme will be signed by the following public key:

```
5480d297f1b27c98e4aa9956c1fc288dbc96e87e5d1e05236e127d516c00f9d0
```

You can verify the signature by running:
```bash
$ cargo run -- verify \
  example/readme.md \
  example/readme.md.signature \
  5480d297f1b27c98e4aa9956c1fc288dbc96e87e5d1e05236e127d516c00f9d0
```