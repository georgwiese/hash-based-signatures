# Example

This very readme will be signed by the following public key:

```
d4c280791e7712789c21babb323c8b9ab5631f36bcef75c8ec4a2466d69057fe
```

You can verify the signature by running:
```bash
$ cargo run -- verify \
  example/readme.md \
  example/readme.md.signature \
  d4c280791e7712789c21babb323c8b9ab5631f36bcef75c8ec4a2466d69057fe
```