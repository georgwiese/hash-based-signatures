# Example

This very readme will be signed by the following public key:

```
702d39ca33cab5590ada460e4bc0d6821468cfd40ea593140c0e3002fd3c0412
```

You can verify the signature by running:
```bash
$ cargo run -- verify \
  example/readme.md \
  example/readme.md.signature \
  702d39ca33cab5590ada460e4bc0d6821468cfd40ea593140c0e3002fd3c0412
```