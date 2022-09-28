# Example

This very readme will be signed by the following public key:

```
2295347ca777bb31b353b180b46ef09907712445ded61ea4a050c9889b6c142f
```

You can verify the signature by running:
```bash
$ cargo run -- verify \
  example/readme.md \
  example/readme.md.signature \
  2295347ca777bb31b353b180b46ef09907712445ded61ea4a050c9889b6c142f
```