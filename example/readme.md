# Example

This very readme will be signed by the following public key:

```
cef7b96b7fc47850cb01991c58c29bbfef733eefc6fd3f22e2d9b2bbd147a4e3
```

You can verify the signature by running:
```bash
$ cargo run -- verify \
  example/readme.md \
  example/readme.md.signature \
  cef7b96b7fc47850cb01991c58c29bbfef733eefc6fd3f22e2d9b2bbd147a4e3
```