# Example

This very readme will be signed by the following public key:

```
97d45a522cb1f497ef2c55942b402b6dfedd1efd75cbe2d0cd19b4067cf01c95
```

You can verify the signature by running:
```bash
$ cargo run -- verify \
  example/readme.md \
  example/readme.md.signature \
  97d45a522cb1f497ef2c55942b402b6dfedd1efd75cbe2d0cd19b4067cf01c95
```