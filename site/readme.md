# Webapp

A web app to verify signatures, built by following [this guide](https://developer.mozilla.org/en-US/docs/WebAssembly/Rust_to_wasm).

For development, run:
```
$ wasm-pack build --target web && wasm-pack build --target bundler
```

from the project directory.

Then, run:
```
$ cd site && npm run serve
```

## Deployment

To deploy, run the deployment script from the project root:

```
$ ./site/deploy.sh
```

The result will be deployed to:

https://georgwiese.github.io/hash-based-signatures/