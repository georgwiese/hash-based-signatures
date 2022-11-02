use crate::signature::stateless_merkle::StatelessMerkleSignatureScheme;
use crate::signature::SignatureScheme;
use crate::utils::{hash, slice_to_hash, string_to_hash};
use js_sys::Uint8Array;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello 2, {}!", name));
}

#[wasm_bindgen]
pub fn verify(file_bytes: Uint8Array, signature_bytes: Uint8Array, public_key_str: &str) -> bool {
    let file_hash = hash(&file_bytes.to_vec());

    match rmp_serde::from_slice(&signature_bytes.to_vec()) {
        Ok(signature) => StatelessMerkleSignatureScheme::verify(
            string_to_hash(public_key_str),
            slice_to_hash(file_hash.as_ref()),
            &signature,
        ),
        Err(_) => {
            log("Can't parse signature!");
            false
        }
    }
}
