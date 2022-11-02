use crate::signature::stateless_merkle::StatelessMerkleSignatureScheme;
use crate::signature::SignatureScheme;
use crate::utils::{hash, slice_to_hash, string_to_hash_maybe};
use js_sys::Uint8Array;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn verify(file_bytes: Uint8Array, signature_bytes: Uint8Array, public_key_str: &str) -> String {
    let file_hash = hash(&file_bytes.to_vec());

    match string_to_hash_maybe(public_key_str) {
        Ok(public_key) => match rmp_serde::from_slice(&signature_bytes.to_vec()) {
            Ok(signature) => {
                if StatelessMerkleSignatureScheme::verify(
                    public_key,
                    slice_to_hash(file_hash.as_ref()),
                    &signature,
                ) {
                    "valid".into()
                } else {
                    "invalid_signature".into()
                }
            }
            Err(_) => "cant_parse_signature".into(),
        },
        Err(_) => "invalid_public_key".into(),
    }
}
