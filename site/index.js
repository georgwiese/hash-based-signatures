async function check_signature(js) {
    let public_key = document.forms["form"]["public_key"].value;
    let file_array_buffer = await document.forms["form"]["file"].files[0].arrayBuffer();
    let signature_array_buffer = await document.forms["form"]["signature"].files[0].arrayBuffer();

    let file_bytes = new Uint8Array(file_array_buffer);
    let signature_bytes = new Uint8Array(signature_array_buffer);

    console.log(public_key);
    console.log(file_bytes);
    console.log(signature_bytes);

    window.public_key = public_key;
    window.file_bytes = file_bytes;
    window.signature_bytes = signature_bytes;
    window.js = js;

    console.log(js.verify(file_bytes, signature_bytes, public_key));
}

import("./node_modules/hash-based-signatures/hash_based_signatures.js").then((js) => {
    function onSubmit() {
        setTimeout(() => check_signature(js), 0);

        return false;
    }
    window.onSubmit = onSubmit;
});
