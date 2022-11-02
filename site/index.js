async function check_signature(js) {
    let public_key = document.forms["form"]["public_key"].value;
    let file_array_buffer = await document.forms["form"]["file"].files[0].arrayBuffer();
    let signature_array_buffer = await document.forms["form"]["signature"].files[0].arrayBuffer();

    let file_bytes = new Uint8Array(file_array_buffer);
    let signature_bytes = new Uint8Array(signature_array_buffer);

    console.log(js.verify(file_bytes, signature_bytes, public_key));

    var validModal = new bootstrap.Modal(document.getElementById('valid-modal'), {
        keyboard: false
    });
    var invalidModal = new bootstrap.Modal(document.getElementById('invalid-modal'), {
        keyboard: false
    });

    let result = js.verify(file_bytes, signature_bytes, public_key);
    console.log(result);

    if (result === "valid") {
        validModal.show();
    } else if (result === "cant_parse_signature") {
        document.getElementById('invalid-reason').textContent = "The provided signature cannot be parsed. Did you upload the correct signature file?";
        invalidModal.show();
    } else if (result === "invalid_public_key") {
        document.getElementById('invalid-reason').textContent = "The provided public key can't be parsed. It needs to be exactly 64 characters, encoding a 256-bit hash in hexadecimal.";
        invalidModal.show();
    } else if (result === "invalid_signature") {
        document.getElementById('invalid-reason').textContent = "The provided signature can be parsed, but is not valid for the given file and public key.";
        invalidModal.show();
    } else {
        alert("Unexpected result: " + result);
    }
}

import("./node_modules/hash-based-signatures/hash_based_signatures.js").then((js) => {
    function onSubmit() {
        setTimeout(() => check_signature(js), 0);

        return false;
    }
    window.onSubmit = onSubmit;
});
