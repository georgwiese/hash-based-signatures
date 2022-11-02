async function check_signature() {
    let public_key = document.forms["form"]["public_key"].value;
    let file_array_buffer = await document.forms["form"]["file"].files[0].arrayBuffer();
    let signature_array_buffer = await document.forms["form"]["signature"].files[0].arrayBuffer();

    console.log(public_key);
    console.log(file_array_buffer);
    console.log(signature_array_buffer);
}

import("./node_modules/hash-based-signatures/hash_based_signatures.js").then((js) => {
    function onSubmit() {
        setTimeout(check_signature, 0);

        // js.greet("WebAssembly with npm");

        return false;
    }
    window.onSubmit = onSubmit;
});
