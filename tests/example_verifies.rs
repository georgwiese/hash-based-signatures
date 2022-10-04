use hash_based_signatures::cli::verify;
use hash_based_signatures::utils::string_to_hash;
use std::path::PathBuf;

#[test]
fn example_verifies() {
    let verifies = verify(
        PathBuf::from("example/readme.md"),
        PathBuf::from("example/readme.md.signature"),
        string_to_hash(&String::from(
            "cef7b96b7fc47850cb01991c58c29bbfef733eefc6fd3f22e2d9b2bbd147a4e3",
        )),
    );
    assert!(verifies)
}
