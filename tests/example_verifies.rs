use hash_based_signatures::cli::verify;
use hash_based_signatures::utils::string_to_hash;
use std::path::PathBuf;

#[test]
fn example_verifies() {
    let verifies = verify(
        PathBuf::from("example/readme.md"),
        PathBuf::from("example/readme.md.signature"),
        string_to_hash(&String::from(
            "702d39ca33cab5590ada460e4bc0d6821468cfd40ea593140c0e3002fd3c0412",
        )),
    );
    assert!(verifies)
}
