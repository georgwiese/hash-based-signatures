use hash_based_signatures::cli::verify;
use hash_based_signatures::utils::string_to_hash;
use std::path::PathBuf;

#[test]
fn example_verifies() {
    let verifies = verify(
        PathBuf::from("example/readme.md"),
        PathBuf::from("example/readme.md.signature"),
        string_to_hash(&String::from(
            "9e2543961faafa9a021752ad7598170472e688988ad1fa66a33dc65945385194",
        )),
    )
    .unwrap();
    assert!(verifies)
}
