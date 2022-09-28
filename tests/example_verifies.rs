use hash_based_signatures::cli::verify;
use hash_based_signatures::utils::string_to_hash;
use std::path::PathBuf;

#[test]
fn example_verifies() {
    let verifies = verify(
        PathBuf::from("example/readme.md"),
        PathBuf::from("example/readme.md.signature"),
        string_to_hash(&String::from(
            "2295347ca777bb31b353b180b46ef09907712445ded61ea4a050c9889b6c142f",
        )),
    );
    assert!(verifies)
}
