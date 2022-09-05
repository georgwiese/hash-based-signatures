use orion::hash::Digest;

pub fn digest_to_bytes(digest: Digest) -> [u8; 32] {
    assert_eq!(digest.len(), 32);

    let mut res: [u8; 32] = [0; 32];
    for i in 0..32 {
        res[i] = digest.as_ref()[i];
    }
    res
}
