use orion::hash::Digest;

pub fn digest_to_bytes(digest: Digest) -> [u8; 32] {
    assert_eq!(digest.len(), 32);

    let mut res: [u8; 32] = [0; 32];
    for i in 0..32 {
        res[i] = digest.as_ref()[i];
    }
    res
}

pub fn hash_to_string(hash: &[u8; 32]) -> String {
    let mut result = format!("{:x?}", hash[0]);
    for i in 1..32 {
        result.push_str(&format!("{:x?}", hash[i]));
    }
    result
}
