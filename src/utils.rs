use crate::signature::HashType;
use data_encoding::HEXLOWER;
use ring::digest::{digest, SHA256};
use ring::hmac::Key;
use std::cmp::min;

/// Convert a `&[u8]` to a [u8; 32]
///
/// # Panics
/// Panics if the input does not have length 32.
pub fn slice_to_hash(input_slice: &[u8]) -> HashType {
    assert_eq!(input_slice.len(), 32);
    let mut result = [0u8; 32];
    result.copy_from_slice(input_slice);
    result
}

pub fn hash(data: &[u8]) -> HashType {
    slice_to_hash(digest(&SHA256, data).as_ref())
}

pub fn hmac(key: &HashType, data: &[u8]) -> HashType {
    let hmac_key = Key::new(ring::hmac::HMAC_SHA256, key);
    slice_to_hash(ring::hmac::sign(&hmac_key, data).as_ref())
}

pub fn string_to_hash(hash_string: &String) -> HashType {
    slice_to_hash(
        &HEXLOWER
            .decode(hash_string.as_bytes())
            .expect("Could not decode"),
    )
}

/// Gets the `bits` least significant bits of `index`,
/// sorted from most significant to least significant.
pub fn get_least_significant_bits(index: usize, bits: usize) -> Vec<bool> {
    let mut result = Vec::new();
    for i in (0..bits).rev() {
        result.push((index & (1 << i)) != 0)
    }
    result
}

// Converts a vector of bits to an unsigned integer, corresponding to
// the big-endian interpretation of the bit string.
//
// # Panics
// Panics if the number of bits is bigger than 8.
pub fn bits_to_unsigned_int(bits: &[bool]) -> u8 {
    assert!(bits.len() <= 8);
    let mut result = 0;
    for i in 0..bits.len() {
        if bits[i] {
            result = result | (1 << (bits.len() - 1 - i));
        }
    }
    result
}

// Converts a slice of bits to a vector of u8s
pub fn bits_to_unsigned_ints(bits: &[bool]) -> Vec<u8> {
    let size = (bits.len() as f32 / 8.0).ceil() as usize;
    let mut result = Vec::with_capacity(size);
    for i in 0..size {
        let end_bit = min((i + 1) * 8, bits.len());
        result.push(bits_to_unsigned_int(&bits[i * 8..end_bit]));
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::signature::HashType;
    use crate::utils::{
        bits_to_unsigned_int, bits_to_unsigned_ints, get_least_significant_bits, string_to_hash,
    };

    #[test]
    fn test_get_least_significant_bits() {
        assert_eq!(
            get_least_significant_bits(10, 5),
            vec![false, true, false, true, false]
        )
    }

    #[test]
    fn test_bits_to_unsigned_int() {
        assert_eq!(bits_to_unsigned_int(&[false, true, false, true, false]), 10)
    }

    #[test]
    fn test_bits_to_unsigned_ints() {
        assert_eq!(
            bits_to_unsigned_ints(&[
                false, false, false, false, true, false, true, false, true, false
            ]),
            vec![10, 2]
        )
    }

    fn get_test_hash() -> (HashType, String) {
        let mut hash = [0u8; 32];
        for i in 0..32 {
            hash[i] = i as u8;
        }
        (
            hash,
            String::from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        )
    }

    #[test]
    fn test_string_to_hash() {
        let (test_hash, test_hash_string) = get_test_hash();
        assert_eq!(string_to_hash(&test_hash_string), test_hash);
    }

    #[test]
    #[should_panic]
    fn test_string_to_hash_invalid_wrong_length() {
        string_to_hash(&String::from("I have the wrong length"));
    }

    #[test]
    #[should_panic]
    fn test_string_to_hash_invalid_no_hex() {
        let hash_string = "Right length but no valid hash!                                 ";
        string_to_hash(&String::from(hash_string));
    }
}
