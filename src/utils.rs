use crate::signature::HashType;

pub fn hash_to_string(hash: &HashType) -> String {
    let mut result = format!("{:02x?}", hash[0]);
    for i in 1..32 {
        result.push_str(&format!("{:02x?}", hash[i]));
    }
    result
}

pub fn string_to_hash(hash_string: &String) -> HashType {
    let mut hash = [0u8; 32];
    if hash_string.len() != 64 {
        panic!("String has wrong length");
    } else {
        for i in 0..32 {
            hash[i] = u8::from_str_radix(&hash_string[2 * i..2 * i + 2], 16)
                .expect("Error parsing string");
        }
        hash
    }
}

/// Gets the `bits` least significant bits of `index`,
/// sorted from most significant to least significant.
pub fn get_least_significant_bits(index: usize, bits: usize) -> Vec<bool>
where
{
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

#[cfg(test)]
mod tests {
    use crate::signature::HashType;
    use crate::utils::{
        bits_to_unsigned_int, get_least_significant_bits, hash_to_string, string_to_hash,
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
    fn test_hash_to_string() {
        let (test_hash, test_hash_string) = get_test_hash();
        assert_eq!(hash_to_string(&test_hash), test_hash_string);
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
