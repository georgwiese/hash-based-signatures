pub fn hash_to_string(hash: &[u8; 32]) -> String {
    let mut result = format!("{:x?}", hash[0]);
    for i in 1..32 {
        result.push_str(&format!("{:x?}", hash[i]));
    }
    result
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

#[cfg(test)]
mod tests {
    use crate::utils::get_least_significant_bits;

    #[test]
    fn test_get_least_significant_bits() {
        assert_eq!(
            get_least_significant_bits(10, 5),
            vec![false, true, false, true, false]
        )
    }
}
