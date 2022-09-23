use crate::signature::HashType;
use crate::utils::{bits_to_unsigned_int, get_least_significant_bits};

fn calculate_bits_to_combine(d: u64) -> (usize, usize) {
    if d >= (1 << 32) {
        panic!("d is larger than 2^32 - 1!");
    }
    let bits_to_combine = ((d + 1) as f64).log2() as usize;
    if (1 << bits_to_combine) != d + 1 {
        panic!("d + 1 is not a power of two!");
    }
    let log2_bits_to_combine = (bits_to_combine as f64).log2() as usize;
    if (1 << log2_bits_to_combine) != bits_to_combine {
        panic!("d + 1 is not of the form 2^(2^x)!");
    }

    (bits_to_combine, log2_bits_to_combine)
}

pub fn bitstring_to_integers(bit_string: &Vec<bool>, bits_to_combine: usize) -> Vec<u8> {
    let n_elements = bit_string.len() / bits_to_combine;
    (0..n_elements)
        .map(|i| {
            let start_bit = i * bits_to_combine;
            let end_bit = start_bit + bits_to_combine;
            bits_to_unsigned_int(&bit_string[start_bit..end_bit])
        })
        .collect()
}

pub fn domination_free_function(input: HashType, d: u64) -> Vec<u8> {
    let (bits_to_combine, log2_bits_to_combine) = calculate_bits_to_combine(d);
    let bit_string: Vec<bool> = input
        .map(|x| get_least_significant_bits(x as usize, 8))
        .into_iter()
        .flatten()
        .collect();

    let mut result = Vec::new();
    let n0 = 256 / bits_to_combine;
    let mut c = d * (n0 as u64);
    for x in bitstring_to_integers(&bit_string, bits_to_combine) {
        result.push(x);
        c -= x as u64;
    }

    // Make immutable
    let c = c;

    // The maximal value of c is d * n0,
    // and this is the number of bits of (d + 1) * n0:
    // log2((d + 1) * n0)
    // = log2(d + 1) + log2(n0)
    // = bits_to_combine + log2(256 / bits_to_combine)
    // = bits_to_combine + 8 + log2_bits_to_combine
    let bits_c = bits_to_combine + 8 - log2_bits_to_combine;

    // Round up to the next factor of bits_to_combine
    let bits_c = (((bits_c as f32) / (bits_to_combine as f32)).ceil() as usize) * bits_to_combine;

    let c_bitstring = get_least_significant_bits(c as usize, bits_c as usize);

    result.append(&mut bitstring_to_integers(&c_bitstring, bits_to_combine));

    result
}

#[cfg(test)]
mod tests {
    use crate::signature::winternitz::domination_free_function::domination_free_function;
    use rand::prelude::*;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_domination_free_function_0s_d1() {
        let result = domination_free_function([0; 32], 1);
        let mut expected = vec![0u8; 256];

        // Maximal value of c is 2^8
        expected.extend([1, 0, 0, 0, 0, 0, 0, 0, 0]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_domination_free_function_0s_d3() {
        let result = domination_free_function([0; 32], 3);
        let mut expected = vec![0u8; 128];

        // TODO
        // bits_to_combine is 2
        // Maximal value of c is 3 * 128 = 0x180 = 11000 (base 4)
        // Which should be encoded in 10 2-bit integers
        expected.extend([1, 2, 0, 0, 0]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_domination_free_function_0s_d15() {
        let result = domination_free_function([0; 32], 15);
        let mut expected = vec![0u8; 64];

        // bits_to_combine is 4
        // Maximal value of c is 15 * 64 = 0x3c0
        // Which should be encoded in 3 4-bit integers
        expected.extend([0x3, 0xc, 0x0]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_domination_free_function_0s_d255() {
        let result = domination_free_function([0; 32], 255);
        let mut expected = vec![0u8; 32];

        // bits_to_combine is 4
        // Maximal value of c is 255 * 32 = 0x1FE0
        // Which should be encoded in 2 16-bit integers
        expected.extend([0x1f, 0xe0]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_domination_free_function_1s_d255() {
        let result = domination_free_function([255; 32], 255);
        let mut expected = vec![255u8; 32];

        // bits_to_combine is 4
        // Maximal value of c is 255 * 32 = 0x1FE0
        // Which should be encoded in 2 16-bit integers
        expected.extend([0, 0]);

        assert_eq!(result, expected);
    }

    fn get_domination_free_vectors_on_random_data(d: u64, count: usize) -> Vec<Vec<u8>> {
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        let mut hash = [0u8; 32];
        (0..count)
            .map(|_| {
                rng.fill_bytes(&mut hash);
                domination_free_function(hash, d)
            })
            .collect()
    }

    fn assert_no_domination(domination_free_vectors: &Vec<Vec<u8>>) {
        for i in 0..domination_free_vectors.len() {
            for j in 0..domination_free_vectors.len() {
                if i != j {
                    // The two vectors should be distinct with overwhelming probability and
                    // at least one value should of vec1 should be higher than the corresponding
                    // value in vec2.
                    let vec1 = &domination_free_vectors[i];
                    let vec2 = &domination_free_vectors[j];

                    let v1_dominates_sometimes =
                        vec1.iter().zip(vec2).map(|(v1, v2)| v1 > v2).max().unwrap();
                    assert!(v1_dominates_sometimes);
                }
            }
        }
    }

    #[test]
    fn domination_free_on_random_data_d1() {
        let domination_free_vectors = get_domination_free_vectors_on_random_data(1, 1000);
        assert_no_domination(&domination_free_vectors);
    }

    #[test]
    fn domination_free_on_random_data_d3() {
        let domination_free_vectors = get_domination_free_vectors_on_random_data(3, 1000);
        assert_no_domination(&domination_free_vectors);
    }

    #[test]
    fn domination_free_on_random_data_d15() {
        let domination_free_vectors = get_domination_free_vectors_on_random_data(15, 1000);
        assert_no_domination(&domination_free_vectors);
    }

    #[test]
    fn domination_free_on_random_data_d255() {
        let domination_free_vectors = get_domination_free_vectors_on_random_data(255, 1000);
        assert_no_domination(&domination_free_vectors);
    }
}
