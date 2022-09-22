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
    if (1 << log2_bits_to_combine) != log2_bits_to_combine {
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

    #[test]
    fn test_domination_free_function_0s_d1() {
        let result = domination_free_function([0; 32], 1);
        let mut expected = vec![0u8; 256];
        expected.extend([1u8; 8]);

        assert_eq!(result, expected);
    }
}
