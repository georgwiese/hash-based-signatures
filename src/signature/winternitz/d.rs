use anyhow::{anyhow, Error, Result};

/// Wrapper around the parameter "d" used for `domination_free_function`
#[derive(Clone, Copy)]
pub struct D {
    pub d: u64,
    log_log_d_plus_1: usize,
}

impl D {
    /// Wraps a value for `d`.
    ///
    /// # Panics
    /// Panics if `d` is not of the form 2^(2^x) - 1.
    /// Consider using `D::try_from()`.
    pub fn new(d: u64) -> Self {
        D::try_from(d).unwrap()
    }

    /// The number of bits that are combined into one integer value
    pub fn bits_to_combine(&self) -> usize {
        1 << self.log_log_d_plus_1
    }

    /// The number of bits of the "checksum" c
    pub fn bits_c(&self) -> usize {
        // The maximal value of c is d * n0,
        // and this is the number of bits of (d + 1) * n0:
        // log2((d + 1) * n0)
        // = log2(d + 1) + log2(n0)
        // = bits_to_combine + log2(256 / bits_to_combine)
        // = bits_to_combine + 8 + log2_bits_to_combine
        let bits_c = self.bits_to_combine() + 8 - self.log_log_d_plus_1;

        // Round up to the next factor of bits_to_combine
        let bits_c = (((bits_c as f32) / (self.bits_to_combine() as f32)).ceil() as usize)
            * self.bits_to_combine();
        bits_c
    }

    /// Size of the resulting Winternitz signature / key
    pub fn signature_and_key_size(&self) -> usize {
        (256 + self.bits_c()) / self.bits_to_combine()
    }
}

impl TryFrom<u64> for D {
    type Error = Error;

    fn try_from(d: u64) -> Result<D> {
        let log_log_d_plus_1 = ((d + 1) as f64).log2().log2() as usize;
        if d + 1 != (1 << (1 << log_log_d_plus_1)) {
            Err(anyhow!(
                "d is not of the form 2^(2^x) - 1! Try one of 1, 3, 15, or 255."
            ))
        } else {
            Ok(D {
                d,
                log_log_d_plus_1,
            })
        }
    }
}
