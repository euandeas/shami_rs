//! Provides base Shamir's Secret Sharing functionality.
use std::fmt;

use crate::{gf256::GF256, random::random_no_zero_distinct_set};

#[derive(Debug)]
pub enum Error {
    ZeroSharesError,
    ZeroMinimumSharesError,
    ThresholdError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ZeroSharesError => write!(f, "Must be more than 0 shares."),
            Error::ZeroMinimumSharesError => write!(f, "Must be more than 0 minimum shares."),
            Error::ThresholdError => write!(
                f,
                "Number of minimum shares must be less than or equal to number of shares."
            ),
        }
    }
}

pub fn build_shares(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, Error> {
    if n == 0 {
        return Err(Error::ZeroSharesError);
    }
    
    if k == 0 {
        return Err(Error::ZeroMinimumSharesError);
    }

    if k > n {
        return Err(Error::ThresholdError);
    }

    // create polynomial for each byte
    let polys: Vec<Vec<GF256>> = secret
        .iter()
        .enumerate()
        .map(|(_, byte)| {
            let mut row: Vec<GF256> = vec![GF256::ZERO; k];
            row[0] = GF256::from(*byte);

            let random_bytes = random_no_zero_distinct_set(k - 1);
            for i in 1..k {
                row[i] = GF256::from(random_bytes[i - 1]);
            }

            row
        })
        .collect();

    let mut shares: Vec<Vec<u8>> = vec![vec![0u8; 0]; n];

    let random_bytes = random_no_zero_distinct_set(n);
    for (i, share) in shares.iter_mut().enumerate() {
        share.push(random_bytes[i]);

        for poly in polys.iter() {
            let mut eval: GF256 = GF256::ZERO;
            let mut power: GF256 = GF256::ONE;
            for coeff in poly.iter() {
                eval += *coeff * power;
                power *= GF256::from(random_bytes[i]);
            }

            share.push(eval.as_u8());
        }
    }

    Ok(shares)
}

pub fn rebuild_secret(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, Error> {
    if shares.is_empty() {
        return Err(Error::ZeroSharesError);
    }
 
    let mut secret = vec![0u8; shares[0].len() - 1];

    for i in 1..shares[0].len() {
        let mut secret_temp = GF256::ZERO;
        for share in shares.iter() {
            let mut num = GF256::ONE;
            let mut denom = GF256::ONE;
            for share2 in shares.iter() {
                if share[0] == share2[0] {
                    continue;
                };

                num *= GF256::from(share2[0]);
                denom *= GF256::from(share2[0]) - GF256::from(share[0]);
            }

            secret_temp += GF256::from(share[i]) * num * denom.mul_inv();
        }

        secret[i - 1] = secret_temp.as_u8();
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamirs() {
        for _ in 0..1000 {
            assert_eq!(
                "Hello! Testing!".as_bytes().to_vec(),
                rebuild_secret(build_shares("Hello! Testing!".as_bytes(), 3, 5).unwrap()).unwrap()
            );
        }
    }
}
/*

ALTERNATIVE IMPLEMENTATION
This implementation randomises x values for each byte and so it produces shares of double the original secret length.
This is not needed in the current use case of this library, and unsure if it provides any benefit to just randomising x for each share.

pub fn build_shares_randomised(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, &'static str> {
    assert!(
        k <= n,
        "Threshold should be less than or equal to the number of shares."
    );

    let polys: Vec<Vec<GF256>> = secret
        .iter()
        .enumerate()
        .map(|(_, byte)| {
            let mut row: Vec<GF256> = vec![GF256::ZERO; k];
            row[0] = GF256::from(*byte);

            let random_bytes = random_no_zero_distinct_set(k - 1);
            for i in 1..k {
                row[i] = GF256::from(random_bytes[i - 1]);
            }

            row
        })
        .collect();

    let mut shares: Vec<Vec<u8>> = vec![vec![0u8; 0]; n];

    for poly in polys.iter() {
        let random_bytes = random_no_zero_distinct_set(n);
        for (i, share) in shares.iter_mut().enumerate() {
            share.push(random_bytes[i]);

            let mut eval: GF256 = GF256::ZERO;
            let mut power: GF256 = GF256::ONE;
            for coeff in poly.iter() {
                eval += *coeff * power;
                power *= GF256::from(random_bytes[i]);
            }

            share.push(eval.as_u8());
        }
    }

    Ok(shares)
}

pub fn rebuild_secret_randomised(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    let mut secret = vec![0u8; shares[0].len() / 2];
    for i in (0..shares[0].len()).step_by(2) {
        let mut secret_temp = GF256::ZERO;
        for share in shares.iter() {
            let mut num = GF256::ONE;
            let mut denom = GF256::ONE;
            for share2 in shares.iter() {
                if share[i] == share2[i] {
                    continue;
                };

                num *= GF256::from(share2[i]);
                denom *= GF256::from(share2[i]) - GF256::from(share[i]);
            }

            secret_temp += GF256::from(share[i + 1]) * num * denom.mul_inv();
        }

        secret[i / 2] = secret_temp.as_u8();
    }

    Ok(secret)
} */
