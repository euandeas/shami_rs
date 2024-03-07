//! Provides base Shamir's Secret Sharing functionality.
use std::fmt;

#[cfg(feature = "experimental")]
use rand_core::{OsRng, RngCore};

#[cfg(feature = "experimental")]
use crate::random::random_no_zero_distinct_set_with_preset;

use crate::{gf256::GF256, random::random_no_zero_distinct_set};

///
#[derive(Debug)]
pub enum Error {
    ZeroSharesError,
    ZeroMinimumSharesError,
    ThresholdError,
    #[cfg(feature = "experimental")]
    PredefinedSharesError,
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
            #[cfg(feature = "experimental")]
            Error::PredefinedSharesError => {
                write!(f, "Predefined share has invalid size or duplicate x")
            }
        }
    }
}

/// Explanation
///
/// # Arguments
///
/// * `p1` - A point in 2D space.
///
/// # Returns
///
/// * A float representing the distance.
///
/// # Example
///
/// ```
///
/// ```
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

/// Explanation
///
/// # Arguments
///
/// * `p1` - A point in 2D space.
///
/// # Returns
///
/// * A float representing the distance.
///
/// # Example
///
/// ```
///
/// ```
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

/// Explanation
///
/// # Arguments
///
/// * `p1` - A point in 2D space.
///
/// # Returns
///
/// * A float representing the distance.
///
/// # Example
///
/// ```
///
/// ```
#[cfg(feature = "experimental")]
pub fn build_shares_predefined(
    secret: &[u8],
    pre_shares: Vec<Vec<u8>>,
    k: usize,
    n: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    if n == 0 {
        return Err(Error::ZeroSharesError);
    }

    if k == 0 {
        return Err(Error::ZeroMinimumSharesError);
    }

    if k > n {
        return Err(Error::ThresholdError);
    }

    if k < 3 {
        return Err(Error::ThresholdError);
    }

    if pre_shares.len() > 2 {
        return Err(Error::PredefinedSharesError);
    }

    let seen_elements: std::collections::HashSet<u8> = std::collections::HashSet::new();
    for share in pre_shares.iter() {
        if share.len() != secret.len() + 1 {
            return Err(Error::PredefinedSharesError);
        }

        if seen_elements.contains(&share[0]) {
            return Err(Error::PredefinedSharesError);
        }
    }

    let mut shares = pre_shares.clone();
    let mut sshare = vec![0u8; secret.len() + 1];
    sshare[0] = 0;
    sshare[1..].copy_from_slice(secret);
    shares.push(sshare);

    // GENERATE EXTRA RANDOM SHARES TO MATCH K
    for _ in 0..(k - pre_shares.len() - 1) {
        let mut share = vec![0u8; secret.len() + 1];
        loop {
            OsRng.fill_bytes(&mut share);
            if share[0] == 0 || shares.iter().any(|s| s[0] == share[0]) {
                continue;
            }
            break;
        }
        shares.push(share);
    }

    let ncoefs = shares.len();
    let npolys = shares[0].len() - 1;

    // create polynomial for each byte
    let mut polys: Vec<Vec<GF256>> = vec![vec![GF256::ZERO; ncoefs]; npolys];

    for i in 1..shares[0].len() {
        let mut polystemp = vec![vec![GF256::ZERO; ncoefs]; ncoefs];
        let mut k = 0;
        for share in shares.iter() {
            let mut coeffs = vec![GF256::ONE];
            let mut denom = GF256::ONE;
            for share2 in shares.iter() {
                if share[0] == share2[0] {
                    continue;
                };

                let mut tempcoeffs = vec![GF256::ZERO; coeffs.len() + 1];
                for j in 0..coeffs.len() {
                    tempcoeffs[j] += coeffs[j] * GF256::from(share2[0]);
                    tempcoeffs[j + 1] += coeffs[j];
                }
                coeffs = tempcoeffs;

                denom *= GF256::from(share[0]) - GF256::from(share2[0]);
            }

            //for j in 0..coeffs.len() {
            for coeff in &mut coeffs {
                *coeff *= denom.mul_inv();
                *coeff *= GF256::from(share[i]);
            }

            polystemp[k] = coeffs;
            k += 1;
        }

        let mut column_sums = vec![GF256::ZERO; polystemp[0].len()];

        for row in polystemp {
            for (i, &element) in row.iter().enumerate() {
                column_sums[i] += element;
            }
        }

        polys[i - 1] = column_sums;
    }

    let shares_left = n - pre_shares.len();
    let mut new_shares: Vec<Vec<u8>> = vec![vec![0u8; 0]; shares_left];

    let random_bytes =
        random_no_zero_distinct_set_with_preset(shares_left, shares.iter().map(|x| x[0]).collect());
    for (i, share) in new_shares.iter_mut().enumerate() {
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

    let mut all_shares = Vec::new();
    all_shares.append(&mut pre_shares.clone());
    all_shares.append(&mut new_shares);

    Ok(all_shares)
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

    #[cfg(feature = "experimental")]
    #[test]
    fn test_build_shares_predefined() {
        // Define inputs
        let secret = b"Hello";
        let mut pre_shares: Vec<Vec<u8>> = Vec::new();

        for _ in 0..2 {
            let mut share = vec![0u8; secret.len() + 1];
            loop {
                OsRng.fill_bytes(&mut share);
                if share[0] == 0 || pre_shares.iter().any(|s| s[0] == share[0]) {
                    continue;
                }
                break;
            }
            pre_shares.push(share);
        }

        let k = 3;
        let n = 5;

        // Call the function
        let result = build_shares_predefined(secret, pre_shares.clone(), k, n);

        // Assertions
        match result {
            Ok(shares) => {
                assert_eq!(shares.len(), 5); // Number of shares matches n
                for share in shares.iter() {
                    assert_eq!(share.len(), secret.len() + 1); // Each share has length of secret + 1
                }

                let shareset1 = shares.clone();
                assert_eq!(
                    rebuild_secret(shareset1[..3].to_vec()).unwrap(),
                    "Hello".as_bytes().to_vec()
                );

                let shareset2 = shares.clone();

                assert_eq!(
                    rebuild_secret(shareset2[1..4].to_vec()).unwrap(),
                    "Hello".as_bytes().to_vec()
                );
            }
            Err(e) => panic!("Error occurred: {:?}", e),
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
