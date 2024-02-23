use crate::{gf256::GF256, random::random_no_zero_distinct_set};
// TODO: Probably ideal to use Result<T, E> instead of panicking

pub type BuildShares = fn(&[u8], usize, usize) -> Result<Vec<Vec<u8>>, &'static str>;
pub type RebuildSecret = fn(Vec<Vec<u8>>) -> Result<Vec<u8>, &'static str>;

// TODO: For each part we must make sure that the x values are unique
pub fn build_shares(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, &'static str> {
    assert!(
        k <= n,
        "Threshold should be less than or equal to the number of shares."
    );

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

    //Generate Shares (x, y) for each part of the secret
    let mut shares: Vec<Vec<u8>> = vec![vec![0u8; 0]; n];

    // For Each part of the secret
    for poly in polys.iter() {
        // For Each Share
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

// TODO: Validate this works after changes to creating shares
pub fn rebuild_secret(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    // TODO: Check For Valid Shares

    // Lagrange Interpolation:
    // For Each Part of the Secret
    // x = shares[i]
    // y = shares[i+1]
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamirs_simple() {
        for _ in 0..1000 {
            assert_eq!(
                "Hello! Testing!".as_bytes().to_vec(),
                rebuild_secret(build_shares("Hello! Testing!".as_bytes(), 3, 5).unwrap()).unwrap()
            );
        }
    }
}
