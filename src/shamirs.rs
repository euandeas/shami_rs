use crate::gf256::GF256;
use rand_core::{RngCore, OsRng};
// TODO: Probably ideal to use Result<T, E> instead of panicking

// TODO: For each part we must make sure that the x values are unique
pub fn build_shares(secret: &str, k: usize, n: usize) -> Vec<Vec<u8>> {
    assert!(
        k <= n,
        "Threshold should be less than or equal to the number of shares."
    );

    // create polynomial for each byte
    let polys: Vec<Vec<GF256>> = secret
        .bytes()
        .enumerate()
        .map(|(_, byte)| {
            let mut row: Vec<GF256> = vec![GF256::ZERO; k];
            row[0] = GF256::from(byte);

            //let random_bytes = get_random_buf(k - 1);
            let mut random_bytes = vec![0u8; k-1];
            OsRng.fill_bytes(&mut random_bytes);
            for i in 1..k {
                row[i] = GF256::from(random_bytes[i - 1]);
            }

            row
        })
        .collect();

    let mut shares: Vec<Vec<u8>> = vec![vec![0u8; 0]; n];
    // For Each Share
    for share in shares.iter_mut().take(n) {
        // For Each Part of the Secret
        for poly in polys.iter() {
            let rnd = OsRng.next_u64() as u8;// get_random_buf(1)[0];

            share.push(rnd);

            let mut eval: GF256 = GF256::ZERO;
            let mut power: GF256 = GF256::ONE;
            for coeff in poly.iter() {
                eval += *coeff * power;
                power *= GF256::from(rnd);
            }

            share.push(eval.as_u8());
        }
    }

    shares
}

// TODO: Validate this works after changes to creating shares
pub fn rebuild_secret(shares: Vec<Vec<u8>>) -> Vec<u8> {
    // TODO: Check For Valid Shares

    // Lagrange Interpolation:
    // For Each Part of the Secret
    // shares[i] = x val
    // shares[i+1] = y val
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

    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamirs_simple() {
        for _ in 0..10 {
            assert_eq!(
                "Hello! Testing!".as_bytes().to_vec(),
                rebuild_secret(build_shares("Hello! Testing!", 3, 5))
            );
        }
    }
}
