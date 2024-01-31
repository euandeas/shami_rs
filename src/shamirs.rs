use crate::gf256::GF256;

fn get_random_buf(k: usize) -> Vec<u8> {
    let mut buf = vec![0u8; k];
    match getrandom::getrandom(&mut buf) {
        Ok(_) => buf,
        Err(e) => panic!("Failed to generate random bytes: {}", e),
    }
}

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
            let mut row: Vec<GF256> = vec![GF256(0); k];
            row[0] = GF256(byte);

            let random_bytes = get_random_buf(k - 1);
            for i in 1..k {
                row[i] = GF256(random_bytes[i - 1]);
            }

            row
        })
        .collect();

    let mut shares: Vec<Vec<u8>> = vec![vec![0u8; 0]; n];
    // For Each Share
    for share in shares.iter_mut().take(n) {
        // For Each Part of the Secret
        for poly in polys.iter() {
            let rnd = get_random_buf(1)[0];

            share.push(rnd);

            let mut eval: GF256 = GF256(0);
            let mut power: GF256 = GF256(1);
            for coeff in poly.iter() {
                eval += *coeff * power;
                power *= GF256(rnd);
            }

            share.push(eval.0);
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
        let mut secret_temp = GF256(0);
        for share in shares.iter() {
            let mut num = GF256(1);
            let mut denom = GF256(1);
            for share2 in shares.iter() {
                if share[i] == share2[i] {
                    continue;
                };

                num *= GF256(share2[i]);
                denom *= GF256(share2[i]) - GF256(share[i]);
            }

            secret_temp += GF256(share[i + 1]) * num * denom.mul_inv();
        }

        secret[i / 2] = secret_temp.0;
    }

    secret
}
