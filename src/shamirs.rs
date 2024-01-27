use crate::gf256::GF256;

fn get_random_buf(k: usize) -> Result<Vec<u8>, getrandom::Error> {
    let mut buf = vec![0u8; k];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}

pub fn create_shares(secret: &str, k: usize, n: usize) -> Vec<Vec<u8>> {
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

            if let Ok(random_bytes) = get_random_buf(k - 1) {
                for i in 1..k {
                    row[i] = GF256(random_bytes[i - 1]);
                }
            } else {
                panic!("Failed to generate random bytes");
            }

            row
        })
        .collect();

    let mut shares: Vec<Vec<u8>> = vec![vec![0u8; 0]; n];
    // For Each Share
    for share in shares.iter_mut().take(n) {
        // For Each Part of the Secret
        for poly in polys.iter() {
            let rnd: u8;
            if let Ok(random_byte) = get_random_buf(1) {
                rnd = random_byte[0];
            } else {
                panic!("Failed to generate random bytes");
            }

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

fn combine_shares() {}
