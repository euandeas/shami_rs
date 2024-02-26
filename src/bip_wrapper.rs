use crate::shamirs::{BuildShares, RebuildSecret};
use bip39::Mnemonic;

fn verify_mnemonic(secret: &[u8]) -> Result<Mnemonic, &'static str> {
    let string = match std::str::from_utf8(secret) {
        Ok(s) => s,
        Err(_) => return Err("Invalid String"),
    };

    match Mnemonic::parse_normalized(string) {
        Ok(m) => Ok(m),
        Err(_) => Err("Invalid Mnemonic"),
    }
}

pub fn build_shares_bip(
    secret: &[u8],
    k: usize,
    n: usize,
    f: BuildShares,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let m = verify_mnemonic(secret)?;

    let shares = match f(&m.to_entropy(), k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e),
    };

    Ok(shares)
}

pub fn rebuild_secret_bip(shares: Vec<Vec<u8>>, f: RebuildSecret) -> Result<Vec<u8>, &'static str> {
    let secret = match f(shares) {
        Ok(secret) => secret,
        Err(e) => return Err(e),
    };

    let m = match Mnemonic::from_entropy(&secret) {
        Ok(m) => m,
        Err(_) => return Err("Invalid Mnemonic"),
    };

    Ok(m.to_string().into_bytes())
}

#[cfg(test)]
mod tests {
    use crate::shamirs::{build_shares, rebuild_secret};

    use super::*;

    #[test]
    fn test_bip_simple() {
        const TEST_MNEMONIC: &str = "hundred match learn goddess figure filter zone grocery step tuition manual marriage polar spice inquiry";
        
        for _ in 0..1000 {
            assert_eq!(
                TEST_MNEMONIC.as_bytes().to_vec(),
                rebuild_secret_bip(
                    build_shares_bip(TEST_MNEMONIC.as_bytes(), 3, 5, build_shares).unwrap(),
                    rebuild_secret
                )
                .unwrap()
            );
        }
    }
}
