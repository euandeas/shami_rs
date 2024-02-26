use bip39::Mnemonic;

use crate::{
    aead_wrapper::{build_shares_aead, rebuild_secret_aead},
    shamirs::{build_shares, rebuild_secret},
};

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

pub fn build_shares_bip(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, &'static str> {
    let m = verify_mnemonic(secret)?;

    let shares = match build_shares(&m.to_entropy(), k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e),
    };

    Ok(shares)
}

pub fn rebuild_secret_bip(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    let secret = match rebuild_secret(shares) {
        Ok(secret) => secret,
        Err(e) => return Err(e),
    };

    let m = match Mnemonic::from_entropy(&secret) {
        Ok(m) => m,
        Err(_) => return Err("Invalid Mnemonic"),
    };

    Ok(m.to_string().into_bytes())
}

pub fn build_shares_bip_aead(
    secret: &[u8],
    k: usize,
    n: usize,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let m = verify_mnemonic(secret)?;

    let shares = match build_shares_aead(&m.to_entropy(), k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e),
    };

    Ok(shares)
}

pub fn rebuild_secret_bip_aead(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    let secret = match rebuild_secret_aead(shares) {
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
    use super::*;

    const TEST_MNEMONIC: &str = "hundred match learn goddess figure filter zone grocery step tuition manual marriage polar spice inquiry";

    #[test]
    fn test_bip_simple() {
        assert_eq!(
            TEST_MNEMONIC.as_bytes().to_vec(),
            rebuild_secret_bip(build_shares_bip(TEST_MNEMONIC.as_bytes(), 3, 5).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_bip_aead() {
        assert_eq!(
            TEST_MNEMONIC.as_bytes().to_vec(),
            rebuild_secret_bip_aead(build_shares_bip_aead(TEST_MNEMONIC.as_bytes(), 3, 5).unwrap())
                .unwrap()
        );
    }
}
