use bip39::Mnemonic;

use crate::base;
use crate::aead;

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

pub fn build_shares(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, &'static str> {
    let m = verify_mnemonic(secret)?;

    let shares = match base::build_shares(&m.to_entropy(), k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e),
    };

    Ok(shares)
}

pub fn rebuild_secret(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    let secret = match base::rebuild_secret(shares) {
        Ok(secret) => secret,
        Err(e) => return Err(e),
    };

    let m = match Mnemonic::from_entropy(&secret) {
        Ok(m) => m,
        Err(_) => return Err("Invalid Mnemonic"),
    };

    Ok(m.to_string().into_bytes())
}

pub fn build_shares_aead(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, &'static str> {
    let m = verify_mnemonic(secret)?;

    let shares = match aead::build_shares(&m.to_entropy(), k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e),
    };

    Ok(shares)
}

pub fn rebuild_secret_aead(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    let secret = match aead::rebuild_secret(shares) {
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
            rebuild_secret(build_shares(TEST_MNEMONIC.as_bytes(), 3, 5).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_bip_aead() {
        assert_eq!(
            TEST_MNEMONIC.as_bytes().to_vec(),
            rebuild_secret_aead(build_shares_aead(TEST_MNEMONIC.as_bytes(), 3, 5).unwrap())
                .unwrap()
        );
    }
}
