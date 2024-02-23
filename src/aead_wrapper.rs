use crate::shamirs::{BuildShares, RebuildSecret};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    Error, XChaCha20Poly1305, XNonce,
};

//https://docs.rs/chacha20poly1305/latest/chacha20poly1305/index.html

pub fn build_shares_aead(
    secret: &[u8],
    k: usize,
    n: usize,
    f: BuildShares,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);
    let ciphertext = match cipher.encrypt(XNonce::from_slice(&[0; 24]), secret) {
        Ok(ciphertext) => ciphertext,
        Err(Error) => return Err("Error Encrypting Secret!"),
    };

    let mut shares = match f(&key, k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e),
    };

    for share in &mut shares {
        share.extend_from_slice(&ciphertext);
    }

    Ok(shares)
}

pub fn rebuild_secret_aead(
    shares: Vec<Vec<u8>>,
    f: RebuildSecret,
) -> Result<Vec<u8>, &'static str> {
    let mut keys = Vec::new();
    for share in &shares {
        let key = &share[..64];
        keys.push(key.to_vec());
    }

    let actual_key = match f(keys) {
        Ok(key) => key,
        Err(e) => return Err(e),
    };

    let cipher = match XChaCha20Poly1305::new_from_slice(&actual_key) {
        Ok(cipher) => cipher,
        Err(_) => return Err("Key has invalid length!"),
    };

    let ciphertext = &shares[0][64..];
    let plaintext = match cipher.decrypt(XNonce::from_slice(&[0; 24]), ciphertext) {
        Ok(plaintext) => plaintext,
        Err(Error) => return Err("Error Decrypting Secret!"),
    };

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use crate::shamirs::{build_shares, rebuild_secret};

    use super::*;

    #[test]
    fn test_aeadwrapper_simple() {
        for _ in 0..1000 {
            assert_eq!(
                "Hello! Testing!".as_bytes().to_vec(),
                rebuild_secret_aead(
                    build_shares_aead("Hello! Testing!".as_bytes(), 3, 5, build_shares).unwrap(),
                    rebuild_secret
                )
                .unwrap()
            );
        }
    }
}
