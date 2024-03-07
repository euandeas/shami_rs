//! Provides Shamir's Secret Sharing functionality with XChaCha20Poly1305 wrapper.
use std::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};

use crate::base::{self, Error};

///
#[derive(Debug)]
pub enum ErrorAead {
    ZeroSharesError,
    ZeroMinimumSharesError,
    ThresholdError,
    #[cfg(feature = "experimental")]
    PredefinedSharesError,
    KeyLengthError,
    EncryptionError,
    DecryptionError,
}

impl fmt::Display for ErrorAead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorAead::ZeroSharesError => write!(f, "Must be more than 0 shares."),
            ErrorAead::ZeroMinimumSharesError => write!(f, "Must be more than 0 minimum shares."),
            ErrorAead::ThresholdError => write!(
                f,
                "Number of minimum shares must be less than or equal to number of shares."
            ),
            ErrorAead::KeyLengthError => write!(f, "Key has invalid length."),
            ErrorAead::EncryptionError => write!(f, "Error Encrypting Secret."),
            ErrorAead::DecryptionError => write!(f, "Error Decrypting Secret."),
            #[cfg(feature = "experimental")]
            ErrorAead::PredefinedSharesError => {
                write!(f, "Predefined share has invalid size or duplicate x")
            }
        }
    }
}

impl From<base::Error> for ErrorAead {
    fn from(e: base::Error) -> Self {
        match e {
            Error::ZeroSharesError => ErrorAead::ZeroSharesError,
            Error::ZeroMinimumSharesError => ErrorAead::ZeroMinimumSharesError,
            Error::ThresholdError => ErrorAead::ThresholdError,
            #[cfg(feature = "experimental")]
            Error::PredefinedSharesError => ErrorAead::PredefinedSharesError,
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
pub fn build_shares(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, ErrorAead> {
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);
    let ciphertext = match cipher.encrypt(XNonce::from_slice(&[0; 24]), secret) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(ErrorAead::EncryptionError),
    };

    let mut shares = match base::build_shares(&key, k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

    for share in &mut shares {
        share.extend_from_slice(&ciphertext);
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
pub fn rebuild_secret(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, ErrorAead> {
    let mut keys = Vec::new();
    for share in &shares {
        let key = &share[..33];
        keys.push(key.to_vec());
    }

    let actual_key = match base::rebuild_secret(keys) {
        Ok(key) => key,
        Err(e) => return Err(e.into()),
    };

    let cipher = match XChaCha20Poly1305::new_from_slice(&actual_key) {
        Ok(cipher) => cipher,
        Err(_) => return Err(ErrorAead::KeyLengthError),
    };

    let ciphertext = &shares[0][33..];
    let plaintext = match cipher.decrypt(XNonce::from_slice(&[0; 24]), ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => return Err(ErrorAead::DecryptionError),
    };

    Ok(plaintext)
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
) -> Result<Vec<Vec<u8>>, ErrorAead> {
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);
    let ciphertext = match cipher.encrypt(XNonce::from_slice(&[0; 24]), secret) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(ErrorAead::EncryptionError),
    };

    let mut shares = match base::build_shares_predefined(&key, pre_shares, k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

    for share in &mut shares {
        share.extend_from_slice(&ciphertext);
    }

    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_aeadwrapper_simple() {
        assert_eq!(
            "Hello! Testing!".as_bytes().to_vec(),
            rebuild_secret(build_shares("Hello! Testing!".as_bytes(), 3, 5).unwrap()).unwrap()
        );
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn test_build_shares_predefined() {
        // Define inputs
        let secret = b"Hello";
        let mut pre_shares: Vec<Vec<u8>> = Vec::new();

        for _ in 0..2 {
            let mut share = vec![0u8; 32 + 1];
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
