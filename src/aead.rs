//! Provides Shamir's Secret Sharing functionality with XChaCha20Poly1305 wrapper.
use crate::utils::{pkcs7_pad, pkcs7_unpad};
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

/// Build the shares for a secret. The secret is encrypted with XChaCha20Poly1305 and then the key is split into shares.
///
/// # Arguments
///
/// * `secret` - The secret that is to be shared.
/// * `k` - The minimum number of shares required to rebuild the secret.
/// * `n` - The total number of shares to generate.
/// * `pad` - Whether to pad the secret to so shares are a multiple of 8 bytes.
/// 
/// # Returns
///
/// * A vector of shares in the form of a vector of bytes.
///
pub fn build_shares(
    secret: &[u8],
    k: usize,
    n: usize,
    pad: bool,
) -> Result<Vec<Vec<u8>>, ErrorAead> {
    let mut setsecret: Vec<u8> = secret.to_vec();

    // Pad the secret if required
    if pad {
        setsecret = pkcs7_pad(secret);
    }

    // Generate a random key
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);
    
    // Encrypt the secret
    let ciphertext = match cipher.encrypt(XNonce::from_slice(&[0; 24]), setsecret.as_slice()) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(ErrorAead::EncryptionError),
    };

    // Pass the key to the base function to generate shares
    let mut shares = match base::build_shares(&key, k, n, false) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

    // Append the ciphertext to each share
    for share in &mut shares {
        share.extend_from_slice(&ciphertext);
    }

    Ok(shares)
}

/// Rebuild the encrypted secret from shares.
///
/// # Arguments
///
/// * `shares` - The shares that are to be used to rebuild the secret.
/// 
/// # Returns
///
/// * A vector of bytes representing the secret.
///
pub fn rebuild_secret(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, ErrorAead> {
    let mut keys = Vec::new();
    
    // Extract the keys from the shares
    for share in &shares {
        let key = &share[..33];
        keys.push(key.to_vec());
    }

    // Rebuild the key using the base function
    let actual_key = match base::rebuild_secret(keys) {
        Ok(key) => key,
        Err(e) => return Err(e.into()),
    };

    let cipher = match XChaCha20Poly1305::new_from_slice(&actual_key) {
        Ok(cipher) => cipher,
        Err(_) => return Err(ErrorAead::KeyLengthError),
    };

    // Decrypt the secret
    let ciphertext = &shares[0][33..];
    let plaintext = match cipher.decrypt(XNonce::from_slice(&[0; 24]), ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => return Err(ErrorAead::DecryptionError),
    };

    // Unpad the plaintext if required
    if plaintext.len() % 8 == 7 {
        Ok(pkcs7_unpad(plaintext))
    } else {
        Ok(plaintext)
    }
}

/// Build the shares for a secret, using some predefined shares. The secret is encrypted with XChaCha20Poly1305 and then the key is split into shares.
///
/// # Arguments
///
/// * `secret` - The secret that is to be shared.
/// * `pre_shares` - The predefined shares to use in the generation of new shares.
/// * `k` - The minimum number of shares required to rebuild the secret.
/// * `n` - The total number of shares to generate.
/// * `pad` - Whether to pad the secret to so shares are a multiple of 8 bytes.
/// 
/// # Returns
///
/// * A vector of shares in the form of a vector of bytes.
///
#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
pub fn build_shares_predefined(
    secret: &[u8],
    pre_shares: Vec<Vec<u8>>,
    k: usize,
    n: usize,
    pad: bool,
) -> Result<Vec<Vec<u8>>, ErrorAead> {
    let mut setsecret: Vec<u8> = secret.to_vec();

    // Pad the secret if required
    if pad {
        setsecret = pkcs7_pad(secret);
    }

    // Generate a random key
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);
    
    // Encrypt the secret
    let ciphertext = match cipher.encrypt(XNonce::from_slice(&[0; 24]), setsecret.as_slice()) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(ErrorAead::EncryptionError),
    };

    // Pass the key to the base function to generate shares, along with the predefined shares
    let mut shares = match base::build_shares_predefined(&key, pre_shares, k, n, false) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

    // Append the ciphertext to each share
    for share in &mut shares {
        share.extend_from_slice(&ciphertext);
    }

    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "experimental")]
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_aeadwrapper_simple() {
        assert_eq!(
            "Hello! Testing!".as_bytes().to_vec(),
            rebuild_secret(build_shares("Hello! Testing!".as_bytes(), 3, 5, false).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn test_aeadwrapper_pad() {
        assert_eq!(
            "Hello! Testing!".as_bytes().to_vec(),
            rebuild_secret(build_shares("Hello! Testing!".as_bytes(), 3, 5, true).unwrap())
                .unwrap()
        );
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn test_build_shares_predefined() {
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

        let result = build_shares_predefined(secret, pre_shares.clone(), k, n, false);

        match result {
            Ok(shares) => {
                assert_eq!(shares.len(), 5);
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
