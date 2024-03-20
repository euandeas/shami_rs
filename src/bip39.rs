//! Provides Shamir's Secret Sharing functionality for bip39 mnemonics.
use std::fmt;

use bip39::Mnemonic;

use crate::aead;
use crate::base;
use crate::utils::pkcs7_pad;

///
#[derive(Debug)]
pub enum ErrorBip {
    ZeroSharesError,
    ZeroMinimumSharesError,
    ThresholdError,
    #[cfg(feature = "experimental")]
    PredefinedSharesError,
    MnemonicError,
}

///
#[derive(Debug)]
pub enum ErrorBipAead {
    ZeroSharesError,
    ZeroMinimumSharesError,
    ThresholdError,
    #[cfg(feature = "experimental")]
    PredefinedSharesError,
    KeyLengthError,
    EncryptionError,
    DecryptionError,
    MnemonicError,
}

impl fmt::Display for ErrorBip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorBip::ZeroSharesError => write!(f, "Must be more than 0 shares."),
            ErrorBip::ZeroMinimumSharesError => write!(f, "Must be more than 0 minimum shares."),
            ErrorBip::ThresholdError => write!(
                f,
                "Number of minimum shares must be less than or equal to number of shares."
            ),
            ErrorBip::MnemonicError => write!(f, "Error parsing Mnemonic."),
            #[cfg(feature = "experimental")]
            ErrorBip::PredefinedSharesError => {
                write!(f, "Predefined share has invalid size or duplicate x")
            }
        }
    }
}

impl From<base::Error> for ErrorBip {
    fn from(e: base::Error) -> Self {
        match e {
            base::Error::ZeroSharesError => ErrorBip::ZeroSharesError,
            base::Error::ZeroMinimumSharesError => ErrorBip::ZeroMinimumSharesError,
            base::Error::ThresholdError => ErrorBip::ThresholdError,
            #[cfg(feature = "experimental")]
            base::Error::PredefinedSharesError => ErrorBip::PredefinedSharesError,
        }
    }
}

impl fmt::Display for ErrorBipAead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorBipAead::ZeroSharesError => write!(f, "Must be more than 0 shares."),
            ErrorBipAead::ZeroMinimumSharesError => {
                write!(f, "Must be more than 0 minimum shares.")
            }
            ErrorBipAead::ThresholdError => write!(
                f,
                "Number of minimum shares must be less than or equal to number of shares."
            ),
            ErrorBipAead::KeyLengthError => write!(f, "Key has invalid length."),
            ErrorBipAead::EncryptionError => write!(f, "Error Encrypting Secret."),
            ErrorBipAead::DecryptionError => write!(f, "Error Decrypting Secret."),
            ErrorBipAead::MnemonicError => write!(f, "Error parsing Mnemonic."),
            #[cfg(feature = "experimental")]
            ErrorBipAead::PredefinedSharesError => {
                write!(f, "Predefined share has invalid size or duplicate x")
            }
        }
    }
}

impl From<aead::ErrorAead> for ErrorBipAead {
    fn from(e: aead::ErrorAead) -> Self {
        match e {
            aead::ErrorAead::ZeroSharesError => ErrorBipAead::ZeroSharesError,
            aead::ErrorAead::ZeroMinimumSharesError => ErrorBipAead::ZeroMinimumSharesError,
            aead::ErrorAead::ThresholdError => ErrorBipAead::ThresholdError,
            aead::ErrorAead::KeyLengthError => ErrorBipAead::KeyLengthError,
            aead::ErrorAead::EncryptionError => ErrorBipAead::EncryptionError,
            aead::ErrorAead::DecryptionError => ErrorBipAead::DecryptionError,
            #[cfg(feature = "experimental")]
            aead::ErrorAead::PredefinedSharesError => ErrorBipAead::PredefinedSharesError,
        }
    }
}

fn verify_mnemonic(secret: &[u8]) -> Result<Mnemonic, ()> {
    let string = match std::str::from_utf8(secret) {
        Ok(s) => s,
        Err(_) => return Err(()),
    };

    match Mnemonic::parse_normalized(string) {
        Ok(m) => Ok(m),
        Err(_) => Err(()),
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
pub fn build_shares(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, ErrorBip> {
    let m = match verify_mnemonic(secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBip::MnemonicError),
    };

    let shares = match base::build_shares(&m.to_entropy(), k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

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
pub fn build_shares_pad(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, ErrorBip> {
    let m = match verify_mnemonic(secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBip::MnemonicError),
    };

    println!("{:?}", m.to_entropy());
    let padded_secret = pkcs7_pad(m.to_entropy().as_slice());
    println!("{:?}", padded_secret);

    let shares = match base::build_shares(padded_secret.as_slice(), k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

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
pub fn rebuild_secret(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, ErrorBip> {
    let secret = match base::rebuild_secret(shares) {
        Ok(secret) => secret,
        Err(e) => return Err(e.into()),
    };

    let m = match Mnemonic::from_entropy(&secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBip::MnemonicError),
    };

    Ok(m.to_string().into_bytes())
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
pub fn build_shares_aead(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, ErrorBipAead> {
    let m = match verify_mnemonic(secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBipAead::MnemonicError),
    };

    let shares = match aead::build_shares(&m.to_entropy(), k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

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
pub fn build_shares_aead_pad(
    secret: &[u8],
    k: usize,
    n: usize,
) -> Result<Vec<Vec<u8>>, ErrorBipAead> {
    let m = match verify_mnemonic(secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBipAead::MnemonicError),
    };

    let padded_secret = pkcs7_pad(&m.to_entropy());

    let shares = match aead::build_shares(padded_secret.as_slice(), k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

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
pub fn rebuild_secret_aead(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, ErrorBipAead> {
    let secret = match aead::rebuild_secret(shares) {
        Ok(secret) => secret,
        Err(e) => return Err(e.into()),
    };

    let m = match Mnemonic::from_entropy(&secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBipAead::MnemonicError),
    };

    Ok(m.to_string().into_bytes())
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
) -> Result<Vec<Vec<u8>>, ErrorBip> {
    let m = match verify_mnemonic(secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBip::MnemonicError),
    };

    let shares = match base::build_shares_predefined(&m.to_entropy(), pre_shares, k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

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
#[cfg(feature = "experimental")]
pub fn build_shares_aead_predefined(
    secret: &[u8],
    pre_shares: Vec<Vec<u8>>,
    k: usize,
    n: usize,
) -> Result<Vec<Vec<u8>>, ErrorBipAead> {
    let m = match verify_mnemonic(secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBipAead::MnemonicError),
    };

    let shares = match aead::build_shares_predefined(&m.to_entropy(), pre_shares, k, n) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "experimental")]
    use rand_core::{OsRng, RngCore};

    const TEST_MNEMONIC: &str = "hundred match learn goddess figure filter zone grocery step tuition manual marriage polar spice inquiry";

    #[test]
    fn test_bip_simple() {
        assert_eq!(
            TEST_MNEMONIC.as_bytes().to_vec(),
            rebuild_secret(build_shares(TEST_MNEMONIC.as_bytes(), 3, 5).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_bip_pad() {
        assert_eq!(
            TEST_MNEMONIC.as_bytes().to_vec(),
            rebuild_secret(build_shares_pad(TEST_MNEMONIC.as_bytes(), 3, 5).unwrap()).unwrap()
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

    #[test]
    fn test_bip_aead_pad() {
        assert_eq!(
            TEST_MNEMONIC.as_bytes().to_vec(),
            rebuild_secret_aead(build_shares_aead_pad(TEST_MNEMONIC.as_bytes(), 3, 5).unwrap())
                .unwrap()
        );
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn test_build_shares_predefined() {
        // Define inputs
        let secret = TEST_MNEMONIC.as_bytes();
        let mut pre_shares: Vec<Vec<u8>> = Vec::new();

        for _ in 0..2 {
            let mut share = vec![0u8; 20 + 1];
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
                    TEST_MNEMONIC.as_bytes().to_vec()
                );

                let shareset2 = shares.clone();

                assert_eq!(
                    rebuild_secret(shareset2[1..4].to_vec()).unwrap(),
                    TEST_MNEMONIC.as_bytes().to_vec()
                );
            }
            Err(e) => panic!("Error occurred: {:?}", e),
        }
    }
}
