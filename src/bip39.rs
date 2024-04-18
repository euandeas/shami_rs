//! Provides Shamir's Secret Sharing functionality for bip39 mnemonics.
use std::fmt;

use bip39::Mnemonic;

use crate::aead;
use crate::base;

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

// Verify that a bit slice is a valid mnemonic
fn verify_mnemonic(secret: &[u8]) -> Result<Mnemonic, ()> {
    // Convert the secret to a string 
    let string = match std::str::from_utf8(secret) {
        Ok(s) => s,
        Err(_) => return Err(()),
    };

    // Parse the string into a Mnemonic
    match Mnemonic::parse_normalized(string) {
        Ok(m) => Ok(m),
        Err(_) => Err(()),
    }
}

/// Build the shares for a secret. Converting the mnemonic secret to entropy and then splitting the entropy into shares.
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
) -> Result<Vec<Vec<u8>>, ErrorBip> {
    // Verify that the secret is a valid mnemonic
    let m = match verify_mnemonic(secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBip::MnemonicError),
    };

    // Convert the mnemonic to entropy and build the shares, using the base function
    let shares = match base::build_shares(&m.to_entropy(), k, n, pad) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

    Ok(shares)
}

/// Rebuild the secret from shares and produce a mnemonic from the entropy.
///
/// # Arguments
///
/// * `shares` - The shares that are to be used to rebuild the secret.
/// 
/// # Returns
///
/// * A vector of bytes representing the secret.
///
pub fn rebuild_secret(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, ErrorBip> {
    // Rebuild the secret using the base function
    let secret = match base::rebuild_secret(shares) {
        Ok(secret) => secret,
        Err(e) => return Err(e.into()),
    };

    // Convert the entropy to a mnemonic
    let m = match Mnemonic::from_entropy(&secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBip::MnemonicError),
    };

    Ok(m.to_string().into_bytes())
}

/// Build the shares for a secret. Converting the mnemonic secret to entropy and then splitting the entropy into shares. The entropy is encrypted with XChaCha20Poly1305 and then the key is split into shares.
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
pub fn build_shares_aead(
    secret: &[u8],
    k: usize,
    n: usize,
    pad: bool,
) -> Result<Vec<Vec<u8>>, ErrorBipAead> {
    // Verify that the secret is a valid mnemonic
    let m = match verify_mnemonic(secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBipAead::MnemonicError),
    };

    // Convert the mnemonic to entropy and build the shares, using the aead function
    let shares = match aead::build_shares(&m.to_entropy(), k, n, pad) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

    Ok(shares)
}

/// Rebuild the encrypted secret from shares and produce a mnemonic from the entropy.
///
/// # Arguments
///
/// * `shares` - The shares that are to be used to rebuild the secret.
/// 
/// # Returns
///
/// * A vector of bytes representing the secret.
///
pub fn rebuild_secret_aead(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, ErrorBipAead> {
    // Rebuild the secret using the aead function
    let secret = match aead::rebuild_secret(shares) {
        Ok(secret) => secret,
        Err(e) => return Err(e.into()),
    };

    // Convert the entropy to a mnemonic
    let m = match Mnemonic::from_entropy(&secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBipAead::MnemonicError),
    };

    Ok(m.to_string().into_bytes())
}

/// Build the shares for a secret, using some predefined shares. Converting the mnemonic secret to entropy and then splitting the entropy into shares.
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
) -> Result<Vec<Vec<u8>>, ErrorBip> {
    // Verify that the secret is a valid mnemonic
    let m = match verify_mnemonic(secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBip::MnemonicError),
    };

    // Convert the mnemonic to entropy and build the shares, passing the predefined shares to the base function
    let shares = match base::build_shares_predefined(&m.to_entropy(), pre_shares, k, n, pad) {
        Ok(shares) => shares,
        Err(e) => return Err(e.into()),
    };

    Ok(shares)
}

/// Build the shares for a secret, using some predefined shares. Converting the mnemonic secret to entropy and then splitting the entropy into shares. The entropy is encrypted with XChaCha20Poly1305 and then the key is split into shares.
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
pub fn build_shares_aead_predefined(
    secret: &[u8],
    pre_shares: Vec<Vec<u8>>,
    k: usize,
    n: usize,
    pad: bool,
) -> Result<Vec<Vec<u8>>, ErrorBipAead> {
    // Verify that the secret is a valid mnemonic
    let m = match verify_mnemonic(secret) {
        Ok(m) => m,
        Err(_) => return Err(ErrorBipAead::MnemonicError),
    };

    // Convert the mnemonic to entropy and build the shares, passing the predefined shares to the aead function
    let shares = match aead::build_shares_predefined(&m.to_entropy(), pre_shares, k, n, pad) {
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
            rebuild_secret(build_shares(TEST_MNEMONIC.as_bytes(), 3, 5, false).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_bip_pad() {
        assert_eq!(
            TEST_MNEMONIC.as_bytes().to_vec(),
            rebuild_secret(build_shares(TEST_MNEMONIC.as_bytes(), 3, 5, true).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_bip_aead() {
        assert_eq!(
            TEST_MNEMONIC.as_bytes().to_vec(),
            rebuild_secret_aead(build_shares_aead(TEST_MNEMONIC.as_bytes(), 3, 5, false).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn test_bip_aead_pad() {
        assert_eq!(
            TEST_MNEMONIC.as_bytes().to_vec(),
            rebuild_secret_aead(build_shares_aead(TEST_MNEMONIC.as_bytes(), 3, 5, true).unwrap())
                .unwrap()
        );
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn test_build_shares_predefined() {
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

        let result = build_shares_predefined(secret, pre_shares.clone(), k, n, false);

        match result {
            Ok(shares) => {
                assert_eq!(shares.len(), 5); 

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
