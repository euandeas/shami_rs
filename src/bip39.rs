use std::fmt;

use bip39::Mnemonic;

use crate::aead;
use crate::base;

#[derive(Debug)]
pub enum ErrorBip {
    ZeroSharesError,
    ZeroMinimumSharesError,
    ThresholdError,
    MnemonicError,
}

#[derive(Debug)]
pub enum ErrorBipAead {
    ZeroSharesError,
    ZeroMinimumSharesError,
    ThresholdError,
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
        }
    }
}

impl From<base::Error> for ErrorBip {
    fn from(e: base::Error) -> Self {
        match e {
            base::Error::ZeroSharesError => ErrorBip::ZeroSharesError,
            base::Error::ZeroMinimumSharesError => ErrorBip::ZeroMinimumSharesError,
            base::Error::ThresholdError => ErrorBip::ThresholdError,
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
