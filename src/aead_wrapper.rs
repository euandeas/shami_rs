use crate::shamirs;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce
};

//https://docs.rs/chacha20poly1305/latest/chacha20poly1305/index.html

pub fn build_shares(secret: &[u8], k: usize, n: usize) -> Vec<Vec<u8>> {
    
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);
    let ciphertext = cipher.encrypt(XNonce::from_slice(&[0; 24]), secret)?;

    
    shamirs::build_shares(secret, k, n)
    //build_shares(key, k, n)
}

// TODO: Validate this works after changes to creating shares
pub fn rebuild_secret(shares: Vec<Vec<u8>>) -> Vec<u8> {
    
}
