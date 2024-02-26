use crate::shamirs::{BuildShares, RebuildSecret};
use bip39::Mnemonic;


fn print_bip() {
    let m = match Mnemonic::parse_normalized("hundred match learn goddess figure filter zone grocery step tuition manual marriage polar spice inquiry") {
        Ok(m) => m,
        Err(_) => return,
    };

    let entropy = &m.to_entropy_array().0[..(((m.word_count() as f64 * 352.0 / 33.0) / 8.0).ceil())];

        println!("{:?}", entropyw
        );
}

fn verify_mnemonic(secret: &[u8])  -> Result<Mnemonic, &'static str>{
    let string = match std::str::from_utf8(secret) {
        Ok(s) => s,
        Err(_) => return Err("Invalid String")
    };

    match Mnemonic::parse_normalized(string) {
        Ok(m) => Ok(m),
        Err(_) => Err("Invalid Mnemonic")
    }
}

/* d
pub fn build_shares_bip(
    secret: &[u8],
    k: usize,
    n: usize,
    f: BuildShares,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let m = verify_mnemonic(secret)?;
    
    f(str::trim(m.to_entropy_array().0).as_bytes(), k, n);
}

pub fn rebuild_secret_bip(shares: Vec<Vec<u8>>, f: RebuildSecret) -> Result<Vec<u8>, &'static str> {
    unimplemented!()
} */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip_simple() {
        print_bip();
    }
}
