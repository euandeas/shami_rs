use crate::shamirs::{BuildShares, RebuildSecret};
use bip39::Mnemonic;

fn print_bip() {
    let m = match Mnemonic::parse_normalized("hundred match learn goddess figure filter zone grocery step tuition manual marriage polar spice inquiry") {
        Ok(m) => m,
        Err(_) => return,
    };

    for (word) in m.word_iter() {
        println!(
            "{}, {:?}",
            word,
            Mnemonic::from_entropy(&(m.to_entropy_array().0)[..20])
                .unwrap()
                .to_string()
        );
    }
}

pub fn build_shares_bip(
    secret: &[u8],
    k: usize,
    n: usize,
    f: BuildShares,
) -> Result<Vec<Vec<u8>>, &'static str> {
    unimplemented!()
}

pub fn rebuild_secret_bip(shares: Vec<Vec<u8>>, f: RebuildSecret) -> Result<Vec<u8>, &'static str> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip_simple() {
        print_bip();
    }
}
