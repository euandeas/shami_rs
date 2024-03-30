use block_padding::{Pkcs7, RawPadding};
use rand_core::{OsRng, RngCore};
use std::collections::HashSet;

fn random_no_zero() -> u8 {
    let mut rnd = OsRng.next_u64() as u8;
    while rnd == 0 {
        rnd = OsRng.next_u64() as u8;
    }

    rnd
}

pub fn random_no_zero_distinct_set(k: usize) -> Vec<u8> {
    let mut out_map = HashSet::new();
    while out_map.len() < k {
        out_map.insert(random_no_zero());
    }

    out_map.into_iter().collect::<Vec<u8>>()
}

#[cfg(feature = "experimental")]
pub fn random_no_zero_distinct_set_with_preset(k: usize, v: Vec<u8>) -> Vec<u8> {
    let mut out_map = HashSet::new();

    while out_map.len() < k {
        let val = random_no_zero();
        if !v.contains(&val) {
            out_map.insert(val);
        }
    }

    out_map.into_iter().collect::<Vec<u8>>()
}

pub fn pkcs7_pad(msg: &[u8]) -> Vec<u8> {
    let len = msg.len();

    if len % 8 == 7 {
        return msg.to_vec();
    }

    let mut pad_len = ((len + 7) / 8 * 8) - 1;

    if pad_len < len {
        pad_len += 8;
    }

    let mut block = vec![0; pad_len];
    block[..len].copy_from_slice(msg);
    Pkcs7::raw_pad(block.as_mut_slice(), len);
    block
}

pub fn pkcs7_unpad(input: Vec<u8>) -> Vec<u8> {
    match Pkcs7::raw_unpad(input.as_slice()) {
        Ok(v) => v.to_vec(),
        Err(_) => input.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_zero() {
        for _ in 0..10000 {
            assert_ne!(random_no_zero(), 0);
        }
    }

    #[test]
    fn test_random_no_zero_distinct_set() {
        for _ in 0..10000 {
            let result = random_no_zero_distinct_set(10);
            let set: HashSet<_> = result.iter().collect();
            assert_eq!(result.len(), set.len());
        }
    }

    #[test]
    fn test_pad() {
        let result = pkcs7_pad("YELLOW SUBMARINE".as_bytes());
        let result2 = pkcs7_pad("YELLOW SUBMARINE!".as_bytes());
        assert_eq!(
            result.as_slice(),
            b"YELLOW SUBMARINE\x07\x07\x07\x07\x07\x07\x07"
        );
        assert_eq!(
            result2.as_slice(),
            b"YELLOW SUBMARINE!\x06\x06\x06\x06\x06\x06"
        );
        assert_eq!(
            "YELLOW SUBMARINE",
            String::from_utf8_lossy(pkcs7_unpad(result).as_slice())
        );
        assert_eq!(
            "YELLOW SUBMARINE",
            String::from_utf8_lossy(pkcs7_unpad("YELLOW SUBMARINE".as_bytes().to_vec()).as_slice())
        );
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn test_random_no_zero_distinct_set_with_preset() {
        let result = random_no_zero_distinct_set_with_preset(10, vec![1, 2, 3, 4, 5]);
        assert_eq!(result.len(), 10);
        assert_ne!(result.contains(&1), true);
        assert_ne!(result.contains(&2), true);
        assert_ne!(result.contains(&3), true);
        assert_ne!(result.contains(&4), true);
        assert_ne!(result.contains(&5), true);
    }
}
