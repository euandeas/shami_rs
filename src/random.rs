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
}
