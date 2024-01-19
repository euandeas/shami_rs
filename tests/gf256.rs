use shami_rs::gf256::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!((GF256(0b10011) + GF256(0b1000011)), GF256(0b1010000));
        assert_eq!((GF256(0b11) + GF256(0b1001)), GF256(0b1010));
    }

    #[test]
    fn test_sub() {
        assert_eq!((GF256(0b10011) - GF256(0b1000011)), GF256(0b1010000));
        assert_eq!((GF256(0b11) - GF256(0b1001)), GF256(0b1010));
    }

    #[test]
    fn test_mul() {
        assert_eq!((GF256(0b10011) * GF256(0b1000011)), GF256(0b10011001));
        assert_eq!((GF256(0b11) * GF256(0b1001)), GF256(0b11011));
        assert_eq!((GF256(0b11111111) * GF256(0b100000)), GF256(0b11010010));
        assert_eq!((GF256(0b11) * GF256(0b11)), GF256(0b101));
    }

    #[test]
    fn test_inv() {
        assert_eq!(GF256(0x02) * GF256(0x02).mul_inv(), GF256(0b1));
        assert_eq!(GF256(0x8a) * GF256(0x8a).mul_inv(), GF256(0b1));
    }
}
