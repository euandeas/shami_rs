use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

// Primitive Polynomial x^8 + x^4 + x^3 + x + 1 with the high term eliminated.
const PRIMITIVE: u8 = 0x1b;

// Galois Field 2^8 (256) type
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct GF256(u8);

// Constants for GF256 and conversion to u8 
impl GF256 {
    pub const ZERO: Self = GF256(0);
    pub const ONE: Self = GF256(1);

    pub fn as_u8(self) -> u8 {
        self.0
    }
}

// Conversion from u8 to GF256
impl From<u8> for GF256 {
    fn from(val: u8) -> GF256 {
        GF256(val)
    }
}

// Addition in Galois Field
impl Add for GF256 {
    type Output = GF256;

    fn add(self, other: GF256) -> GF256 {
        #[allow(clippy::suspicious_arithmetic_impl)]
        GF256(self.0 ^ other.0)
    }
}

// In-place addition in Galois Field
impl AddAssign for GF256 {
    fn add_assign(&mut self, other: GF256) {
        *self = self.add(other);
    }
}

// Subtraction in Galois Field
impl Sub for GF256 {
    type Output = GF256;

    fn sub(self, other: GF256) -> GF256 {
        self.add(other)
    }
}

// In-place subtraction in Galois Field
impl SubAssign for GF256 {
    fn sub_assign(&mut self, other: GF256) {
        self.add_assign(other)
    }
}

// Multiplication in Galois Field
impl Mul for GF256 {
    type Output = GF256;

    fn mul(self, other: GF256) -> GF256 {
        // Russian Peasant Multiplication
        let mut a: u8 = self.0;
        let mut b: u8 = other.0;
        let mut p: u8 = 0_u8;

        for _ in 0..8 {
            // if b & 1 == 1 {
            //     p ^= a;
            // }
            // BIT MASKED:
            p ^= a & (b & 1).wrapping_neg();

            b >>= 1;

            let carry: u8 = a & 0x80;

            a <<= 1;

            // if carry != 0 {
            //     a ^= PRIMITIVE;
            // }
            // BIT MASKED:
            a ^= ((carry >> 7) & 1) * PRIMITIVE;
        }

        GF256(p)
    }
}

// In-place multiplication in Galois Field
impl MulAssign for GF256 {
    fn mul_assign(&mut self, other: Self) {
        *self = self.mul(other)
    }
}

// Inverse in Galois Field
impl GF256 {
    pub fn mul_inv(self) -> GF256 {
        let mut r: GF256;
        let mut y: GF256;
        let mut z: GF256;

        // Fermat's Little Theorem (Fast Multiplicative Inverse Algorithm)
        y = self * self; // y = x^2
        y *= y; // y = x^4
        r = y * y; // r = x^8
        z = r * self; // z = x^9
        r *= r; // r = x^16
        r *= z; // r = x^25
        r *= r; // r = x^50
        z = r * r; // z = x^100
        z *= z; // z = x^200
        r *= z; // r = x^250
        r *= y; // r = x^254

        r
    }
}

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
