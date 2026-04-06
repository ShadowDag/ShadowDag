// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// U256 — 256-bit unsigned integer for ShadowVM stack elements.
//
// Stored as [u64; 4] in little-endian limb order:
//   value = limbs[0] + limbs[1]*2^64 + limbs[2]*2^128 + limbs[3]*2^192
//
// Supports: add, sub, mul, div, mod, exp, bitwise, comparison, shifts
// All arithmetic is wrapping (modular 2^256) — same as Ethereum EVM.
// ═══════════════════════════════════════════════════════════════════════════

use std::fmt;
use crate::slog_warn;

/// 256-bit unsigned integer
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct U256(pub [u64; 4]); // Little-endian limbs

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE:  U256 = U256([1, 0, 0, 0]);
    pub const MAX:  U256 = U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);

    /// Create from a u64 value
    pub const fn from_u64(v: u64) -> Self {
        U256([v, 0, 0, 0])
    }

    /// Create from a u128 value
    pub const fn from_u128(v: u128) -> Self {
        U256([v as u64, (v >> 64) as u64, 0, 0])
    }

    /// Convert to u64 (truncates upper bits)
    pub fn as_u64(&self) -> u64 {
        self.0[0]
    }

    /// Convert to u128 (truncates upper bits)
    pub fn as_u128(&self) -> u128 {
        (self.0[1] as u128) << 64 | (self.0[0] as u128)
    }

    /// Convert to usize (truncates)
    pub fn as_usize(&self) -> usize {
        self.0[0] as usize
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Number of leading zeros across all 256 bits
    pub fn leading_zeros(&self) -> u32 {
        if self.0[3] != 0 { return self.0[3].leading_zeros(); }
        if self.0[2] != 0 { return 64 + self.0[2].leading_zeros(); }
        if self.0[1] != 0 { return 128 + self.0[1].leading_zeros(); }
        192 + self.0[0].leading_zeros()
    }

    /// Bit length (256 - leading_zeros)
    pub fn bit_len(&self) -> u32 {
        256 - self.leading_zeros()
    }

    /// Get specific byte (0 = least significant)
    pub fn byte(&self, index: usize) -> u8 {
        if index >= 32 { return 0; }
        let limb = index / 8;
        let shift = (index % 8) * 8;
        ((self.0[limb] >> shift) & 0xFF) as u8
    }

    // ── Arithmetic ──────────────────────────────────────────────

    /// Wrapping addition (mod 2^256)
    pub fn wrapping_add(self, rhs: U256) -> U256 {
        let (r0, c0) = self.0[0].overflowing_add(rhs.0[0]);
        let (r1, c1) = self.0[1].carrying_add(rhs.0[1], c0);
        let (r2, c2) = self.0[2].carrying_add(rhs.0[2], c1);
        let (r3, _)  = self.0[3].carrying_add(rhs.0[3], c2);
        U256([r0, r1, r2, r3])
    }

    /// Wrapping subtraction (mod 2^256)
    pub fn wrapping_sub(self, rhs: U256) -> U256 {
        let (r0, b0) = self.0[0].overflowing_sub(rhs.0[0]);
        let (r1, b1) = self.0[1].borrowing_sub(rhs.0[1], b0);
        let (r2, b2) = self.0[2].borrowing_sub(rhs.0[2], b1);
        let (r3, _)  = self.0[3].borrowing_sub(rhs.0[3], b2);
        U256([r0, r1, r2, r3])
    }

    /// Wrapping multiplication (lower 256 bits only)
    pub fn wrapping_mul(self, rhs: U256) -> U256 {
        let mut result = U256::ZERO;
        for i in 0..4 {
            let mut carry: u64 = 0;
            for j in 0..4 {
                if i + j >= 4 { break; }
                let prod = (self.0[i] as u128) * (rhs.0[j] as u128)
                    + (result.0[i + j] as u128)
                    + (carry as u128);
                result.0[i + j] = prod as u64;
                carry = (prod >> 64) as u64;
            }
        }
        result
    }

    /// Division (returns quotient). Division by zero returns 0.
    pub fn checked_div(self, rhs: U256) -> U256 {
        if rhs.is_zero() { return U256::ZERO; }
        if self < rhs { return U256::ZERO; }
        if self == rhs { return U256::ONE; }

        // Long division
        let mut quotient = U256::ZERO;
        let mut remainder = U256::ZERO;

        for i in (0..256).rev() {
            remainder = remainder.shl1();
            if self.bit(i) {
                remainder.0[0] |= 1;
            }
            if remainder >= rhs {
                remainder = remainder.wrapping_sub(rhs);
                quotient = quotient.set_bit(i);
            }
        }
        quotient
    }

    /// Modulo (returns remainder). Mod by zero returns 0.
    pub fn checked_mod(self, rhs: U256) -> U256 {
        if rhs.is_zero() { return U256::ZERO; }

        let mut remainder = U256::ZERO;
        for i in (0..256).rev() {
            remainder = remainder.shl1();
            if self.bit(i) {
                remainder.0[0] |= 1;
            }
            if remainder >= rhs {
                remainder = remainder.wrapping_sub(rhs);
            }
        }
        remainder
    }

    /// Exponentiation (modular, bounded to prevent DoS)
    pub fn wrapping_pow(self, exp: U256) -> U256 {
        if exp.is_zero() { return U256::ONE; }
        let mut result = U256::ONE;
        let mut base = self;
        let mut e = exp;

        let max_bits = 256u32.min(e.bit_len());
        for _ in 0..max_bits {
            if e.0[0] & 1 == 1 {
                result = result.wrapping_mul(base);
            }
            base = base.wrapping_mul(base);
            e = e.shr1();
        }
        result
    }

    // ── Bitwise ─────────────────────────────────────────────────

    #[allow(clippy::should_implement_trait)]
    pub fn bitand(self, rhs: U256) -> U256 {
        U256([self.0[0] & rhs.0[0], self.0[1] & rhs.0[1],
              self.0[2] & rhs.0[2], self.0[3] & rhs.0[3]])
    }

    #[allow(clippy::should_implement_trait)]
    pub fn bitor(self, rhs: U256) -> U256 {
        U256([self.0[0] | rhs.0[0], self.0[1] | rhs.0[1],
              self.0[2] | rhs.0[2], self.0[3] | rhs.0[3]])
    }

    #[allow(clippy::should_implement_trait)]
    pub fn bitxor(self, rhs: U256) -> U256 {
        U256([self.0[0] ^ rhs.0[0], self.0[1] ^ rhs.0[1],
              self.0[2] ^ rhs.0[2], self.0[3] ^ rhs.0[3]])
    }

    pub fn bitnot(self) -> U256 {
        U256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    /// Shift left by `n` bits
    #[allow(clippy::needless_range_loop, clippy::should_implement_trait)]
    pub fn shl(self, n: u32) -> U256 {
        if n >= 256 { return U256::ZERO; }
        if n == 0 { return self; }

        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;

        let mut result = [0u64; 4];
        for i in limb_shift..4 {
            result[i] = self.0[i - limb_shift] << bit_shift;
            if bit_shift > 0 && i > limb_shift {
                result[i] |= self.0[i - limb_shift - 1] >> (64 - bit_shift);
            }
        }
        U256(result)
    }

    /// Shift right by `n` bits
    #[allow(clippy::needless_range_loop, clippy::should_implement_trait)]
    pub fn shr(self, n: u32) -> U256 {
        if n >= 256 { return U256::ZERO; }
        if n == 0 { return self; }

        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;

        let mut result = [0u64; 4];
        for i in 0..4 - limb_shift {
            result[i] = self.0[i + limb_shift] >> bit_shift;
            if bit_shift > 0 && i + limb_shift + 1 < 4 {
                result[i] |= self.0[i + limb_shift + 1] << (64 - bit_shift);
            }
        }
        U256(result)
    }

    /// Arithmetic shift right (preserves sign bit for signed interpretation)
    pub fn sar(self, n: u32) -> U256 {
        let is_negative = self.0[3] >> 63 == 1;
        let mut result = self.shr(n);
        if is_negative && n > 0 {
            // Fill upper bits with 1s
            for i in (256u32.saturating_sub(n))..256 {
                result = result.set_bit(i as usize);
            }
        }
        result
    }

    // ── Helpers ──────────────────────────────────────────────────

    fn bit(&self, index: usize) -> bool {
        if index >= 256 { return false; }
        let limb = index / 64;
        let bit = index % 64;
        (self.0[limb] >> bit) & 1 == 1
    }

    fn set_bit(mut self, index: usize) -> Self {
        if index < 256 {
            let limb = index / 64;
            let bit = index % 64;
            self.0[limb] |= 1 << bit;
        }
        self
    }

    fn shl1(self) -> U256 {
        let mut r = [0u64; 4];
        r[0] = self.0[0] << 1;
        r[1] = (self.0[1] << 1) | (self.0[0] >> 63);
        r[2] = (self.0[2] << 1) | (self.0[1] >> 63);
        r[3] = (self.0[3] << 1) | (self.0[2] >> 63);
        U256(r)
    }

    fn shr1(self) -> U256 {
        let mut r = [0u64; 4];
        r[0] = (self.0[0] >> 1) | (self.0[1] << 63);
        r[1] = (self.0[1] >> 1) | (self.0[2] << 63);
        r[2] = (self.0[2] >> 1) | (self.0[3] << 63);
        r[3] = self.0[3] >> 1;
        U256(r)
    }

    /// From 32 big-endian bytes
    #[allow(clippy::needless_range_loop)]
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let offset = (3 - i) * 8;
            limbs[i] = u64::from_be_bytes([
                bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
            ]);
        }
        U256(limbs)
    }

    /// To 32 big-endian bytes
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let offset = (3 - i) * 8;
            bytes[offset..offset+8].copy_from_slice(&self.0[i].to_be_bytes());
        }
        bytes
    }

    /// From hex string
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() > 64 {
            slog_warn!("runtime", "u256_hex_too_long", length => &s.len().to_string());
            return None;
        }
        let padded = format!("{:0>64}", s);
        let bytes = hex::decode(&padded).ok()?;
        if bytes.len() != 32 { return None; }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Self::from_be_bytes(&arr))
    }

    /// To hex string (no 0x prefix)
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_be_bytes())
    }
}

// ── Comparison ──────────────────────────────────────────────────

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

// ── Display ─────────────────────────────────────────────────────

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "U256(0x{})", self.to_hex())
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 {
            write!(f, "{}", self.0[0])
        } else {
            write!(f, "0x{}", self.to_hex())
        }
    }
}

// ── From traits ─────────────────────────────────────────────────

impl From<u64> for U256 {
    fn from(v: u64) -> Self { U256::from_u64(v) }
}

impl From<u128> for U256 {
    fn from(v: u128) -> Self { U256::from_u128(v) }
}

impl From<bool> for U256 {
    fn from(v: bool) -> Self { if v { U256::ONE } else { U256::ZERO } }
}

impl From<usize> for U256 {
    fn from(v: usize) -> Self { U256::from_u64(v as u64) }
}

// ═══════════════════════════════════════════════════════════════════════════
//                            TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_one() {
        assert!(U256::ZERO.is_zero());
        assert!(!U256::ONE.is_zero());
        assert_eq!(U256::ONE.as_u64(), 1);
    }

    #[test]
    fn from_u64() {
        let v = U256::from_u64(42);
        assert_eq!(v.as_u64(), 42);
        assert_eq!(v.0[1], 0);
    }

    #[test]
    fn from_u128() {
        let v = U256::from_u128(u128::MAX);
        assert_eq!(v.0[0], u64::MAX);
        assert_eq!(v.0[1], u64::MAX);
        assert_eq!(v.0[2], 0);
    }

    #[test]
    fn addition() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        assert_eq!(a.wrapping_add(b).as_u64(), 300);
    }

    #[test]
    fn addition_overflow_wraps() {
        let a = U256::MAX;
        let b = U256::ONE;
        assert_eq!(a.wrapping_add(b), U256::ZERO);
    }

    #[test]
    fn subtraction() {
        let a = U256::from_u64(500);
        let b = U256::from_u64(200);
        assert_eq!(a.wrapping_sub(b).as_u64(), 300);
    }

    #[test]
    fn subtraction_underflow_wraps() {
        let a = U256::ZERO;
        let b = U256::ONE;
        assert_eq!(a.wrapping_sub(b), U256::MAX);
    }

    #[test]
    fn multiplication() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        assert_eq!(a.wrapping_mul(b).as_u64(), 20_000);
    }

    #[test]
    fn multiplication_large() {
        let a = U256::from_u64(u64::MAX);
        let b = U256::from_u64(2);
        let r = a.wrapping_mul(b);
        assert_eq!(r.0[0], u64::MAX - 1); // lower 64 bits
        assert_eq!(r.0[1], 1);             // carry
    }

    #[test]
    fn division() {
        assert_eq!(U256::from_u64(100).checked_div(U256::from_u64(3)).as_u64(), 33);
        assert_eq!(U256::from_u64(100).checked_div(U256::from_u64(100)), U256::ONE);
        assert_eq!(U256::from_u64(10).checked_div(U256::ZERO), U256::ZERO);
    }

    #[test]
    fn modulo() {
        assert_eq!(U256::from_u64(100).checked_mod(U256::from_u64(3)).as_u64(), 1);
        assert_eq!(U256::from_u64(10).checked_mod(U256::ZERO), U256::ZERO);
    }

    #[test]
    fn exponentiation() {
        let base = U256::from_u64(2);
        let exp = U256::from_u64(10);
        assert_eq!(base.wrapping_pow(exp).as_u64(), 1024);
    }

    #[test]
    fn bitwise_and() {
        let a = U256::from_u64(0xFF00);
        let b = U256::from_u64(0x0FF0);
        assert_eq!(a.bitand(b).as_u64(), 0x0F00);
    }

    #[test]
    fn bitwise_or() {
        let a = U256::from_u64(0xFF00);
        let b = U256::from_u64(0x00FF);
        assert_eq!(a.bitor(b).as_u64(), 0xFFFF);
    }

    #[test]
    fn bitwise_xor() {
        let a = U256::from_u64(0xFF);
        assert_eq!(a.bitxor(a), U256::ZERO);
    }

    #[test]
    fn bitwise_not() {
        assert_eq!(U256::ZERO.bitnot(), U256::MAX);
    }

    #[test]
    fn shift_left() {
        let a = U256::from_u64(1);
        assert_eq!(a.shl(64).0[1], 1);
        assert_eq!(a.shl(64).0[0], 0);
        assert_eq!(a.shl(128).0[2], 1);
    }

    #[test]
    fn shift_right() {
        let a = U256([0, 1, 0, 0]); // 2^64
        assert_eq!(a.shr(64).as_u64(), 1);
    }

    #[test]
    fn shift_256_is_zero() {
        assert_eq!(U256::MAX.shl(256), U256::ZERO);
        assert_eq!(U256::MAX.shr(256), U256::ZERO);
    }

    #[test]
    fn comparison() {
        assert!(U256::from_u64(10) > U256::from_u64(5));
        assert!(U256::from_u64(5) < U256::from_u64(10));
        assert_eq!(U256::from_u64(7), U256::from_u64(7));
    }

    #[test]
    fn comparison_large() {
        let a = U256([0, 0, 0, 1]); // 2^192
        let b = U256::from_u64(u64::MAX);
        assert!(a > b);
    }

    #[test]
    fn be_bytes_roundtrip() {
        let v = U256([1, 2, 3, 4]);
        let bytes = v.to_be_bytes();
        let restored = U256::from_be_bytes(&bytes);
        assert_eq!(v, restored);
    }

    #[test]
    fn hex_roundtrip() {
        let v = U256::from_u64(0xDEADBEEF);
        let hex = v.to_hex();
        let restored = U256::from_hex(&hex).unwrap();
        assert_eq!(v, restored);
    }

    #[test]
    fn byte_extraction() {
        let v = U256::from_u64(0x1234);
        assert_eq!(v.byte(0), 0x34);
        assert_eq!(v.byte(1), 0x12);
    }

    #[test]
    fn bit_length() {
        assert_eq!(U256::ZERO.bit_len(), 0);
        assert_eq!(U256::ONE.bit_len(), 1);
        assert_eq!(U256::from_u64(255).bit_len(), 8);
        assert_eq!(U256::MAX.bit_len(), 256);
    }

    #[test]
    fn display_small() {
        assert_eq!(format!("{}", U256::from_u64(42)), "42");
    }

    #[test]
    fn display_large() {
        let v = U256([0, 1, 0, 0]);
        assert!(format!("{}", v).starts_with("0x"));
    }

    #[test]
    fn from_bool() {
        assert_eq!(U256::from(true), U256::ONE);
        assert_eq!(U256::from(false), U256::ZERO);
    }

    #[test]
    fn addmod_simulation() {
        // (a + b) % n
        let a = U256::from_u64(7);
        let b = U256::from_u64(5);
        let n = U256::from_u64(6);
        let result = a.wrapping_add(b).checked_mod(n);
        assert_eq!(result.as_u64(), 0); // (7+5) % 6 = 0
    }

    #[test]
    fn mulmod_simulation() {
        let a = U256::from_u64(7);
        let b = U256::from_u64(3);
        let n = U256::from_u64(10);
        let result = a.wrapping_mul(b).checked_mod(n);
        assert_eq!(result.as_u64(), 1); // (7*3) % 10 = 1
    }
}
