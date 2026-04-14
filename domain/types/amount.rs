// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Amount — All monetary values are stored as u64 integers (satoshis).
// 1 SDAG = 100,000,000 satoshis (like Bitcoin).
// NEVER use floating-point for consensus-critical amounts.
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::CryptoError;

pub type Amount = u64;

pub struct AmountHelper;

impl AmountHelper {
    pub const COIN: u64 = 100_000_000; // 1 SDAG
    pub const HALF_COIN: u64 = 50_000_000; // 0.5 SDAG
    pub const MIN_AMOUNT: u64 = 1; // 1 satoshi
    pub const MAX_AMOUNT: u64 = 21_000_000_000 * 100_000_000; // 21 billion SDAG

    /// Convert SDAG string to satoshis (integer-only, no floating point)
    /// "10.5" → 1_050_000_000
    pub fn parse_sdag(s: &str) -> Result<u64, CryptoError> {
        let parts: Vec<&str> = s.split('.').collect();
        match parts.len() {
            1 => {
                let whole: u64 = parts[0]
                    .parse()
                    .map_err(|e| CryptoError::Other(format!("Invalid amount: {}", e)))?;
                whole
                    .checked_mul(Self::COIN)
                    .ok_or_else(|| CryptoError::Other("Amount overflow".to_string()))
            }
            2 => {
                let whole: u64 = parts[0]
                    .parse()
                    .map_err(|e| CryptoError::Other(format!("Invalid whole part: {}", e)))?;
                let frac_str = parts[1];
                if frac_str.len() > 8 {
                    return Err(CryptoError::Other("Maximum 8 decimal places".to_string()));
                }
                // Pad to 8 digits
                let padded = format!("{:0<8}", frac_str);
                let frac: u64 = padded
                    .parse()
                    .map_err(|e| CryptoError::Other(format!("Invalid fraction: {}", e)))?;

                let whole_sats = whole
                    .checked_mul(Self::COIN)
                    .ok_or_else(|| CryptoError::Other("Amount overflow".to_string()))?;
                whole_sats
                    .checked_add(frac)
                    .ok_or_else(|| CryptoError::Other("Amount overflow".to_string()))
            }
            _ => Err(CryptoError::Other(
                "Invalid format: too many decimal points".to_string(),
            )),
        }
    }

    /// Format satoshis as human-readable SDAG string (for display only, NOT consensus)
    pub fn format(satoshis: u64) -> String {
        let whole = satoshis / Self::COIN;
        let frac = satoshis % Self::COIN;
        format!("{}.{:08} SDAG", whole, frac)
    }

    /// Safe addition with overflow check
    pub fn checked_add(a: u64, b: u64) -> Result<u64, CryptoError> {
        a.checked_add(b)
            .ok_or_else(|| CryptoError::Other("Amount addition overflow".to_string()))
    }

    /// Safe subtraction with underflow check
    pub fn checked_sub(a: u64, b: u64) -> Result<u64, CryptoError> {
        a.checked_sub(b)
            .ok_or_else(|| CryptoError::Other("Amount subtraction underflow".to_string()))
    }

    /// Safe multiplication with overflow check
    pub fn checked_mul(a: u64, b: u64) -> Result<u64, CryptoError> {
        a.checked_mul(b)
            .ok_or_else(|| CryptoError::Other("Amount multiplication overflow".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_whole_number() {
        assert_eq!(
            AmountHelper::parse_sdag("10").unwrap(),
            10 * AmountHelper::COIN
        );
    }

    #[test]
    fn parse_with_decimals() {
        assert_eq!(AmountHelper::parse_sdag("10.5").unwrap(), 1_050_000_000);
        assert_eq!(AmountHelper::parse_sdag("0.00000001").unwrap(), 1); // 1 satoshi
    }

    #[test]
    fn parse_rejects_too_many_decimals() {
        assert!(AmountHelper::parse_sdag("1.000000001").is_err());
    }

    #[test]
    fn format_output() {
        assert_eq!(AmountHelper::format(1_050_000_000), "10.50000000 SDAG");
        assert_eq!(AmountHelper::format(1), "0.00000001 SDAG");
        assert_eq!(AmountHelper::format(0), "0.00000000 SDAG");
    }

    #[test]
    fn checked_add_overflow() {
        assert!(AmountHelper::checked_add(u64::MAX, 1).is_err());
        assert_eq!(AmountHelper::checked_add(100, 200).unwrap(), 300);
    }

    #[test]
    fn checked_sub_underflow() {
        assert!(AmountHelper::checked_sub(10, 20).is_err());
        assert_eq!(AmountHelper::checked_sub(100, 30).unwrap(), 70);
    }

    #[test]
    fn no_floating_point_precision_loss() {
        // This is why we use integer math: 0.1 + 0.2 != 0.3 in float
        let a = AmountHelper::parse_sdag("0.1").unwrap();
        let b = AmountHelper::parse_sdag("0.2").unwrap();
        let sum = AmountHelper::checked_add(a, b).unwrap();
        let expected = AmountHelper::parse_sdag("0.3").unwrap();
        assert_eq!(sum, expected, "Integer math must be exact");
    }
}
