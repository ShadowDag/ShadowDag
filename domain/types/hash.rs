// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Strict hex-hash parsing utilities.
//
// CONSENSUS CRITICAL — every function in this module is designed to REJECT
// ambiguous input rather than silently normalize it.  Silent normalization
// (zero-padding, truncation, raw-byte fallback) leads to nodes computing
// different hashes from the same "input", which causes chain forks.
//
// Rule of thumb:  if the input doesn't look exactly right → Err / None.
// ═══════════════════════════════════════════════════════════════════════════

use std::fmt;

pub type HashValue = String;

// ─────────────────────────────────────────────────────────────────────────
//  Error type
// ─────────────────────────────────────────────────────────────────────────

/// Reason a hex string was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexParseError {
    /// After normalization (trim, strip "0x"), length ≠ expected hex chars.
    BadLength { expected: usize, got: usize },
    /// Contains a non-hex byte at the given offset.
    InvalidChar { offset: usize, byte: u8 },
    /// Caller passed an empty / whitespace-only string.
    Empty,
}

impl fmt::Display for HexParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { expected, got } => {
                write!(f, "hex length {}, expected {}", got, expected)
            }
            Self::InvalidChar { offset, byte } => {
                write!(f, "non-hex byte 0x{:02X} at offset {}", byte, offset)
            }
            Self::Empty => write!(f, "empty hex string"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Core strict parser
// ─────────────────────────────────────────────────────────────────────────

/// Normalize a hex string: trim whitespace, strip optional "0x"/"0X" prefix.
///
/// Returns the clean inner slice — never allocates.
#[inline]
pub fn normalize_hex(raw: &str) -> &str {
    let s = raw.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        &s[2..]
    } else {
        s
    }
}

/// Validate that `hex` (already normalized) is exactly `expected_chars` long
/// and every byte is ASCII hex.  Returns the first error found, if any.
pub fn validate_hex_strict(hex: &str, expected_chars: usize) -> Result<(), HexParseError> {
    if hex.is_empty() {
        return Err(HexParseError::Empty);
    }
    if hex.len() != expected_chars {
        return Err(HexParseError::BadLength {
            expected: expected_chars,
            got: hex.len(),
        });
    }
    for (i, b) in hex.bytes().enumerate() {
        if !b.is_ascii_hexdigit() {
            return Err(HexParseError::InvalidChar { offset: i, byte: b });
        }
    }
    Ok(())
}

/// Parse a **32-byte hash** from a hex string.
///
/// STRICT:
///   - Trims whitespace, strips "0x" prefix
///   - Rejects anything that isn't exactly 64 hex characters
///   - Rejects non-hex bytes (no silent zero-mapping)
///   - Returns the decoded 32 bytes on success
///
/// This is the ONE canonical way to parse a tx hash, block hash, or any
/// 256-bit identifier from untrusted/external input.
pub fn parse_hash256(raw: &str) -> Result<[u8; 32], HexParseError> {
    let hex = normalize_hex(raw);
    validate_hex_strict(hex, 64)?;
    // Validation passed — hex::decode cannot fail on validated input.
    // Use map_err to convert any (impossible) failure into our error type
    // rather than panicking.
    let bytes = hex::decode(hex).map_err(|_| HexParseError::InvalidChar { offset: 0, byte: 0 })?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a hex string of **arbitrary expected byte-length**.
///
/// Same strictness as `parse_hash256` but for any target size.
pub fn parse_hex_exact(raw: &str, expected_bytes: usize) -> Result<Vec<u8>, HexParseError> {
    let hex = normalize_hex(raw);
    validate_hex_strict(hex, expected_bytes * 2)?;
    let bytes = hex::decode(hex).map_err(|_| HexParseError::InvalidChar { offset: 0, byte: 0 })?;
    Ok(bytes)
}

/// Convenience: validate a hex hash string without decoding.
///
/// Returns `true` only if the string is exactly 64 hex chars after
/// normalization.  Suitable for quick checks before deeper processing.
#[inline]
pub fn is_valid_hash256(raw: &str) -> bool {
    parse_hash256(raw).is_ok()
}

/// Truncate a string to at most `max_bytes` for logging — never panics.
///
/// USE THIS INSTEAD OF `&s[..s.len().min(n)]`. Slicing a `str` panics when the
/// index lands inside a multi-byte UTF-8 character, so that idiom is a remote
/// crash vector anywhere the string arrived over the network: a peer puts one
/// non-ASCII byte in a hash-shaped field and every node that logs it aborts.
/// It is not enough that hashes are "supposed to be" ASCII hex — these log and
/// error sites run on the REJECTION path, i.e. precisely when the input is
/// malformed. Back off to the nearest character boundary instead.
#[inline]
pub fn log_prefix(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ─────────────────────────────────────────────────────────────────────────
//  Legacy helper (kept for backward compat)
// ─────────────────────────────────────────────────────────────────────────

pub struct HashHelper;

impl HashHelper {
    pub fn meets_difficulty(hash: &str, difficulty: u64) -> bool {
        crate::engine::mining::pow::pow_validator::PowValidator::hash_meets_target(hash, difficulty)
    }

    pub fn zero() -> String {
        "0".repeat(64)
    }

    /// Strict validation: exactly 64 hex chars, no prefix, no whitespace.
    pub fn is_valid(hash: &str) -> bool {
        is_valid_hash256(hash)
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_hash() {
        let hex = "aa".repeat(32);
        let result = parse_hash256(&hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0xAA; 32]);
    }

    #[test]
    fn log_prefix_never_splits_a_multibyte_char() {
        // The exact remote-DoS shape: an attacker-supplied "hash" whose byte 16
        // falls inside a 3-byte character. `&s[..16]` aborts the process here.
        let hostile = "aaaaaaaaaaaaaaa\u{1F600}bbbb";
        assert!(!hostile.is_char_boundary(16));
        let out = log_prefix(hostile, 16);
        assert_eq!(out, "aaaaaaaaaaaaaaa");
        assert!(hostile.starts_with(out));

        // A cut landing exactly on a boundary keeps the full budget.
        assert_eq!(log_prefix("abcdefghijklmnop_tail", 16), "abcdefghijklmnop");
        // Shorter than the budget is returned whole, including non-ASCII.
        assert_eq!(log_prefix("\u{1F600}", 16), "\u{1F600}");
        // Degenerate budgets must not panic either.
        assert_eq!(log_prefix("\u{1F600}tail", 1), "");
        assert_eq!(log_prefix("anything", 0), "");
        assert_eq!(log_prefix("", 16), "");
    }

    #[test]
    fn parse_with_0x_prefix() {
        let hex = format!("0x{}", "bb".repeat(32));
        assert!(parse_hash256(&hex).is_ok());
    }

    #[test]
    fn parse_with_whitespace() {
        let hex = format!("  {}  ", "cc".repeat(32));
        assert!(parse_hash256(&hex).is_ok());
    }

    #[test]
    fn reject_short() {
        assert_eq!(
            parse_hash256("aabb"),
            Err(HexParseError::BadLength {
                expected: 64,
                got: 4
            })
        );
    }

    #[test]
    fn reject_long() {
        let hex = "aa".repeat(33); // 66 chars
        assert_eq!(
            parse_hash256(&hex),
            Err(HexParseError::BadLength {
                expected: 64,
                got: 66
            })
        );
    }

    #[test]
    fn reject_non_hex_char() {
        let mut bad = "aa".repeat(32);
        bad.replace_range(0..1, "g");
        let err = parse_hash256(&bad).unwrap_err();
        assert!(matches!(
            err,
            HexParseError::InvalidChar {
                offset: 0,
                byte: b'g'
            }
        ));
    }

    #[test]
    fn reject_empty() {
        assert_eq!(parse_hash256(""), Err(HexParseError::Empty));
        assert_eq!(parse_hash256("   "), Err(HexParseError::Empty));
    }

    #[test]
    fn case_insensitive() {
        let lower = parse_hash256(&"ab".repeat(32)).unwrap();
        let upper = parse_hash256(&"AB".repeat(32)).unwrap();
        assert_eq!(lower, upper);
    }

    #[test]
    fn is_valid_hash256_works() {
        assert!(is_valid_hash256(&"ff".repeat(32)));
        assert!(!is_valid_hash256("short"));
        assert!(!is_valid_hash256(""));
    }

    #[test]
    fn parse_hex_exact_20_bytes() {
        let hex = "ab".repeat(20);
        let result = parse_hex_exact(&hex, 20);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 20);
    }

    #[test]
    fn parse_hex_exact_rejects_wrong_len() {
        let hex = "ab".repeat(20);
        assert!(parse_hex_exact(&hex, 32).is_err());
    }

    #[test]
    fn hashhelper_is_valid_strict() {
        // Old behavior was: "SD1abc".len()==6 → false. Still false.
        assert!(!HashHelper::is_valid("SD1abc"));
        // Valid 64-char hex passes
        assert!(HashHelper::is_valid(&"00".repeat(32)));
        // With 0x prefix — normalize strips it, len becomes 64 → valid
        assert!(HashHelper::is_valid(&format!("0x{}", "ff".repeat(32))));
    }
}
