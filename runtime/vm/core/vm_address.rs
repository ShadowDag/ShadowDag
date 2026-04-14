// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// VmAddressBody — canonical 20-byte address body for VM stack encoding.
//
// Background
// ----------
// ShadowDAG addresses are network-prefixed strings like `SD1cABCDEF…` with
// several recognized formats:
//
//   Standard EOA : {SD1|ST1|SR1}{40 hex}           (3 + 40 = 43 chars)
//   Contract     : {SD1|ST1|SR1}c{40 hex}          (3 + 1 + 40 = 44 chars)
//   Token        : {SD1|ST1|SR1}t{40 hex}          (3 + 1 + 40 = 44 chars)
//   Stealth      : {SD1|ST1|SR1}s{40 hex}          (4 + 40 = 44 chars)
//   Schnorr      : {SD1|ST1|SR1}k{40 hex}          (4 + 40 = 44 chars)
//   P2SH         : {SD1|ST1|SR1}h{40 hex}          (4 + 40 = 44 chars)
//
// Every canonical format embeds a **20-byte body** — the SHA-256-derived
// hash at the end of the string. That 20-byte body is the natural
// EVM-compatible representation for an address on the VM stack.
//
// The previous CALLER/ADDRESS implementation pushed
// `U256::from_hex(hex::encode(addr.as_bytes()))`, which tried to fit the
// entire UTF-8 address string into the U256 word via its hex encoding.
// For a typical 44-char contract address that produces an 88-char hex
// string, which exceeds `U256::from_hex`'s 64-char limit and silently
// fell back to `U256::ZERO`. So `CALLER` literally pushed `0` for any
// real contract address, and any subsequent `BALANCE(CALLER)` /
// `CALL(…, CALLER, …)` lookup looked up the zero key, returning 0 /
// targeting nothing. This module is the EVM-style canonical-bytes fix.
//
// Layout on the U256 stack
// ------------------------
// The 20-byte body is RIGHT-aligned in a 32-byte (U256) word, matching
// Ethereum's address convention:
//
//   bytes  0..12  = zero padding
//   bytes 12..32  = 20-byte canonical body
//
// `from_u256` extracts the low 20 bytes; `to_u256` zero-pads to 32.

use crate::runtime::vm::core::u256::U256;

/// 20-byte canonical address body, right-aligned when projected onto a U256
/// stack word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VmAddressBody(pub [u8; 20]);

impl VmAddressBody {
    /// All-zero body. Used as the fallback when an address string does not
    /// match any canonical ShadowDAG format.
    pub const ZERO: Self = Self([0u8; 20]);

    /// Parse a 20-byte canonical body from a ShadowDAG address string.
    ///
    /// Accepts every canonical format documented at the top of this module:
    /// standard EOA, contract, token, stealth, schnorr, and P2SH. The
    /// parser extracts the trailing 40-hex-char body and decodes it to 20
    /// bytes; non-hex or wrong-length strings return `None` so callers
    /// can surface the failure explicitly.
    ///
    /// Non-canonical strings (ad-hoc test fixtures like `"caller"` or
    /// `"contract_a"`) return `None`. Callers that need a stable
    /// encoding for those can derive a synthetic body via
    /// [`Self::derive_from_nonstandard`].
    pub fn from_address_string(s: &str) -> Option<Self> {
        if !(s.starts_with("SD1") || s.starts_with("ST1") || s.starts_with("SR1")) {
            return None;
        }
        if s.len() < 4 {
            return None;
        }
        // Inspect the 4th byte to tell apart the subtype prefixes.
        let body_hex = match s.as_bytes()[3] {
            b'c' | b't' | b's' | b'k' | b'h' => {
                // 4-char prefix + 40-char body
                if s.len() != 44 {
                    return None;
                }
                &s[4..]
            }
            _ => {
                // 3-char prefix + 40-char body
                if s.len() != 43 {
                    return None;
                }
                &s[3..]
            }
        };
        if body_hex.len() != 40 {
            return None;
        }
        let bytes = hex::decode(body_hex).ok()?;
        if bytes.len() != 20 {
            return None;
        }
        let mut body = [0u8; 20];
        body.copy_from_slice(&bytes);
        Some(Self(body))
    }

    /// Derive a deterministic synthetic 20-byte body from a non-canonical
    /// address string (e.g. `"caller"`, `"target"`). Used by the
    /// ExecutionEnvironment address registry so that ad-hoc test fixtures
    /// still round-trip through the stack.
    ///
    /// The derivation is `SHA-256(b"ShadowDAG_VmAddress_v1" || s.as_bytes())[..20]`.
    /// It is NOT reversible — the registry stores the original string
    /// alongside the derived body so `resolve_address` can recover it.
    pub fn derive_from_nonstandard(s: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_VmAddress_v1");
        h.update(s.as_bytes());
        let hash = h.finalize();
        let mut body = [0u8; 20];
        body.copy_from_slice(&hash[..20]);
        Self(body)
    }

    /// Parse a canonical body if possible, otherwise derive a synthetic
    /// one. Always returns a usable 20-byte body, which is what CALLER /
    /// ADDRESS need in order to push *something* onto the stack even when
    /// `ctx.caller` is an ad-hoc test string like `"caller"`.
    pub fn from_any(s: &str) -> Self {
        Self::from_address_string(s).unwrap_or_else(|| Self::derive_from_nonstandard(s))
    }

    /// Right-align the 20-byte body in a 32-byte word, matching the
    /// Ethereum convention where addresses live in the low 20 bytes of
    /// a U256 with 12 leading zero bytes.
    pub fn to_u256(&self) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[12..32].copy_from_slice(&self.0);
        U256::from_be_bytes(&bytes)
    }

    /// Extract the low 20 bytes of a U256 word as a canonical body.
    pub fn from_u256(u: U256) -> Self {
        let bytes = u.to_be_bytes();
        let mut body = [0u8; 20];
        body.copy_from_slice(&bytes[12..32]);
        Self(body)
    }

    /// Reconstruct a fallback ShadowDAG address string for this body,
    /// using the supplied network as a prefix and a default `'c'` type
    /// marker (contract). This is the format used when an address appears
    /// on the stack without having been registered by CALLER / ADDRESS /
    /// CREATE — for example a contract that executes `PUSH20` directly.
    ///
    /// Layout: `{SD1|ST1|SR1}c{40-hex body}`.
    pub fn to_fallback_string(&self, network: &str) -> String {
        let prefix = match network {
            "testnet" => "ST1",
            "regtest" => "SR1",
            _ => "SD1",
        };
        format!("{}c{}", prefix, hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_contract_address() {
        // SD1c + 40 hex chars (all 'a')
        let s = format!("SD1c{}", "a".repeat(40));
        let body = VmAddressBody::from_address_string(&s).expect("must parse");
        assert_eq!(body.0, [0xaa; 20]);
    }

    #[test]
    fn parses_canonical_eoa_address() {
        // SD1 + 40 hex chars (all '5')
        let s = format!("SD1{}", "5".repeat(40));
        let body = VmAddressBody::from_address_string(&s).expect("must parse");
        assert_eq!(body.0, [0x55; 20]);
    }

    #[test]
    fn parses_canonical_token_address() {
        // ST1t + 40 hex chars (all '0b')
        let s = format!("ST1t{}", "0b".repeat(20));
        let body = VmAddressBody::from_address_string(&s).expect("must parse");
        assert_eq!(body.0, [0x0b; 20]);
    }

    #[test]
    fn parses_all_network_prefixes() {
        let hex40 = "1".repeat(40);
        assert!(VmAddressBody::from_address_string(&format!("SD1c{}", hex40)).is_some());
        assert!(VmAddressBody::from_address_string(&format!("ST1c{}", hex40)).is_some());
        assert!(VmAddressBody::from_address_string(&format!("SR1c{}", hex40)).is_some());
    }

    #[test]
    fn rejects_unknown_prefix() {
        let s = format!("BTC1{}", "a".repeat(40));
        assert!(VmAddressBody::from_address_string(&s).is_none());
    }

    #[test]
    fn rejects_wrong_length() {
        // 39 hex chars instead of 40
        let s = format!("SD1c{}", "a".repeat(39));
        assert!(VmAddressBody::from_address_string(&s).is_none());
    }

    #[test]
    fn rejects_non_hex_body() {
        let s = format!("SD1c{}zz", "a".repeat(38));
        assert!(VmAddressBody::from_address_string(&s).is_none());
    }

    #[test]
    fn rejects_short_strings() {
        assert!(VmAddressBody::from_address_string("").is_none());
        assert!(VmAddressBody::from_address_string("SD1").is_none());
        assert!(VmAddressBody::from_address_string("SD1c").is_none());
    }

    #[test]
    fn derive_from_nonstandard_is_deterministic() {
        let a = VmAddressBody::derive_from_nonstandard("caller");
        let b = VmAddressBody::derive_from_nonstandard("caller");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_from_nonstandard_distinguishes_inputs() {
        let a = VmAddressBody::derive_from_nonstandard("caller");
        let b = VmAddressBody::derive_from_nonstandard("target");
        assert_ne!(a, b);
    }

    #[test]
    fn from_any_handles_both_paths() {
        // canonical path
        let canonical = format!("SD1c{}", "a".repeat(40));
        let body_canonical = VmAddressBody::from_any(&canonical);
        assert_eq!(body_canonical.0, [0xaa; 20]);

        // synthetic path — must be deterministic and equal the derived value
        let body_synthetic = VmAddressBody::from_any("caller");
        assert_eq!(
            body_synthetic,
            VmAddressBody::derive_from_nonstandard("caller")
        );
    }

    #[test]
    fn u256_roundtrip_preserves_body() {
        let body = VmAddressBody([0x42u8; 20]);
        let u = body.to_u256();
        let recovered = VmAddressBody::from_u256(u);
        assert_eq!(body, recovered);
    }

    #[test]
    fn u256_layout_is_right_aligned_20_bytes() {
        // Body = 20 bytes of 0xFF. The U256 word should be 12 zero bytes
        // followed by 20 0xFF bytes — i.e. the low 20 bytes are the body.
        let body = VmAddressBody([0xFFu8; 20]);
        let u = body.to_u256();
        let bytes = u.to_be_bytes();
        assert_eq!(&bytes[0..12], &[0u8; 12], "high 12 bytes must be zero");
        assert_eq!(
            &bytes[12..32],
            &[0xFFu8; 20],
            "low 20 bytes must be the body"
        );
    }

    #[test]
    fn to_fallback_string_reproduces_canonical_for_contract_type() {
        // Parse "SD1cAAAA..." → body = [0xaa; 20]
        // Fallback reconstruction with network="mainnet" must produce
        // the SAME canonical string, since the contract type 'c' is
        // the fallback default.
        let canonical = format!("SD1c{}", "a".repeat(40));
        let body = VmAddressBody::from_address_string(&canonical).unwrap();
        let rebuilt = body.to_fallback_string("mainnet");
        assert_eq!(rebuilt, canonical);
    }

    #[test]
    fn to_fallback_string_uses_network_prefix() {
        let body = VmAddressBody([0x12u8; 20]);
        assert!(body.to_fallback_string("mainnet").starts_with("SD1c"));
        assert!(body.to_fallback_string("testnet").starts_with("ST1c"));
        assert!(body.to_fallback_string("regtest").starts_with("SR1c"));
    }
}
