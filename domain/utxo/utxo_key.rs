// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Canonical binary UTXO key.
//
// CONSENSUS CRITICAL — every node MUST produce identical bytes for the
// same (tx_hash, output_index) pair.  A single bit of difference causes
// a chain fork.
//
// Layout (36 bytes, fixed, no allocation):
//   bytes[0..32]  = SHA-256 tx hash decoded from hex (big-endian)
//   bytes[32..36] = output index as big-endian u32
//
// Big-endian index ensures lexicographic byte ordering matches numeric
// ordering — important for RocksDB range scans.
//
// WHY NOT String?
//   - format!("{}:{}", hash, index) depends on locale, normalization
//   - "0x" prefix, case, whitespace cause silent mismatches → fork
//   - Variable-length: "0" vs "00" vs "000" for index
//   - 100+ bytes per key vs 36 bytes (3x memory savings)
// ═══════════════════════════════════════════════════════════════════════════

use std::fmt;

/// Fixed 36-byte canonical UTXO key.
///
/// The ONLY way to construct a key for UTXO operations.
/// All UTXO lookups, inserts, and deletes go through this type.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(C)]
pub struct UtxoKey {
    bytes: [u8; 36],
}

/// Size of a serialized UTXO key in bytes.
pub const UTXO_KEY_LEN: usize = 36;

impl UtxoKey {
    /// Strict construction — validates input and panics on bad data.
    ///
    /// TEST ONLY — production code MUST use `try_new()`.
    ///
    /// A panic here means upstream validation (DagShield) failed to reject
    /// bad data — this is a defense-in-depth crash, not normal operation.
    #[cfg(test)]
    #[inline]
    pub fn new(tx_hash: &str, index: u32) -> Self {
        match Self::try_new(tx_hash, index) {
            Some(key) => key,
            None => panic!(
                "UtxoKey::new: invalid tx hash (must be exactly 64 hex chars, got {} chars after normalization). \
                 Input: '{}'. This indicates a bug in upstream validation.",
                {
                    let h = tx_hash.trim();
                    let h = if h.starts_with("0x") || h.starts_with("0X") { &h[2..] } else { h };
                    h.len()
                },
                if tx_hash.len() > 24 { &tx_hash[..24] } else { tx_hash },
            ),
        }
    }

    /// Fallible construction — returns `None` on invalid input.
    ///
    /// CONSENSUS CRITICAL:
    ///   - Rejects non-hex characters (instead of silently mapping to 0)
    ///   - Rejects wrong-length hashes (instead of zero-padding or truncating)
    ///   - Normalizes: trim whitespace, strip "0x"/"0X", case-insensitive
    ///   - Index encoded as big-endian u32
    #[inline]
    pub fn try_new(tx_hash: &str, index: u32) -> Option<Self> {
        let hash = tx_hash.trim();
        let hash = if hash.starts_with("0x") || hash.starts_with("0X") {
            &hash[2..]
        } else {
            hash
        };

        // STRICT: exactly 64 hex chars = 32 bytes
        if hash.len() != 64 {
            return None;
        }

        // Decode hex → bytes.  decode_hex_into validates every nibble
        // and returns false on ANY non-hex character, so the earlier
        // length check + this decode is the complete validation.
        // No separate "all chars valid?" pass needed — one traversal does both.
        let mut bytes = [0u8; 36];
        if !Self::decode_hex_into(&mut bytes[..32], hash) {
            return None;
        }
        bytes[32..36].copy_from_slice(&index.to_be_bytes());

        Some(Self { bytes })
    }

    /// Construct from raw 36 bytes (e.g. loaded from RocksDB).
    #[inline]
    pub fn from_bytes(bytes: [u8; 36]) -> Self {
        Self { bytes }
    }

    /// Construct from a byte slice (must be exactly 36 bytes).
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 36 {
            return None;
        }
        let mut bytes = [0u8; 36];
        bytes.copy_from_slice(slice);
        Some(Self { bytes })
    }

    /// The raw 36-byte canonical representation.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 36] {
        &self.bytes
    }

    /// Extract the output index (big-endian u32 at bytes[32..36]).
    #[inline]
    pub fn index(&self) -> u32 {
        u32::from_be_bytes([self.bytes[32], self.bytes[33], self.bytes[34], self.bytes[35]])
    }

    /// Extract the 32-byte hash portion.
    #[inline]
    pub fn hash_bytes(&self) -> &[u8; 32] {
        // self.bytes is [u8; 36], so [..32] is always exactly 32 bytes.
        // Use arrayref-style split: first() on a split_at is infallible.
        // SAFETY: This is a pure compile-time guarantee — no unsafe needed.
        let (hash, _rest) = self.bytes.split_at(32);
        // hash is &[u8] of len 32; try_into cannot fail but we avoid expect().
        // The compiler can see the length is fixed from split_at on [u8; 36].
        match <&[u8; 32]>::try_from(hash) {
            Ok(arr) => arr,
            Err(_) => unreachable!(),  // [u8; 36].split_at(32).0 is always 32 bytes
        }
    }

    /// Hex-encode the hash portion (for logging/display only, NOT for storage).
    pub fn hash_hex(&self) -> String {
        hex::encode(&self.bytes[..32])
    }

    /// Decode a hex string into a byte buffer, validating every nibble.
    ///
    /// Returns `false` if ANY character is not valid hex or if the length
    /// doesn't match `dst.len() * 2`.  On failure, `dst` may be partially
    /// written — caller must discard the buffer.
    ///
    /// This is the single point of hex→bytes conversion for UtxoKey.
    /// The type signature makes it impossible to silently swallow bad input,
    /// regardless of whether the caller pre-validated or not.
    #[inline]
    fn decode_hex_into(dst: &mut [u8], hex_str: &str) -> bool {
        let hex_bytes = hex_str.as_bytes();
        if hex_bytes.len() != dst.len() * 2 {
            return false;
        }
        for i in 0..dst.len() {
            let hi = match Self::hex_nibble(hex_bytes[i * 2]) {
                Some(v) => v,
                None => return false,
            };
            let lo = match Self::hex_nibble(hex_bytes[i * 2 + 1]) {
                Some(v) => v,
                None => return false,
            };
            dst[i] = (hi << 4) | lo;
        }
        true
    }

    /// Convert a single hex ASCII byte to its 4-bit value.
    ///
    /// Returns `None` for non-hex bytes — the type system enforces that
    /// every caller handles the error case.  No silent fallback to 0.
    #[inline]
    const fn hex_nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
}

impl fmt::Debug for UtxoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UtxoKey({}:{})", &self.hash_hex()[..16], self.index())
    }
}

impl fmt::Display for UtxoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.hash_hex(), self.index())
    }
}

impl AsRef<[u8]> for UtxoKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl serde::Serialize for UtxoKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de> serde::Deserialize<'de> for UtxoKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UtxoKey;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "36 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<UtxoKey, E> {
                UtxoKey::from_slice(v).ok_or_else(|| E::invalid_length(v.len(), &"36"))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<UtxoKey, A::Error> {
                let mut bytes = [0u8; 36];
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = seq.next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"36"))?;
                }
                Ok(UtxoKey::from_bytes(bytes))
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_deterministic() {
        let a = UtxoKey::new("aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233", 7);
        let b = UtxoKey::new("aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233", 7);
        assert_eq!(a, b);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn index_roundtrip() {
        let k = UtxoKey::new("aa".repeat(32).as_str(), 42);
        assert_eq!(k.index(), 42);
    }

    #[test]
    fn big_endian_ordering() {
        let k0 = UtxoKey::new(&"aa".repeat(32), 0);
        let k1 = UtxoKey::new(&"aa".repeat(32), 1);
        let k256 = UtxoKey::new(&"aa".repeat(32), 256);
        assert!(k0 < k1);
        assert!(k1 < k256);
    }

    #[test]
    fn hex_normalization() {
        let lower = UtxoKey::new(&"aabb".repeat(16), 0);
        let upper = UtxoKey::new(&"AABB".repeat(16), 0);
        assert_eq!(lower, upper);
    }

    #[test]
    fn prefix_0x_stripped() {
        let hash = "aa".repeat(32);
        let with = UtxoKey::new(&format!("0x{}", hash), 0);
        let without = UtxoKey::new(&hash, 0);
        assert_eq!(with, without);
    }

    #[test]
    fn display_format() {
        let k = UtxoKey::new(&"ab".repeat(32), 3);
        let s = k.to_string();
        assert!(s.ends_with(":3"));
        assert!(s.starts_with("abab"));
    }

    #[test]
    fn try_new_rejects_short_hash() {
        assert!(UtxoKey::try_new("aabb", 0).is_none());
    }

    #[test]
    fn try_new_rejects_long_hash() {
        assert!(UtxoKey::try_new(&"aa".repeat(33), 0).is_none());
    }

    #[test]
    fn try_new_rejects_non_hex() {
        // 'g' is not a valid hex character — replace one char in a 64-char string
        let mut bad = "aa".repeat(32);
        bad.replace_range(0..1, "g");
        assert_eq!(bad.len(), 64);
        assert!(UtxoKey::try_new(&bad, 0).is_none());
    }

    #[test]
    fn try_new_accepts_valid() {
        assert!(UtxoKey::try_new(&"ff".repeat(32), 42).is_some());
    }

    #[test]
    #[should_panic(expected = "invalid tx hash")]
    fn new_panics_on_short_hash() {
        let _ = UtxoKey::new("aabb", 0);
    }

    #[test]
    #[should_panic(expected = "invalid tx hash")]
    fn new_panics_on_non_hex() {
        let _ = UtxoKey::new(&format!("zz{}", "00".repeat(31)), 0);
    }

    #[test]
    fn hash_set_dedup() {
        let mut set = std::collections::HashSet::new();
        let k1 = UtxoKey::new(&"ff".repeat(32), 0);
        let k2 = UtxoKey::new(&"ff".repeat(32), 0);
        set.insert(k1);
        assert!(!set.insert(k2)); // duplicate
    }

    #[test]
    fn from_bytes_roundtrip() {
        let k = UtxoKey::new(&"cd".repeat(32), 99);
        let bytes = *k.as_bytes();
        let k2 = UtxoKey::from_bytes(bytes);
        assert_eq!(k, k2);
    }

    #[test]
    fn serde_roundtrip() {
        let k = UtxoKey::new(&"ab".repeat(32), 42);
        let encoded = bincode::serialize(&k).unwrap();
        let decoded: UtxoKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(k, decoded);
    }

    #[test]
    fn exactly_36_bytes() {
        assert_eq!(std::mem::size_of::<UtxoKey>(), 36);
    }
}
