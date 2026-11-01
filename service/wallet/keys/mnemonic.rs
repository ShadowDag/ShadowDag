// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! BIP39 mnemonic generation and seed derivation (thin wrapper over `bip39`).

use crate::errors::WalletError;
use bip39::Mnemonic;

/// Supported mnemonic lengths.
#[derive(Clone, Copy)]
pub enum WordCount {
    Twelve,
    TwentyFour,
}

impl WordCount {
    fn count(self) -> usize {
        match self {
            WordCount::Twelve => 12,
            WordCount::TwentyFour => 24,
        }
    }
}

/// Generate a new English BIP39 mnemonic phrase.
pub fn generate_mnemonic(words: WordCount) -> Result<String, WalletError> {
    let m = Mnemonic::generate(words.count())
        .map_err(|e| WalletError::KeyDerivation(format!("mnemonic generate: {e}")))?;
    Ok(m.to_string())
}

/// Parse + validate a mnemonic and derive the 64-byte BIP39 seed.
pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<[u8; 64], WalletError> {
    let m = Mnemonic::parse_normalized(phrase)
        .map_err(|e| WalletError::KeyDerivation(format!("invalid mnemonic: {e}")))?;
    Ok(m.to_seed(passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_mnemonic_produces_known_seed() {
        // BIP39 English test vector (all-zero entropy), passphrase "TREZOR".
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(phrase, "TREZOR").unwrap();
        assert_eq!(
            hex::encode(seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn generate_then_roundtrip_seed_is_stable() {
        let phrase = generate_mnemonic(WordCount::Twelve).unwrap();
        let s1 = mnemonic_to_seed(&phrase, "").unwrap();
        let s2 = mnemonic_to_seed(&phrase, "").unwrap();
        assert_eq!(s1, s2);
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn invalid_mnemonic_is_rejected() {
        assert!(mnemonic_to_seed("not a valid mnemonic phrase at all", "").is_err());
    }
}
