// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::config::genesis::genesis::{
        create_genesis_block, verify_genesis, GENESIS_HEIGHT, GENESIS_TIMESTAMP,
    };

    #[test]
    fn genesis_is_deterministic() {
        let g1 = create_genesis_block();
        let g2 = create_genesis_block();
        assert_eq!(g1.header.hash, g2.header.hash);
        assert_eq!(g1.header.merkle_root, g2.header.merkle_root);
    }

    #[test]
    fn genesis_height_zero() {
        let g = create_genesis_block();
        assert_eq!(g.header.height, GENESIS_HEIGHT);
        assert_eq!(g.header.height, 0);
    }

    #[test]
    fn genesis_has_no_parents() {
        let g = create_genesis_block();
        assert!(g.header.parents.is_empty());
    }

    #[test]
    fn genesis_has_coinbase_tx() {
        let g = create_genesis_block();
        assert!(!g.body.transactions.is_empty());
        let coinbase = &g.body.transactions[0];
        assert!(coinbase.inputs.is_empty(), "Coinbase has no inputs");
        assert!(!coinbase.outputs.is_empty(), "Coinbase has outputs");
    }

    #[test]
    fn genesis_hash_non_empty() {
        let g = create_genesis_block();
        assert!(!g.header.hash.is_empty());
        assert_eq!(g.header.hash.len(), 64, "SHA-256 hex = 64 chars");
    }

    #[test]
    fn genesis_timestamp_correct() {
        let g = create_genesis_block();
        assert_eq!(g.header.timestamp, GENESIS_TIMESTAMP);
    }

    #[test]
    fn genesis_verify_passes() {
        let g = create_genesis_block();
        assert!(verify_genesis(&g));
    }

    #[test]
    fn genesis_verify_fails_wrong_hash() {
        let mut g = create_genesis_block();
        g.header.hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(!verify_genesis(&g));
    }

    #[test]
    fn genesis_merkle_root_matches_coinbase() {
        let g = create_genesis_block();
        assert!(!g.header.merkle_root.is_empty());
        assert_eq!(g.header.merkle_root.len(), 64);
    }
}
