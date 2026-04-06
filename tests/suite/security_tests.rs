// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//    Security Tests — double-spend, replay, spam, DoS, ban, peer validation
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
    use crate::domain::transaction::tx_validator::{TxValidator, DUST_LIMIT, MIN_TX_FEE};
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
    use crate::engine::dag::core::dag_manager::DagManager;
    use crate::service::network::p2p::peer_manager::PeerManager;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::block::block_body::BlockBody;
    use crate::config::consensus::consensus_params::ConsensusParams;

    // ── helpers ──────────────────────────────────────────────────────────
    fn tmp_utxo(suffix: &str) -> UtxoSet {
        let path = format!("/tmp/sec_utxo_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        UtxoSet::new(Arc::new(UtxoStore::new(path.as_str()).expect("UtxoStore::new failed")))
    }

    fn tmp_dag(suffix: &str) -> DagManager {
        let path = format!("/tmp/sec_dag_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        DagManager::new_required(&path).unwrap()
    }

    fn tmp_pm(suffix: &str) -> PeerManager {
        let path = format!("/tmp/sec_pm_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        PeerManager::new_default_path(&path).expect("test DB open failed")
    }

    fn genesis_block() -> Block {
        Block {
            header: BlockHeader::new_with_defaults(
                1, "sec_genesis_000000000000".to_string(), vec![],
                "merkle_sec_genesis".to_string(),
                ConsensusParams::GENESIS_TIMESTAMP, 0,
                ConsensusParams::GENESIS_DIFFICULTY, 0,
            ),
            body: BlockBody { transactions: vec![Transaction {
                hash: "cb_sec_genesis".to_string(), inputs: vec![],
                outputs: vec![TxOutput { address: "shadow1sec".into(), amount: 10_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
                fee: 0, timestamp: ConsensusParams::GENESIS_TIMESTAMP, is_coinbase: true,
                tx_type: TxType::Transfer,
            payload_hash: None,
            }]},
        }
    }

    // ── 1. Double-spend: same utxo spent twice ────────────────────────────
    #[test]
    fn double_spend_rejected_by_utxo_set() {
        let utxo = tmp_utxo("double_spend");
        utxo.add_utxo_str("ds_tx:0", "owner".into(), 10_000, "shadow1ds".into());

        let r1 = utxo.spend_utxo_checked_str("ds_tx:0", 200);
        assert!(r1.is_ok(), "First spend must succeed");

        let r2 = utxo.spend_utxo_checked_str("ds_tx:0", 200);
        assert!(r2.is_err(), "Double-spend must be rejected");
    }

    // ── 2. Replay attack: same TX hash added twice to mempool ─────────────
    #[test]
    fn replay_attack_same_tx_rejected() {
        use crate::service::mempool::core::mempool::Mempool;
        let path = "/tmp/sec_mempool_replay".to_string();
        let _ = std::fs::remove_dir_all(&path);
        let pool = Mempool::try_new(path.as_str()).expect("mp");

        let tx = Transaction {
            hash: "replay_tx_hash_001".to_string(),
            inputs: vec![],
            outputs: vec![TxOutput { address: "addr".into(), amount: DUST_LIMIT, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: MIN_TX_FEE,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        };
        pool.add_transaction(&tx);
        let second = pool.add_transaction(&tx);
        assert!(!second, "Replay of same TX must be rejected");
    }

    // ── 3. Spam prevention: malformed signatures rejected ─────────────────
    #[test]
    fn malformed_signature_rejected_by_validator() {
        let tx = Transaction {
            hash: "spam_bad_sig".to_string(),
            inputs: vec![TxInput {
                txid:      "prev_tx_0000".to_string(),
                index:     0,
                owner:     "owner".into(),
                signature: "ZZZZZZ_NOT_HEX_ZZZZZZ".to_string(),
                pub_key:   "aabbccdd".repeat(8),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput { address: "addr".into(), amount: DUST_LIMIT, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: MIN_TX_FEE,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        };
        let valid = TxValidator::verify_signatures(&tx);
        assert!(!valid, "Malformed signature must fail verification");
    }

    // ── 4. Wrong signature length rejected ───────────────────────────────
    #[test]
    fn wrong_signature_length_rejected() {
        let tx = Transaction {
            hash: "wrong_sig_len".to_string(),
            inputs: vec![TxInput {
                txid:      "prev_tx_0001".to_string(),
                index:     0,
                owner:     "owner".into(),
                signature: "aabbccdd".to_string(),
                pub_key:   "aabb".repeat(16),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput { address: "addr".into(), amount: DUST_LIMIT, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: MIN_TX_FEE,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        };
        assert!(!TxValidator::verify_signatures(&tx), "Short signature must be rejected");
    }

    // ── 5. Empty signature rejected ───────────────────────────────────────
    #[test]
    fn empty_signature_rejected() {
        let tx = Transaction {
            hash: "empty_sig_tx".to_string(),
            inputs: vec![TxInput {
                txid:      "prev_tx_0002".to_string(),
                index:     0,
                owner:     "owner".into(),
                signature: String::new(),
                pub_key:   "aabb".repeat(16),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput { address: "addr".into(), amount: DUST_LIMIT, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: MIN_TX_FEE,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        };
        assert!(!TxValidator::verify_signatures(&tx), "Empty signature must be rejected");
    }

    // ── 6. Empty public key rejected ──────────────────────────────────────
    #[test]
    fn empty_public_key_rejected() {
        let tx = Transaction {
            hash: "empty_pk_tx".to_string(),
            inputs: vec![TxInput {
                txid:      "prev_tx_0003".to_string(),
                index:     0,
                owner:     "owner".into(),
                signature: "aabb".repeat(32),
                pub_key:   String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput { address: "addr".into(), amount: DUST_LIMIT, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: MIN_TX_FEE,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        };
        assert!(!TxValidator::verify_signatures(&tx), "Empty public key must be rejected");
    }

    // ── 7. Ban peer and verify ban ────────────────────────────────────────
    #[test]
    fn banned_peer_reported_as_banned() {
        let pm = tmp_pm("ban");
        pm.ban_peer("192.168.1.100:8333", 3600, "DoS attack");
        assert!(
            pm.is_banned("192.168.1.100:8333"),
            "Banned peer must be reported as banned"
        );
    }

    // ── 8. Ban expiry is positive ─────────────────────────────────────────
    #[test]
    fn ban_expiry_is_future_timestamp() {
        let pm = tmp_pm("ban_expiry");
        pm.ban_peer("10.0.0.1:9000", 7200, "Sybil");
        let expiry = pm.get_ban_expiry("10.0.0.1:9000");
        assert!(expiry > 0, "Ban expiry must be a positive future timestamp");
    }

    // ── 9. Unban restores peer access ─────────────────────────────────────
    #[test]
    fn unban_removes_ban() {
        let pm = tmp_pm("unban");
        pm.ban_peer("172.16.0.5:7777", 3600, "spam");
        assert!(pm.is_banned("172.16.0.5:7777"));
        pm.unban_peer("172.16.0.5:7777");
        assert!(!pm.is_banned("172.16.0.5:7777"), "Unbanned peer must not be banned");
    }

    // ── 10. Invalid peer address rejected ────────────────────────────────
    #[test]
    fn invalid_peer_address_rejected() {
        use crate::service::network::p2p::message::PeerAddress;
        // Address validation is performed via PeerAddress::is_valid()
        // before passing to add_peer in production networking code.
        let empty_pa = PeerAddress::new("", 0);
        assert!(!empty_pa.is_valid(), "Empty address must be rejected");

        let long_addr = "x".repeat(300);
        // Long address without port separator is also invalid
        let long_pa = PeerAddress::new(&long_addr, 0);
        assert!(!long_pa.is_valid(), "Oversized address without port must be rejected");
    }

    // ── 11. Penalty system accumulates points ────────────────────────────
    #[test]
    fn peer_penalty_accumulates() {
        let pm = tmp_pm("penalty");
        pm.add_peer("192.0.2.10:8333").ok();
        pm.add_penalty("192.0.2.10:8333", 10, "invalid block");
        pm.add_penalty("192.0.2.10:8333", 20, "invalid tx");
        let total = pm.get_penalty("192.0.2.10:8333");
        assert!(total >= 30, "Penalties must accumulate: got {}", total);
    }

    // ── 12. DoS: duplicate block in DAG rejected ──────────────────────────
    #[test]
    fn dos_duplicate_block_rejected() {
        let dag = tmp_dag("dos_dup");
        let g = genesis_block();
        dag.add_block_validated(&g, true).unwrap();
        for _ in 0..100 {
            let r = dag.add_block_validated(&g, true);
            assert!(r.is_err(), "Duplicate block must always be rejected");
        }
    }

    // ── 13. Non-canonical s-value in signature ────────────────────────────
    #[test]
    fn non_canonical_s_value_rejected() {
        const ED25519_L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ];
        assert!(!TxValidator::s_is_canonical(&ED25519_L), "s=L must be non-canonical");

        let mut s_above = ED25519_L;
        s_above[0] = s_above[0].wrapping_add(1);
        assert!(!TxValidator::s_is_canonical(&s_above), "s>L must be non-canonical");
    }

    // ── 14. Overflow protection in wallet balance ─────────────────────────
    #[test]
    fn overflow_safe_in_utxo_balance() {
        let utxo = tmp_utxo("overflow");
        let addr = "shadow1overflow".to_string();
        utxo.add_utxo_str("ov_tx_1:0", "owner".into(), u64::MAX / 2, addr.clone());
        utxo.add_utxo_str("ov_tx_2:0", "owner".into(), u64::MAX / 2, addr.clone());
        let balance = utxo.get_balance(&addr);
        assert!(balance > 0, "Balance must be positive despite near-overflow");
    }

    // ── 15. Immature coinbase cannot be double-spent ──────────────────────
    #[test]
    fn immature_coinbase_spend_rejected() {
        let utxo = tmp_utxo("immature_cb");
        utxo.add_utxo_coinbase_str(
            "immature_cb_tx:0", "owner".into(), 50_000,
            "shadow1immature".into(), 100,
        );
        let result = utxo.spend_utxo_checked_str("immature_cb_tx:0", 150);
        assert!(result.is_err(), "Immature coinbase must not be spendable");
    }

    // ── 16. Sybil: 1000 fake nodes — peer count bounded ──────────────────
    #[test]
    fn sybil_1000_fake_nodes_peer_count_tracked() {
        let pm = tmp_pm("sybil");
        let mut added = 0usize;
        for i in 0..1_000usize {
            let addr = format!("10.{}.{}.{}:8333", (i / 256) % 256, i % 256, i % 100);
            if pm.add_peer(&addr).is_ok() {
                added += 1;
            }
        }
        let count = pm.count();
        assert!(count > 0, "At least some peers must be accepted");
        assert!(count <= added, "Peer count must not exceed inserted peers");
    }
}
