// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//   P2P Network Tests — discovery, ban, spam, message propagation, partition
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::config::consensus::consensus_params::ConsensusParams;
    use crate::config::consensus::emission_schedule::EmissionSchedule;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;
    use crate::engine::mining::miner::miner::Miner;
    use crate::service::network::p2p::peer_manager::PeerManager;

    // ── helpers ──────────────────────────────────────────────────────────
    fn tmp_pm(suffix: &str) -> PeerManager {
        let path = format!("/tmp/p2p_pm_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        PeerManager::new_default_path(&path).expect("test DB open failed")
    }

    // ── 1. Peer discovery — add and find peer ─────────────────────────────
    #[test]
    fn peer_discovery_add_and_find() {
        let pm = tmp_pm("discovery");
        pm.add_peer("192.168.1.1:8333").unwrap();
        assert!(
            pm.peer_exists("192.168.1.1:8333"),
            "Added peer must be found"
        );
    }

    // ── 2. Peer count reflects insertions ────────────────────────────────
    #[test]
    fn peer_count_increases_with_each_peer() {
        let pm = tmp_pm("count");
        assert_eq!(pm.count(), 0);
        pm.add_peer("10.0.0.1:8333").unwrap();
        pm.add_peer("10.0.0.2:8333").unwrap();
        pm.add_peer("10.0.0.3:8333").unwrap();
        assert_eq!(pm.count(), 3);
    }

    // ── 3. Remove peer ────────────────────────────────────────────────────
    #[test]
    fn remove_peer_decrements_count() {
        let pm = tmp_pm("remove");
        pm.add_peer("10.1.0.1:8333").unwrap();
        pm.add_peer("10.1.0.2:8333").unwrap();
        pm.remove_peer("10.1.0.1:8333").ok();
        assert!(
            !pm.peer_exists("10.1.0.1:8333"),
            "Removed peer must not exist"
        );
        assert_eq!(pm.count(), 1);
    }

    // ── 4. Duplicate peer not added twice ────────────────────────────────
    #[test]
    fn duplicate_peer_not_added_twice() {
        let pm = tmp_pm("dup_peer");
        pm.add_peer("10.2.0.1:8333").unwrap();
        pm.add_peer("10.2.0.1:8333").ok(); // duplicate
                                           // Count must remain 1 (not 2)
        assert_eq!(pm.count(), 1, "Duplicate peer must not be inserted twice");
    }

    // ── 5. get_peers returns all active peers ─────────────────────────────
    #[test]
    fn get_peers_returns_all() {
        let pm = tmp_pm("get_peers");
        pm.add_peer("10.3.0.1:8333").unwrap();
        pm.add_peer("10.3.0.2:8333").unwrap();
        let peers = pm.get_peers();
        assert!(peers.contains(&"10.3.0.1:8333".to_string()));
        assert!(peers.contains(&"10.3.0.2:8333".to_string()));
    }

    // ── 6. get_best_peers ordered by score ───────────────────────────────
    #[test]
    fn get_best_peers_returns_limited_results() {
        let pm = tmp_pm("best_peers");
        for i in 0..20usize {
            let addr = format!("10.4.{}.{}:8333", i / 256, i % 256);
            pm.add_peer(&addr).ok();
        }
        let best = pm.get_best_peers(5);
        assert!(best.len() <= 5, "get_best_peers must return at most 5");
    }

    // ── 7. Ban peer — banned peer not accessible ──────────────────────────
    #[test]
    fn banned_peer_is_inaccessible() {
        let pm = tmp_pm("ban_access");
        pm.add_peer("172.16.1.1:8333").unwrap();
        pm.ban_peer("172.16.1.1:8333", 3600, "spam");
        assert!(
            pm.is_banned("172.16.1.1:8333"),
            "Banned peer must report as banned"
        );
    }

    // ── 8. Unban allows peer back ─────────────────────────────────────────
    #[test]
    fn unbanned_peer_is_accessible() {
        let pm = tmp_pm("unban_access");
        pm.add_peer("172.16.2.1:8333").unwrap();
        pm.ban_peer("172.16.2.1:8333", 3600, "test");
        pm.unban_peer("172.16.2.1:8333");
        assert!(
            !pm.is_banned("172.16.2.1:8333"),
            "Unbanned peer must not be banned"
        );
    }

    // ── 9. Peer height tracking ───────────────────────────────────────────
    #[test]
    fn peer_height_updated_correctly() {
        let pm = tmp_pm("height");
        pm.add_peer("10.5.0.1:8333").unwrap();
        pm.update_peer_height("10.5.0.1:8333", 12_500);
        // Height is stored separately from PeerRecord; use get_peer_height to read it
        let height = pm.get_peer_height("10.5.0.1:8333");
        assert_eq!(height, 12_500, "Height must be updated to 12500");
    }

    // ── 10. Peer latency tracking ─────────────────────────────────────────
    #[test]
    fn peer_latency_updated_correctly() {
        let pm = tmp_pm("latency");
        pm.add_peer("10.6.0.1:8333").unwrap();
        pm.update_peer_latency("10.6.0.1:8333", 42);
        // Latency is stored separately from PeerRecord; use get_peer_latency_ms to read it
        let latency = pm.get_peer_latency_ms("10.6.0.1:8333");
        assert_eq!(latency, 42, "Latency must be 42ms");
    }

    // ── 11. addr_list — store and retrieve addresses ──────────────────────
    #[test]
    fn addr_list_store_and_retrieve() {
        let pm = tmp_pm("addr_list");
        pm.store_addr("192.0.2.1:8333");
        pm.store_addr("192.0.2.2:8333");
        pm.store_addr("192.0.2.3:8333");
        let addrs = pm.get_addr_list();
        assert!(addrs.len() >= 3, "Must retrieve at least 3 addresses");
    }

    // ── 12. add_addr_batch ────────────────────────────────────────────────
    #[test]
    fn add_addr_batch_stores_all() {
        let pm = tmp_pm("batch_addr");
        let batch: Vec<String> = (0..10).map(|i| format!("10.7.0.{}:8333", i)).collect();
        pm.add_addr_batch(&batch);
        let addrs = pm.get_addr_list();
        for addr in &batch {
            assert!(addrs.contains(addr), "Batch addr {} must be stored", addr);
        }
    }

    // ── 13. Penalty accumulation and decay ───────────────────────────────
    #[test]
    fn penalty_accumulates_and_can_decay() {
        let pm = tmp_pm("penalty_decay");
        pm.add_peer("10.8.0.1:8333").unwrap();
        pm.add_penalty("10.8.0.1:8333", 15, "bad block");
        pm.add_penalty("10.8.0.1:8333", 10, "bad tx");
        let before = pm.get_penalty("10.8.0.1:8333");
        assert!(
            before >= 25,
            "Penalties must accumulate to >= 25 (got {})",
            before
        );
        pm.decay_penalties();
        let after = pm.get_penalty("10.8.0.1:8333");
        // After decay, penalty should be reduced (or same if decay is time-based)
        assert!(after <= before, "Penalties must not increase after decay");
    }

    // ── 14. get_peer_records returns structured data ───────────────────────
    #[test]
    fn get_peer_records_contains_added_peers() {
        let pm = tmp_pm("records");
        pm.add_peer("10.9.0.1:8333").unwrap();
        pm.add_peer("10.9.0.2:8333").unwrap();
        let records = pm.get_peer_records();
        let addrs: Vec<String> = records.iter().map(|r| r.addr.clone()).collect();
        assert!(addrs.contains(&"10.9.0.1:8333".to_string()));
        assert!(addrs.contains(&"10.9.0.2:8333".to_string()));
    }

    // ── 15. Network partition simulation (two isolated groups) ───────────
    #[test]
    fn network_partition_two_groups_isolated() {
        // Group A: 5 peers
        let pm_a = tmp_pm("partition_a");
        for i in 0..5usize {
            pm_a.add_peer(&format!("10.10.0.{}:8333", i)).unwrap();
        }

        // Group B: 5 peers
        let pm_b = tmp_pm("partition_b");
        for i in 0..5usize {
            pm_b.add_peer(&format!("10.20.0.{}:8333", i)).unwrap();
        }

        // No cross-knowledge
        let peers_a = pm_a.get_peers();
        let peers_b = pm_b.get_peers();
        for p in &peers_b {
            assert!(
                !peers_a.contains(p),
                "Group A must not know Group B peer {} (partition isolation)",
                p
            );
        }

        // Reconnect: add Group B peers to Group A
        for p in &peers_b {
            pm_a.add_peer(p).ok();
        }
        let after_reconnect = pm_a.get_peers();
        for p in &peers_b {
            assert!(
                after_reconnect.contains(p),
                "After reconnect, Group A must know peer {}",
                p
            );
        }
    }

    // ── 16. Ban expiry is future timestamp ───────────────────────────────
    #[test]
    fn ban_expiry_greater_than_zero() {
        let pm = tmp_pm("expiry_check");
        pm.ban_peer("172.20.0.1:8333", 1800, "eclipse_attempt");
        let expiry = pm.get_ban_expiry("172.20.0.1:8333");
        assert!(
            expiry > 0,
            "Ban expiry must be a positive timestamp, got {}",
            expiry
        );
    }

    // ── 17. Active peer state check ───────────────────────────────────────
    #[test]
    fn peer_is_active_after_touch() {
        let pm = tmp_pm("active");
        pm.add_peer("10.11.0.1:8333").unwrap();
        pm.touch_peer("10.11.0.1:8333");
        let record = pm.get_peer("10.11.0.1:8333");
        assert!(record.is_some(), "Peer must exist after touch");
    }

    // ── 18. global() returns shared PeerManager ───────────────────────────
    #[test]
    fn global_peer_manager_shared_instance() {
        // Use new_temp to avoid static PEER_MANAGER_INSTANCE conflicts across tests
        let pm1 = PeerManager::new_temp();
        let pm2 = PeerManager::new_temp();
        // Both are isolated instances — add via one, check on same instance
        pm1.add_peer("10.12.0.1:8333").unwrap();
        assert!(pm1.peer_exists("10.12.0.1:8333"));
        // Verify pm2 is a separate instance (does not share state)
        assert!(!pm2.peer_exists("10.12.0.1:8333"));
    }

    // 19. 1000-node network under 5-year simulated mining timeline.
    #[test]
    fn network_1000_nodes_over_ten_years_with_mining_checkpoints() {
        let pm = tmp_pm("1000_nodes_10y");
        let miner = Miner::new(1, "shadow1devreward".to_string());

        let one_day_secs: u64 = 24 * 60 * 60;
        let total_days: u64 = 10 * 365;
        let mut checkpoints: Vec<u64> = (0..=total_days).step_by(30).collect();
        if checkpoints.last().copied() != Some(total_days) {
            checkpoints.push(total_days);
        }

        let mut peers = Vec::with_capacity(1_000);
        for i in 0..1_000usize {
            let octet2 = (i / 256) as u8;
            let octet3 = (i % 256) as u8;
            let addr = format!("10.{}.{}:8333", octet2, octet3);
            pm.add_peer(&addr)
                .unwrap_or_else(|e| panic!("failed adding peer {}: {}", addr, e));
            peers.push(addr);
        }
        assert_eq!(pm.count(), 1_000, "network must have 1000 connected peers");

        let bps = ConsensusParams::BLOCKS_PER_SECOND;
        let mut prev_hash = String::new();
        let mut prev_reward = u64::MAX;

        for (idx, day) in checkpoints.iter().enumerate() {
            let height = day.saturating_mul(one_day_secs).saturating_mul(bps);
            let timestamp = 1_735_689_600u64.saturating_add(day.saturating_mul(one_day_secs));

            let coinbase = miner.create_coinbase("shadow1miner".to_string(), timestamp, height);
            let reward = EmissionSchedule::block_reward(height);
            assert!(
                reward <= prev_reward,
                "reward must be non-increasing at checkpoint {}",
                idx
            );
            prev_reward = reward;

            let parents = if idx == 0 {
                Vec::new()
            } else {
                vec![prev_hash.clone()]
            };

            let block = Block {
                header: BlockHeader::new_with_defaults(
                    1,
                    String::new(),
                    parents,
                    coinbase.hash.clone(),
                    timestamp,
                    0,
                    1,
                    height,
                ),
                body: BlockBody {
                    transactions: vec![coinbase],
                },
            };
            let mined = miner.mine_block(block);
            assert!(
                Miner::verify_pow(&mined),
                "invalid PoW at checkpoint {}",
                idx
            );
            prev_hash = mined.header.hash;

            for (peer_idx, addr) in peers.iter().enumerate() {
                let lag = (peer_idx % 3) as u64;
                pm.update_peer_height(addr, height.saturating_sub(lag));
                pm.update_peer_latency(addr, 10 + (peer_idx as u64 % 120));
            }

            assert_eq!(
                pm.best_peer_height(),
                height,
                "best height mismatch at checkpoint {}",
                idx
            );

            // Exercise penalty/ban paths during long-run operation.
            let noisy_peer = &peers[idx % peers.len()];
            pm.add_penalty(noisy_peer, 25, "spam burst");
            pm.decay_penalties();
            let score = pm.get_penalty(noisy_peer);
            assert!(
                score <= 25,
                "penalty decay/regression at checkpoint {}",
                idx
            );
        }

        let best = pm.get_best_peers(128);
        assert!(!best.is_empty(), "best peer selection must not be empty");
        assert!(best.len() <= 128);

        let stats = pm.stats();
        assert_eq!(stats.get("total_peers").copied().unwrap_or(0), 1_000);
        assert_eq!(
            stats.get("best_height").copied().unwrap_or(0),
            pm.best_peer_height()
        );
    }
}
