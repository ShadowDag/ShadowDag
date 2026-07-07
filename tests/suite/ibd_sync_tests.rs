// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Initial Block Download (IBD) from a STATIC peer. Regression coverage for the
// bug where a fresh node could not sync from a peer holding a static chain
// (no miner producing new blocks). Drives the real serving path
// (build_headers_response / serve_block_bytes) plus peer-height learning.
//
// A two-DaemonNode TCP test is impossible in-process: the P2P layer keeps its
// queues, the advertised-height cell and the learned peer-height in process
// globals, so two daemons in one test process clobber each other. This drives
// the exact production serving path against a static store instead.

#[cfg(test)]
mod ibd_tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::domain::block::block::Block;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;
    use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;
    use crate::service::network::p2p::p2p::{note_peer_height, peer_best_height};
    use crate::service::network::sync::{build_headers_response, serve_block_bytes};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_store() -> BlockStore {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("shadowdag_ibd_{}_{}", pid, n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        BlockStore::new(dir.to_string_lossy().to_string()).expect("open block store")
    }

    fn hash_at(height: u64) -> String {
        format!("{:064x}", 0x5DA6_0000_0000u64 + height)
    }

    fn synth_block(height: u64, parent: Option<String>) -> Block {
        let parents = parent.map(|p| vec![p]).unwrap_or_default();
        let mut b = Block {
            header: BlockHeader::new_with_defaults(
                1,
                String::new(),
                parents,
                format!("{:064x}", height),
                1_735_689_600 + height,
                0,
                1,
                height,
            ),
            body: BlockBody {
                transactions: Vec::new(),
            },
        };
        b.header.hash = hash_at(height);
        b
    }

    fn static_chain(n: u64) -> (BlockStore, String) {
        let store = temp_store();
        let genesis = synth_block(0, None);
        assert!(store.save_block(&genesis));
        let mut prev = genesis.header.hash.clone();
        for h in 1..=n {
            let b = synth_block(h, Some(prev.clone()));
            assert!(store.save_block(&b));
            prev = b.header.hash;
        }
        (store, genesis.header.hash)
    }

    #[test]
    fn headers_response_walks_full_chain_from_genesis() {
        let n = 30u64;
        let (server, genesis) = static_chain(n);

        let headers = build_headers_response(&server, n, &genesis, 2000);
        assert_eq!(headers.len() as u64, n, "must return the whole chain, not tips");
        for (i, h) in headers.iter().enumerate() {
            assert_eq!(*h, hash_at(i as u64 + 1), "headers must be in height order");
        }

        let from_empty = build_headers_response(&server, n, "", 2000);
        assert_eq!(from_empty, headers);
    }

    #[test]
    fn headers_response_respects_count_and_advances() {
        let n = 30u64;
        let (server, genesis) = static_chain(n);

        let first = build_headers_response(&server, n, &genesis, 8);
        assert_eq!(first.len(), 8);
        assert_eq!(first[0], hash_at(1));
        assert_eq!(first[7], hash_at(8));

        let second = build_headers_response(&server, n, &first[7], 8);
        assert_eq!(second[0], hash_at(9));
    }

    #[test]
    fn headers_response_empty_when_caught_up() {
        let n = 10u64;
        let (server, _genesis) = static_chain(n);
        let tip = hash_at(n);
        let headers = build_headers_response(&server, n, &tip, 2000);
        assert!(headers.is_empty(), "no headers to serve once the peer is level");
    }

    #[test]
    fn serve_block_bytes_round_trips() {
        let n = 5u64;
        let (server, _genesis) = static_chain(n);

        let bytes = serve_block_bytes(&server, &hash_at(3)).expect("block must be served");
        let block: Block = bincode::deserialize(&bytes).expect("valid block bytes");
        assert_eq!(block.header.height, 3);
        assert_eq!(block.header.hash, hash_at(3));

        assert!(serve_block_bytes(&server, &hash_at(999)).is_none());
    }

    #[test]
    fn fresh_node_syncs_static_chain_to_tip_without_new_blocks() {
        const N: u64 = 25;
        const HEADERS_PER_REQ: usize = 8;

        let (server, genesis) = static_chain(N);

        let client = temp_store();
        assert!(client.save_block(&synth_block(0, None)));

        note_peer_height(N);
        assert!(peer_best_height() >= N, "peer height must be learned at handshake");

        let mut b_tip = genesis;
        let mut b_height = 0u64;
        let mut rounds = 0u64;

        while b_height < N {
            rounds += 1;
            assert!(rounds <= N + 5, "sync failed to converge (looping like the bug)");

            let headers = build_headers_response(&server, N, &b_tip, HEADERS_PER_REQ);
            assert!(
                !headers.is_empty(),
                "static peer must still serve headers while we are behind \
                 (empty here is the original bug)"
            );

            let mut progressed = false;
            for h in headers {
                if client.get_block(&h).is_some() {
                    continue;
                }
                let bytes =
                    serve_block_bytes(&server, &h).expect("static peer must serve the body");
                let block: Block = bincode::deserialize(&bytes).expect("valid block");
                assert!(client.save_block(&block));
                if block.header.height > b_height {
                    b_height = block.header.height;
                    b_tip = block.header.hash.clone();
                }
                progressed = true;
            }
            assert!(progressed, "a round produced no new blocks");
        }

        assert_eq!(b_height, N, "fresh node must reach the static peer's height");
        for h in 0..=N {
            assert_eq!(
                client.get_block_hashes_at_height(h).len(),
                1,
                "B is missing the block at height {}",
                h
            );
        }
        assert!(rounds > 1, "expected a multi-round forward walk");
    }

    #[test]
    fn peer_best_height_is_monotonic_max() {
        note_peer_height(1_000_000);
        let after_high = peer_best_height();
        assert!(after_high >= 1_000_000);
        note_peer_height(5);
        assert_eq!(peer_best_height(), after_high);
    }
}
