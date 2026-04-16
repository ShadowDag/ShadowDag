// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::network::bootstrap_nodes::BootstrapNodes;
use crate::config::node::node_config::NetworkMode;
use crate::slog_info;

use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::sync::mpsc;
use std::time::Duration;

pub const DNS_LOOKUP_TIMEOUT_SECS: u64 = 10;
pub const MAX_SEEDS_PER_QUERY: usize = 32;

pub struct BootstrapManager;

impl BootstrapManager {
    pub fn seeds_for(network: &NetworkMode) -> Vec<&'static str> {
        match network {
            NetworkMode::Mainnet => BootstrapNodes::mainnet(),
            NetworkMode::Testnet => BootstrapNodes::testnet(),
            NetworkMode::Regtest => BootstrapNodes::localhost(),
        }
    }

    /// Bootstrap the node by resolving seed addresses to active peers.
    ///
    /// Each seed is resolved via DNS with a per-seed timeout. IP:port seeds
    /// resolve instantly (no DNS lookup needed). Hostname:port seeds are
    /// resolved to their A/AAAA records. Results are deduplicated and capped
    /// at `MAX_SEEDS_PER_QUERY`.
    ///
    /// DNS failures are non-fatal — seeds that fail to resolve are skipped,
    /// and the hardcoded IP seeds provide a reliable fallback.
    pub fn bootstrap(network: &NetworkMode) -> Vec<String> {
        let seeds = Self::seeds_for(network);
        let mut resolved = HashSet::new();

        for seed in &seeds {
            match Self::resolve_with_timeout(seed, DNS_LOOKUP_TIMEOUT_SECS) {
                Ok(addrs) => {
                    for addr in addrs {
                        resolved.insert(addr);
                        if resolved.len() >= MAX_SEEDS_PER_QUERY {
                            break;
                        }
                    }
                }
                Err(e) => {
                    slog_info!(
                        "bootstrap",
                        "dns_resolve_failed",
                        seed => seed,
                        error => &e
                    );
                    // Fallback: if resolution failed but the seed looks like
                    // an IP:port, include it directly.
                    if seed.parse::<std::net::SocketAddr>().is_ok() {
                        resolved.insert(seed.to_string());
                    }
                }
            }
            if resolved.len() >= MAX_SEEDS_PER_QUERY {
                break;
            }
        }

        slog_info!(
            "bootstrap",
            "dns_resolved",
            seeds_input => seeds.len(),
            addrs_resolved => resolved.len()
        );

        resolved.into_iter().collect()
    }

    /// Resolve a seed address (IP:port or hostname:port) with a timeout.
    ///
    /// Spawns a background thread for the DNS lookup so we can enforce a
    /// deadline. For raw IP:port seeds this resolves instantly; for hostname
    /// seeds it performs an actual DNS query (A/AAAA records).
    fn resolve_with_timeout(seed: &str, timeout_secs: u64) -> Result<Vec<String>, String> {
        let seed_owned = seed.to_string();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            if let Ok(addrs) = seed_owned.to_socket_addrs() {
                for addr in addrs {
                    let _ = tx.send(format!("{}:{}", addr.ip(), addr.port()));
                }
            }
            // Thread exits → tx dropped → rx gets RecvError
        });

        let mut results = Vec::new();
        let deadline = Duration::from_secs(timeout_secs);

        // Wait for the first resolved address (or timeout)
        match rx.recv_timeout(deadline) {
            Ok(addr) => {
                results.push(addr);
                // Drain remaining results (nearly instant after the first)
                let drain_timeout = Duration::from_millis(100);
                while let Ok(addr) = rx.recv_timeout(drain_timeout) {
                    results.push(addr);
                }
                Ok(results)
            }
            Err(_) => Err(format!("timeout after {}s resolving {}", timeout_secs, seed)),
        }
    }

    pub fn seed_count(network: &NetworkMode) -> usize {
        Self::seeds_for(network).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_seeds_use_port_9333() {
        let seeds = BootstrapManager::seeds_for(&NetworkMode::Mainnet);
        for s in seeds {
            assert!(s.ends_with(":9333"));
        }
    }

    #[test]
    fn testnet_seeds_use_port_19333() {
        let seeds = BootstrapManager::seeds_for(&NetworkMode::Testnet);
        for s in seeds {
            assert!(s.ends_with(":19333"));
        }
    }

    #[test]
    fn regtest_uses_localhost() {
        let seeds = BootstrapManager::seeds_for(&NetworkMode::Regtest);
        for s in seeds {
            assert!(s.starts_with("127.0.0.1"));
        }
    }

    #[test]
    fn bootstrap_returns_non_empty() {
        let list = BootstrapManager::bootstrap(&NetworkMode::Mainnet);
        assert!(!list.is_empty());
    }
}
