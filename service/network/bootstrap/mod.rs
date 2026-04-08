// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::network::bootstrap_nodes::BootstrapNodes;
use crate::config::node::node_config::NetworkMode;

pub const DNS_LOOKUP_TIMEOUT_SECS: u64 = 10;
pub const MAX_SEEDS_PER_QUERY:     usize = 32;

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
    /// TODO(#bootstrap): DNS resolution is not yet implemented. This method
    /// currently returns the raw seed list unchanged. When implemented, it
    /// should resolve each seed hostname via DNS (with `DNS_LOOKUP_TIMEOUT_SECS`
    /// timeout), deduplicate results, and cap at `MAX_SEEDS_PER_QUERY`.
    pub fn bootstrap(network: &NetworkMode) -> Vec<String> {
        let seeds = Self::seeds_for(network);

        // TODO(#bootstrap): Implement DNS resolution for each seed.
        // For each seed, perform a DNS lookup (A/AAAA records), collect
        // the resolved socket addresses, and return those instead of
        // the raw seed strings. Until then, return seeds as-is.
        for _seed in &seeds {
            // Placeholder: DNS resolution would happen here.
            // e.g. resolve(_seed, DNS_LOOKUP_TIMEOUT_SECS)
        }

        seeds.iter().map(|s| s.to_string()).collect()
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
        for s in seeds { assert!(s.ends_with(":9333")); }
    }

    #[test]
    fn testnet_seeds_use_port_19333() {
        let seeds = BootstrapManager::seeds_for(&NetworkMode::Testnet);
        for s in seeds { assert!(s.ends_with(":19333")); }
    }

    #[test]
    fn regtest_uses_localhost() {
        let seeds = BootstrapManager::seeds_for(&NetworkMode::Regtest);
        for s in seeds { assert!(s.starts_with("127.0.0.1")); }
    }

    #[test]
    fn bootstrap_returns_non_empty() {
        let list = BootstrapManager::bootstrap(&NetworkMode::Mainnet);
        assert!(!list.is_empty());
    }
}
