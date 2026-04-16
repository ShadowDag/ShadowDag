// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::node::node_config::NetworkMode;

pub struct BootstrapNodes;

impl BootstrapNodes {
    pub fn mainnet() -> Vec<&'static str> {
        vec![
            // DNS hostnames (resolved at startup via BootstrapManager)
            "seed1.shadowdag.network:9333",
            "seed2.shadowdag.network:9333",
            "seed3.shadowdag.network:9333",
            "seed4.shadowdag.network:9333",
            // Static IP fallbacks (Utah, Dallas, LasVegas seed nodes)
            "144.172.105.147:9333",
            "172.86.90.70:9333",
            "45.61.151.206:9333",
        ]
    }

    pub fn testnet() -> Vec<&'static str> {
        vec![
            // DNS hostnames (resolved at startup; create A records pointing
            // to your testnet servers for dynamic peer discovery)
            "seed1-testnet.shadowdag.network:19333",
            "seed2-testnet.shadowdag.network:19333",
            "seed3-testnet.shadowdag.network:19333",
            // Static IP fallbacks (always reachable even without DNS)
            "144.172.105.147:19333",
            "172.86.90.70:19333",
            "45.61.151.206:19333",
        ]
    }

    pub fn localhost() -> Vec<&'static str> {
        vec!["127.0.0.1:29333", "127.0.0.1:29334"]
    }

    /// Single source of truth: return seeds for a given network mode.
    pub fn for_network(network: &NetworkMode) -> Vec<&'static str> {
        match network {
            NetworkMode::Mainnet => Self::mainnet(),
            NetworkMode::Testnet => Self::testnet(),
            NetworkMode::Regtest => Self::localhost(),
        }
    }

    /// Return seeds as owned Strings (convenience for APIs that need String).
    pub fn for_network_owned(network: &NetworkMode) -> Vec<String> {
        Self::for_network(network)
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Return full seed addresses (host:port) for bootstrap connections.
    /// Unlike `dns_hostnames()`, this preserves ports so that regtest
    /// entries like `127.0.0.1:29333` and `127.0.0.1:29334` remain distinct.
    pub fn dns_seeds(network: &NetworkMode) -> Vec<&'static str> {
        Self::for_network(network)
    }

    /// Return DNS hostnames only (no port), for DNS-only seed resolution.
    /// WARNING: This collapses entries that share a hostname (e.g. regtest
    /// localhost entries). Use `dns_seeds()` for connection bootstrapping.
    pub fn dns_hostnames(network: &NetworkMode) -> Vec<&'static str> {
        Self::for_network(network)
            .into_iter()
            .map(|s| s.split(':').next().unwrap_or(s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_uses_port_9333() {
        for seed in BootstrapNodes::mainnet() {
            assert!(
                seed.ends_with(":9333"),
                "mainnet seed '{}' must use port 9333",
                seed
            );
        }
    }

    #[test]
    fn testnet_uses_port_19333() {
        for seed in BootstrapNodes::testnet() {
            assert!(
                seed.ends_with(":19333"),
                "testnet seed '{}' must use port 19333",
                seed
            );
        }
    }

    #[test]
    fn localhost_uses_port_29333() {
        let seeds = BootstrapNodes::localhost();
        assert!(
            seeds.iter().any(|s| s.contains(":29333")),
            "localhost seeds must include port 29333"
        );
        assert!(
            seeds.iter().any(|s| s.contains(":29334")),
            "localhost seeds must include port 29334"
        );
        for seed in &seeds {
            assert!(
                seed.starts_with("127.0.0.1:"),
                "seed must be localhost, got: {}",
                seed
            );
        }
    }

    #[test]
    fn no_cross_contamination() {
        let mn = BootstrapNodes::mainnet();
        let tn = BootstrapNodes::testnet();
        for seed in &mn {
            assert!(
                !tn.contains(seed),
                "seed '{}' appears in both mainnet and testnet",
                seed
            );
        }
    }
}
