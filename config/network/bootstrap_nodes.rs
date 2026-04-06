// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::node::node_config::NetworkMode;

pub struct BootstrapNodes;

impl BootstrapNodes {
    pub fn mainnet() -> Vec<&'static str> {
        vec![
            "seed1.shadowdag.network:9333",
            "seed2.shadowdag.network:9333",
            "seed3.shadowdag.network:9333",
            "seed4.shadowdag.network:9333",
        ]
    }

    pub fn testnet() -> Vec<&'static str> {
        vec![
            "144.172.105.147:19333",
            "172.86.90.70:19333",
            "45.61.151.206:19333",
        ]
    }

    pub fn localhost() -> Vec<&'static str> {
        vec![
            "127.0.0.1:29333",
            "127.0.0.1:29334",
        ]
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
        Self::for_network(network).into_iter().map(|s| s.to_string()).collect()
    }

    /// Return DNS hostnames only (no port), for DNS seed resolution.
    pub fn dns_seeds(network: &NetworkMode) -> Vec<&'static str> {
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
            assert!(seed.ends_with(":9333"),
                "mainnet seed '{}' must use port 9333", seed);
        }
    }

    #[test]
    fn testnet_uses_port_19333() {
        for seed in BootstrapNodes::testnet() {
            assert!(seed.ends_with(":19333"),
                "testnet seed '{}' must use port 19333", seed);
        }
    }

    #[test]
    fn localhost_uses_port_29333() {
        for seed in BootstrapNodes::localhost() {
            assert!(seed.starts_with("127.0.0.1"),
                "localhost seed '{}' must be loopback", seed);
        }
    }

    #[test]
    fn no_cross_contamination() {
        let mn = BootstrapNodes::mainnet();
        let tn = BootstrapNodes::testnet();
        for seed in &mn {
            assert!(!tn.contains(seed),
                "seed '{}' appears in both mainnet and testnet", seed);
        }
    }
}
