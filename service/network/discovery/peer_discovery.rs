// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::sync::Arc;

use crate::service::network::p2p::peer_manager::PeerManager;

pub struct PeerDiscovery {
    peer_manager: Arc<PeerManager>,
}

impl PeerDiscovery {
    pub fn new(peer_manager: Arc<PeerManager>) -> Self {
        Self { peer_manager }
    }

    pub fn bootstrap(&self) {
        self.peer_manager.bootstrap();
    }

    pub fn bootstrap_testnet(&self) {
        use crate::config::network::bootstrap_nodes::BootstrapNodes;
        self.peer_manager
            .bootstrap_with_seeds(&BootstrapNodes::testnet());
    }

    pub fn bootstrap_with_seeds(&self, seeds: &[&str]) {
        self.peer_manager.bootstrap_with_seeds(seeds);
    }

    pub fn on_addr_message(&self, addrs: &[String]) -> Vec<String> {
        let mut new_addrs = Vec::new();
        let known = self.peer_manager.get_addr_list();
        for addr in addrs {
            let already_known = self.peer_manager.peer_exists(addr) || known.contains(addr);
            self.peer_manager.store_addr(addr);
            if !already_known {
                new_addrs.push(addr.clone());
            }
        }
        new_addrs
    }

    pub fn handle_getaddr(&self, max: usize) -> Vec<String> {
        self.peer_manager.get_addr_list_limited(max)
    }

    pub fn announce_self(&self, our_addr: &str) {
        self.peer_manager.store_addr(our_addr);
    }

    pub fn refresh_peers(&self, max_active: usize) {
        let current = self.peer_manager.count();
        if current >= max_active {
            return;
        }
        let needed = max_active - current;
        let candidates = self.peer_manager.get_addr_list_limited(needed * 2);

        let mut added = 0usize;
        for addr in candidates {
            if added >= needed {
                break;
            }
            if !self.peer_manager.peer_exists(&addr) && !self.peer_manager.is_banned(&addr) {
                let _ = self.peer_manager.add_peer(&addr);
                added += 1;
            }
        }
    }

    pub fn discover_peer(&self, address: &str) {
        let _ = self.peer_manager.add_peer(address);
        self.peer_manager.store_addr(address);
    }
}
