// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Peer Diversity — Anti-Eclipse protection through subnet diversity.
//
// Eclipse Attack: attacker fills all peer slots with their nodes,
// isolating the victim from the honest network.
//
// Protection:
//   1. Outbound peers MUST come from distinct /16 subnets
//   2. Maximum 2 peers per /16 subnet
//   3. Anchor peers persist across restarts (resist churn-based eclipse)
//   4. Cryptographic peer identity prevents IP spoofing
//
// Subnet diversity ensures an attacker controlling one ISP cannot
// monopolize all connections.
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use rand::RngCore;

/// Maximum peers from the same /16 subnet
pub const MAX_PEERS_PER_SUBNET: usize = 2;

/// Minimum distinct /16 subnets for outbound connections
pub const MIN_OUTBOUND_SUBNETS: usize = 4;

/// Maximum anchor peers (persist across restarts)
pub const MAX_ANCHOR_PEERS: usize = 8;

/// Peer identity (cryptographic — prevents spoofing)
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// Ed25519 public key of the peer
    pub public_key: String,
    /// Signature over (public_key || timestamp || nonce) — proves key ownership
    pub signature:  String,
    /// When the identity was created
    pub timestamp:  u64,
    /// Random nonce to prevent replay
    pub nonce:      String,
}

impl PeerIdentity {
    /// Generate a new peer identity
    pub fn generate() -> Self {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let pk_hex = hex::encode(pk.to_bytes());

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

        let mut nonce_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce_hex = hex::encode(nonce_bytes);

        // Sign: H(pk || timestamp || nonce)
        let mut msg = Vec::new();
        msg.extend_from_slice(pk.to_bytes().as_ref());
        msg.extend_from_slice(&ts.to_le_bytes());
        msg.extend_from_slice(nonce_hex.as_bytes());

        use ed25519_dalek::Signer;
        let sig = sk.sign(&msg);
        let sig_hex = hex::encode(sig.to_bytes());

        Self {
            public_key: pk_hex,
            signature:  sig_hex,
            timestamp:  ts,
            nonce:      nonce_hex,
        }
    }

    /// Verify a peer identity
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};

        let pk_bytes = match hex::decode(&self.public_key) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };

        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        let vk = match VerifyingKey::from_bytes(&pk_arr) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let mut msg = Vec::new();
        msg.extend_from_slice(&pk_bytes);
        msg.extend_from_slice(&self.timestamp.to_le_bytes());
        msg.extend_from_slice(self.nonce.as_bytes());

        let sig = Signature::from_bytes(&sig_arr);
        if vk.verify(&msg, &sig).is_err() {
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Reject identities from the future or too old (5 minutes)
        if self.timestamp > now + 30 { return false; } // max 30s future
        if now.saturating_sub(self.timestamp) > 300 { return false; } // max 5 min old

        true
    }

    /// Unique peer ID derived from public key
    pub fn peer_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_PeerID_v1");
        h.update(self.public_key.as_bytes());
        hex::encode(&h.finalize()[..16])
    }
}

/// Extract subnet prefix from an IP address string.
///
/// - IPv4: /16 prefix (first two octets), e.g. "192.168.1.5:9333" → "v4:192.168"
/// - IPv6: /32 prefix (first two groups),  e.g. "[2001:db8::1]:9333" → "v6:2001:0db8"
///
/// Uses `std::net` for correct parsing of both address families and
/// bracket-wrapped IPv6 socket addresses.
pub fn subnet_16(ip: &str) -> String {
    use std::net::{IpAddr, SocketAddr};

    // Try parsing as SocketAddr first (handles "ip:port" and "[ipv6]:port"),
    // then fall back to bare IP address.
    let addr: Option<IpAddr> = ip.parse::<SocketAddr>().ok().map(|sa| sa.ip())
        .or_else(|| ip.parse::<IpAddr>().ok());

    match addr {
        Some(IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("v4:{}.{}", o[0], o[1])
        }
        Some(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("v6:{:04x}:{:04x}", s[0], s[1])
        }
        None => {
            // Unparseable — legacy fallback for non-standard strings.
            // Use the raw input so each unique string gets its own bucket.
            ip.to_string()
        }
    }
}

/// Peer diversity manager
pub struct PeerDiversity {
    /// Subnet → count of connected peers
    subnet_counts:  HashMap<String, usize>,
    /// Anchor peers (persist across restarts)
    anchor_peers:   Vec<String>,
    /// Connected peer identities
    identities:     HashMap<String, PeerIdentity>,
}

impl Default for PeerDiversity {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerDiversity {
    pub fn new() -> Self {
        Self {
            subnet_counts: HashMap::new(),
            anchor_peers:  Vec::new(),
            identities:    HashMap::new(),
        }
    }

    /// Check if connecting to this IP would violate subnet diversity
    pub fn can_connect(&self, ip: &str) -> bool {
        let subnet = subnet_16(ip);
        let count = self.subnet_counts.get(&subnet).copied().unwrap_or(0);
        count < MAX_PEERS_PER_SUBNET
    }

    /// Register a new connection atomically.
    /// Returns `false` (and does NOT increment) if the subnet limit would be exceeded.
    /// This eliminates the TOCTOU race between `can_connect()` and `on_connect()`.
    pub fn on_connect(&mut self, ip: &str, identity: Option<PeerIdentity>) -> bool {
        let subnet = subnet_16(ip);
        let count = self.subnet_counts.entry(subnet).or_insert(0);
        if *count >= MAX_PEERS_PER_SUBNET {
            return false;
        }
        *count += 1;

        if let Some(id) = identity {
            if id.verify() {
                self.identities.insert(ip.to_string(), id);
            }
        }
        true
    }

    /// Unregister a disconnection
    pub fn on_disconnect(&mut self, ip: &str) {
        let subnet = subnet_16(ip);
        if let Some(count) = self.subnet_counts.get_mut(&subnet) {
            *count = count.saturating_sub(1);
            if *count == 0 { self.subnet_counts.remove(&subnet); }
        }
        self.identities.remove(ip);
    }

    /// Number of distinct /16 subnets connected
    pub fn distinct_subnets(&self) -> usize {
        self.subnet_counts.len()
    }

    /// Check if we have enough subnet diversity
    pub fn has_sufficient_diversity(&self) -> bool {
        self.distinct_subnets() >= MIN_OUTBOUND_SUBNETS
    }

    /// Add an anchor peer (persists across restarts)
    pub fn add_anchor(&mut self, ip: String) {
        if self.anchor_peers.len() < MAX_ANCHOR_PEERS && !self.anchor_peers.contains(&ip) {
            self.anchor_peers.push(ip);
        }
    }

    /// Get anchor peers for reconnection after restart
    pub fn anchor_peers(&self) -> &[String] {
        &self.anchor_peers
    }

    /// Check if peer has verified cryptographic identity
    pub fn has_identity(&self, ip: &str) -> bool {
        self.identities.contains_key(ip)
    }

    /// Get peer's cryptographic identity
    pub fn get_identity(&self, ip: &str) -> Option<&PeerIdentity> {
        self.identities.get(ip)
    }

    pub fn subnet_count(&self, ip: &str) -> usize {
        let subnet = subnet_16(ip);
        self.subnet_counts.get(&subnet).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_extraction_ipv4() {
        assert_eq!(subnet_16("192.168.1.5:9333"), "v4:192.168");
        assert_eq!(subnet_16("10.0.0.1"), "v4:10.0");
        assert_eq!(subnet_16("172.16.5.100:7777"), "v4:172.16");
    }

    #[test]
    fn subnet_extraction_ipv6() {
        // Bracketed with port (standard SocketAddr format)
        assert_eq!(subnet_16("[2001:db8::1]:9333"), "v6:2001:0db8");
        // Bare IPv6 address
        assert_eq!(subnet_16("2001:db8:85a3::8a2e:370:7334"), "v6:2001:0db8");
        // Different /32 subnets produce different keys
        assert_ne!(subnet_16("[2001:db8::1]:9333"), subnet_16("[2600:1f18::1]:9333"));
        // Same /32 subnet produces same key regardless of host part
        assert_eq!(
            subnet_16("[2001:db8::1]:9333"),
            subnet_16("[2001:db8:aaaa::ffff]:9333"),
        );
    }

    #[test]
    fn subnet_ipv4_vs_ipv6_distinct() {
        // Even if numeric values overlap, v4 and v6 prefixes are distinct
        assert_ne!(subnet_16("10.0.0.1:9333"), subnet_16("[::ffff:10.0.0.1]:9333"));
    }

    #[test]
    fn diversity_limits_same_subnet() {
        let mut pd = PeerDiversity::new();
        assert!(pd.on_connect("192.168.1.1:9333", None));
        assert!(pd.on_connect("192.168.1.2:9333", None));
        // 2 peers from same /16 — third rejected atomically
        assert!(!pd.on_connect("192.168.1.3:9333", None));
        // Count must not have incremented on rejection
        assert_eq!(pd.subnet_count("192.168.1.3:9333"), 2);
    }

    #[test]
    fn diversity_allows_different_subnets() {
        let mut pd = PeerDiversity::new();
        assert!(pd.on_connect("192.168.1.1:9333", None));
        assert!(pd.on_connect("10.0.0.1:9333", None));
        assert!(pd.can_connect("172.16.0.1:9333"));
    }

    #[test]
    fn disconnect_frees_slot() {
        let mut pd = PeerDiversity::new();
        assert!(pd.on_connect("192.168.1.1:9333", None));
        assert!(pd.on_connect("192.168.1.2:9333", None));
        assert!(!pd.on_connect("192.168.1.3:9333", None));
        pd.on_disconnect("192.168.1.1:9333");
        assert!(pd.on_connect("192.168.1.3:9333", None));
    }

    #[test]
    fn distinct_subnet_count() {
        let mut pd = PeerDiversity::new();
        assert!(pd.on_connect("1.2.3.4:9333", None));
        assert!(pd.on_connect("5.6.7.8:9333", None));
        assert!(pd.on_connect("9.10.11.12:9333", None));
        assert_eq!(pd.distinct_subnets(), 3);
    }

    #[test]
    fn sufficient_diversity() {
        let mut pd = PeerDiversity::new();
        for i in 0..MIN_OUTBOUND_SUBNETS {
            assert!(pd.on_connect(&format!("{}.{}.0.1:9333", i + 1, i + 10), None));
        }
        assert!(pd.has_sufficient_diversity());
    }

    #[test]
    fn peer_identity_generation_and_verification() {
        let id = PeerIdentity::generate();
        assert!(id.verify(), "Generated identity must verify");
        assert_eq!(id.public_key.len(), 64);
        assert!(!id.peer_id().is_empty());
    }

    #[test]
    fn peer_identity_unique() {
        let id1 = PeerIdentity::generate();
        let id2 = PeerIdentity::generate();
        assert_ne!(id1.public_key, id2.public_key);
        assert_ne!(id1.peer_id(), id2.peer_id());
    }

    #[test]
    fn tampered_identity_fails() {
        let mut id = PeerIdentity::generate();
        id.public_key = "ff".repeat(32); // Tamper
        assert!(!id.verify());
    }

    #[test]
    fn anchor_peers() {
        let mut pd = PeerDiversity::new();
        pd.add_anchor("1.2.3.4:9333".into());
        pd.add_anchor("5.6.7.8:9333".into());
        assert_eq!(pd.anchor_peers().len(), 2);
    }

    #[test]
    fn identity_tracking() {
        let mut pd = PeerDiversity::new();
        let id = PeerIdentity::generate();
        assert!(pd.on_connect("1.2.3.4:9333", Some(id)));
        assert!(pd.has_identity("1.2.3.4:9333"));
        pd.on_disconnect("1.2.3.4:9333");
        assert!(!pd.has_identity("1.2.3.4:9333"));
    }
}
