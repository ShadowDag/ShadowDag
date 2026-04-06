// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use crate::errors::NetworkError;

pub const MAX_OUTBOUND:          usize = 8;
pub const MAX_INBOUND:           usize = 56;
pub const MAX_TOTAL_CONNECTIONS: usize = 64;
pub const CONNECT_TIMEOUT_SECS:  u64   = 5;
pub const DISCONNECT_COOLDOWN:   u64   = 60;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Handshaking,
    Connected,
    Disconnecting,
    Disconnected,
    Banned,
}

#[derive(Debug, Clone)]
pub enum ConnectionDir {
    Inbound,
    Outbound,
}

#[derive(Debug)]
pub struct Connection {
    pub id:          u64,
    pub address:     String,
    pub direction:   ConnectionDir,
    pub state:       ConnectionState,
    pub connected_at: Instant,
    pub last_seen:   Instant,
    pub bytes_sent:  u64,
    pub bytes_recv:  u64,
    pub user_agent:  String,
    pub version:     u32,
    pub best_height: u64,
}

impl Connection {
    pub fn new_outbound(id: u64, address: impl Into<String>) -> Self {
        Self {
            id,
            address:      address.into(),
            direction:    ConnectionDir::Outbound,
            state:        ConnectionState::Connecting,
            connected_at: Instant::now(),
            last_seen:    Instant::now(),
            bytes_sent:   0,
            bytes_recv:   0,
            user_agent:   String::new(),
            version:      0,
            best_height:  0,
        }
    }

    pub fn new_inbound(id: u64, address: impl Into<String>) -> Self {
        let mut conn = Self::new_outbound(id, address);
        conn.direction = ConnectionDir::Inbound;
        conn.state     = ConnectionState::Handshaking;
        conn
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state,
            ConnectionState::Connecting | ConnectionState::Handshaking | ConnectionState::Connected)
    }

    pub fn uptime_secs(&self) -> u64 {
        self.connected_at.elapsed().as_secs()
    }
}

pub struct ConnectionManager {
    connections:       HashMap<u64, Connection>,
    banned_addrs:      HashMap<String, u64>,
    self_addrs:        HashSet<String>,
    next_id:           u64,
    local_addr:        String,
}

impl ConnectionManager {
    pub fn new(local_addr: impl Into<String>) -> Self {
        Self {
            connections:  HashMap::new(),
            banned_addrs: HashMap::new(),
            self_addrs:   HashSet::new(),
            next_id:      1,
            local_addr:   local_addr.into(),
        }
    }

    pub fn add_self_addr(&mut self, addr: impl Into<String>) {
        self.self_addrs.insert(addr.into());
    }

    pub fn is_self(&self, addr: &str) -> bool {
        self.self_addrs.contains(addr) || addr == self.local_addr
    }

    pub fn ban(&mut self, address: &str, duration_secs: u64) {
        let expiry = now_secs() + duration_secs;
        self.banned_addrs.insert(address.to_string(), expiry);

        let ids: Vec<u64> = self.connections.values()
            .filter(|c| c.address == address)
            .map(|c| c.id)
            .collect();
        for id in ids {
            self.disconnect(id);
        }
    }

    pub fn is_banned(&self, address: &str) -> bool {
        self.banned_addrs.get(address)
            .map(|&expiry| now_secs() < expiry)
            .unwrap_or(false)
    }

    pub fn unban_expired(&mut self) {
        let now = now_secs();
        self.banned_addrs.retain(|_, &mut expiry| expiry > now);
    }

    pub fn open_connection(&mut self, address: &str) -> Result<u64, NetworkError> {
        if self.is_self(address) {
            return Err(NetworkError::ConnectionFailed(
                format!("Rejected self-connection to {}", address)
            ));
        }
        if self.is_banned(address) {
            return Err(NetworkError::PeerBanned(address.to_string()));
        }
        let outbound_count = self.connections.values()
            .filter(|c| matches!(c.direction, ConnectionDir::Outbound) && c.is_active())
            .count();
        if outbound_count >= MAX_OUTBOUND {
            return Err(NetworkError::ConnectionFailed(
                format!("Max outbound reached ({})", MAX_OUTBOUND)
            ));
        }
        if self.total_active() >= MAX_TOTAL_CONNECTIONS {
            return Err(NetworkError::ConnectionFailed(
                "Max total connections reached".to_string()
            ));
        }
        let id = self.next_id;
        self.next_id += 1;
        let conn = Connection::new_outbound(id, address);
        self.connections.insert(id, conn);
        Ok(id)
    }

    pub fn accept_connection(&mut self, address: &str) -> Result<u64, NetworkError> {
        if self.is_banned(address) {
            return Err(NetworkError::PeerBanned(address.to_string()));
        }
        let inbound_count = self.connections.values()
            .filter(|c| matches!(c.direction, ConnectionDir::Inbound) && c.is_active())
            .count();
        if inbound_count >= MAX_INBOUND {
            return Err(NetworkError::ConnectionFailed(
                format!("Max inbound reached ({})", MAX_INBOUND)
            ));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.connections.insert(id, Connection::new_inbound(id, address));
        Ok(id)
    }

    pub fn disconnect(&mut self, id: u64) {
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.state = ConnectionState::Disconnected;
        }
    }

    pub fn prune_disconnected(&mut self) {
        self.connections.retain(|_, c| c.is_active());
    }

    pub fn on_handshake_complete(
        &mut self, id: u64,
        user_agent: &str, version: u32, best_height: u64,
    ) {
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.state       = ConnectionState::Connected;
            conn.user_agent  = user_agent.to_string();
            conn.version     = version;
            conn.best_height = best_height;
            conn.last_seen   = Instant::now();
        }
    }

    pub fn on_message_received(&mut self, id: u64, bytes: u64) {
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.last_seen  = Instant::now();
            conn.bytes_recv += bytes;
        }
    }

    pub fn on_message_sent(&mut self, id: u64, bytes: u64) {
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.bytes_sent += bytes;
        }
    }

    pub fn total_active(&self) -> usize {
        self.connections.values().filter(|c| c.is_active()).count()
    }

    pub fn outbound_count(&self) -> usize {
        self.connections.values()
            .filter(|c| matches!(c.direction, ConnectionDir::Outbound) && c.is_active())
            .count()
    }

    pub fn inbound_count(&self) -> usize {
        self.connections.values()
            .filter(|c| matches!(c.direction, ConnectionDir::Inbound) && c.is_active())
            .count()
    }

    pub fn connected_addresses(&self) -> Vec<String> {
        self.connections.values()
            .filter(|c| c.is_active())
            .map(|c| c.address.clone())
            .collect()
    }

    pub fn get(&self, id: u64) -> Option<&Connection> {
        self.connections.get(&id)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> ConnectionManager {
        ConnectionManager::new("0.0.0.0:9333")
    }

    #[test]
    fn open_outbound_succeeds() {
        let mut mgr = mgr();
        let id = mgr.open_connection("1.2.3.4:9333").unwrap();
        assert!(id > 0);
        assert_eq!(mgr.outbound_count(), 1);
    }

    #[test]
    fn reject_self_connection() {
        let mut mgr = mgr();
        assert!(mgr.open_connection("0.0.0.0:9333").is_err());
    }

    #[test]
    fn reject_banned_connection() {
        let mut mgr = mgr();
        mgr.ban("5.5.5.5:9333", 3600);
        assert!(mgr.open_connection("5.5.5.5:9333").is_err());
    }

    #[test]
    fn disconnect_marks_state() {
        let mut mgr = mgr();
        let id = mgr.open_connection("2.2.2.2:9333").unwrap();
        mgr.disconnect(id);
        assert_eq!(mgr.get(id).unwrap().state, ConnectionState::Disconnected);
    }

    #[test]
    fn handshake_sets_connected() {
        let mut mgr = mgr();
        let id = mgr.open_connection("3.3.3.3:9333").unwrap();
        mgr.on_handshake_complete(id, "ShadowDAG/0.1", 1, 100);
        assert_eq!(mgr.get(id).unwrap().state, ConnectionState::Connected);
    }

    #[test]
    fn prune_removes_disconnected() {
        let mut mgr = mgr();
        let id = mgr.open_connection("4.4.4.4:9333").unwrap();
        mgr.disconnect(id);
        mgr.prune_disconnected();
        assert!(mgr.get(id).is_none());
    }
}
