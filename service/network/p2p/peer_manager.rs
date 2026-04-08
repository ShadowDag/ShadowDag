// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteBatch, IteratorMode};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::errors::NetworkError;
use crate::{slog_warn, slog_error};
use crate::service::network::dos_guard::BanCategory;

pub const BAN_DURATION_SECS:        u64   = 86_400;
pub const BAN_DURATION_SEVERE_SECS: u64   = 7 * 86_400;
pub const AUTO_BAN_THRESHOLD:       u64   = 100;
pub const SCORE_DECAY_INTERVAL:     u64   = 3_600;
pub const MAX_ADDR_CACHE_SIZE:      usize = 4_096;
pub const MAX_GETADDR_RESPONSE:     usize = 200;
pub const MAX_PEERS_PER_IP:         u32   = 3;
pub const PEER_HEALTH_TIMEOUT_SECS: u64   = 300;

const PFX_BAN:        &str = "ban:";
const PFX_PENALTY:    &str = "penalty:";
const PFX_ADDR:       &str = "addr:";
const PFX_PEER:       &str = "peer:";
const PFX_LAST_SEEN:  &str = "seen:";
const PFX_CONN_COUNT: &str = "conn:";
const PFX_LATENCY:    &str = "latency:";
const PFX_HEIGHT:     &str = "height:";
const PFX_BAN_COUNT:  &str = "bancnt:";
const PFX_BAN_CAT:    &str = "bancat:";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    pub addr:        String,
    pub port:        u16,
    pub first_seen:  u64,
    pub last_seen:   u64,
    pub services:    u64,
    pub user_agent:  String,
    pub best_height: u64,
    pub latency_ms:  u64,
    pub ban_score:   u64,
    pub is_banned:   bool,
    pub ban_until:   u64,
    pub inbound:     bool,
    pub version:     u32,
}

impl PeerRecord {
    pub fn new(addr: &str, port: u16) -> Self {
        let now = unix_now();
        Self {
            addr: addr.to_string(),
            port,
            first_seen:  now,
            last_seen:   now,
            services:    0,
            user_agent:  String::new(),
            best_height: 0,
            latency_ms:  9999,
            ban_score:   0,
            is_banned:   false,
            ban_until:   0,
            inbound:     false,
            version:     1,
        }
    }

    pub fn is_active(&self) -> bool {
        let now = unix_now();
        !self.is_banned && (now - self.last_seen) < PEER_HEALTH_TIMEOUT_SECS
    }

    pub fn health_score(&self) -> i64 {
        let latency_penalty = (self.latency_ms / 100) as i64;
        let ban_penalty     = self.ban_score as i64 * 2;
        100_i64 - latency_penalty - ban_penalty
    }
}

static PEER_MANAGER_INSTANCE: OnceLock<Arc<PeerManager>> = OnceLock::new();

pub struct PeerManager {
    db:           Arc<Mutex<DB>>,
    addr_cache:   Arc<Mutex<Vec<String>>>,
    _network_path: String,
    network:      crate::config::node::node_config::NetworkMode,
}

impl PeerManager {
    pub fn global(path: &str) -> Result<Arc<Self>, NetworkError> {
        // Fast path: already initialised.
        if let Some(pm) = PEER_MANAGER_INSTANCE.get() {
            // Warn if caller requests a different path than what was initialised.
            // OnceLock returns the same instance regardless of path after first init,
            // which silently ignores the new path. This makes the mismatch visible.
            if pm._network_path != path {
                slog_warn!("p2p", "peer_manager_path_mismatch",
                    requested => path,
                    active => &pm._network_path
                );
            }
            return Ok(pm.clone());
        }

        // Try primary path, then fallback, then temp.
        let pm = Self::open(path).or_else(|e| {
            slog_warn!("p2p", "peer_db_open_failed", path => path, error => &e.to_string());
            let fallback = format!("{}_fallback", path);
            Self::open(&fallback)
        }).or_else(|e| {
            slog_warn!("p2p", "peer_db_fallback_failed", error => &e.to_string());
            let temp = std::env::temp_dir().join(format!("shadowdag_peer_emergency_{}", std::process::id()));
            Self::open(temp.to_str().unwrap_or("/tmp/shadowdag_peer_emergency"))
        })?;

        let arc = Arc::new(pm);
        // Another thread may have raced us — that's fine, use whichever won.
        let _ = PEER_MANAGER_INSTANCE.set(arc.clone());
        Ok(PEER_MANAGER_INSTANCE.get().cloned().unwrap_or(arc))
    }

    pub fn open(path: &str) -> Result<Self, NetworkError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(32 * 1024 * 1024);
        opts.set_max_open_files(64);
        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| NetworkError::Storage(crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            }))?;
        Ok(Self {
            db:           Arc::new(Mutex::new(db)),
            addr_cache:   Arc::new(Mutex::new(Vec::new())),
            _network_path: path.to_string(),
            network:      crate::config::node::node_config::NetworkMode::Mainnet,
        })
    }

    pub fn new(path: &str) -> Option<Self> {
        match Self::open(path) {
            Ok(mgr) => Some(mgr),
            Err(e) => {
                slog_error!("p2p", "peer_manager_open_failed", path => path, error => &e.to_string());
                None
            }
        }
    }

    pub fn new_default() -> Result<Self, NetworkError> {
        let base = crate::config::node::node_config::NetworkMode::base_data_dir();
        let primary = base.join("peers");
        let fallback = base.join("peers_fallback");
        let temp = std::env::temp_dir()
            .join(format!("shadowdag_peer_emergency_{}", std::process::id()));

        let paths = [
            primary.to_string_lossy().to_string(),
            fallback.to_string_lossy().to_string(),
            temp.to_string_lossy().to_string(),
        ];

        let mut last_err = None;
        for p in &paths {
            match Self::open(p) {
                Ok(pm) => return Ok(pm),
                Err(e) => {
                    slog_warn!("p2p", "peer_db_open_failed", path => p.as_str(), error => &e.to_string());
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| NetworkError::Other(
            "all peer DB paths exhausted".to_string(),
        )))
    }

    /// Create a PeerManager with a unique temp path (for tests).
    /// Create a temporary PeerManager for testing.
    /// Returns a fallback in-memory default if DB creation fails.
    pub fn new_temp() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let path = format!("/tmp/shadowdag_peer_test_{}_{}", std::process::id(), id);
        Self::open(&path).or_else(|_| Self::new_default())
            .expect("new_temp: cannot open any DB for testing")
    }

    pub fn new_default_path(path: &str) -> Result<Self, NetworkError> {
        Self::open(path).or_else(|e| {
            slog_warn!("p2p", "peer_db_open_failed", path => path, error => &e.to_string());
            let fallback = format!("{}_fallback", path);
            Self::open(&fallback)
        }).or_else(|e| {
            slog_warn!("p2p", "peer_db_fallback_failed", error => &e.to_string());
            let temp = std::env::temp_dir().join(format!("shadowdag_peer_emergency_{}", std::process::id()));
            Self::open(temp.to_str().unwrap_or("/tmp/shadowdag_peer_emergency"))
        })
    }

    fn lock_db(&self) -> std::sync::MutexGuard<'_, DB> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn add_peer(&self, addr: &str) -> Result<(), NetworkError> {
        let port = addr.rsplit(':').next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(9333);
        self.add_peer_record(PeerRecord::new(addr, port))
    }

    pub fn add_peer_record(&self, record: PeerRecord) -> Result<(), NetworkError> {
        if self.is_banned(&record.addr) {
            return Err(NetworkError::PeerBanned(record.addr.clone()));
        }

        let ip    = record.addr.split(':').next().unwrap_or(&record.addr);
        let count = self.conn_count_for_ip(ip);
        if count >= MAX_PEERS_PER_IP {
            return Err(NetworkError::ConnectionFailed(
                format!("IP {} already has {} connections", ip, count)
            ));
        }

        let data = bincode::serialize(&record)
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;
        let db   = self.lock_db();
        let already_exists = db.get(format!("{}{}", PFX_PEER, record.addr).as_bytes())
            .map(|v| v.is_some()).unwrap_or(false);
        let mut batch = WriteBatch::default();
        let key = format!("{}{}", PFX_PEER, record.addr);
        batch.put(key.as_bytes(), &data);
        batch.put(format!("{}{}", PFX_LAST_SEEN, record.addr).as_bytes(),
                  unix_now().to_le_bytes());
        // Only increment conn_count if this is a NEW peer
        if !already_exists {
            batch.put(format!("{}{}", PFX_CONN_COUNT, ip).as_bytes(),
                      (count + 1).to_le_bytes());
        }
        db.write(batch).map_err(|e| NetworkError::Storage(crate::errors::StorageError::WriteFailed(e.to_string())))
    }

    pub fn remove_peer(&self, addr: &str) -> Result<(), NetworkError> {
        if !self.peer_exists(addr) {
            return Ok(()); // Nothing to remove
        }
        let ip    = addr.split(':').next().unwrap_or(addr);
        let count = self.conn_count_for_ip(ip);
        let db    = self.lock_db();
        let mut batch = WriteBatch::default();
        batch.delete(format!("{}{}", PFX_PEER,      addr).as_bytes());
        batch.delete(format!("{}{}", PFX_LAST_SEEN, addr).as_bytes());
        batch.delete(format!("{}{}", PFX_HEIGHT,    addr).as_bytes());
        batch.delete(format!("{}{}", PFX_LATENCY,   addr).as_bytes());
        if count > 0 {
            batch.put(format!("{}{}", PFX_CONN_COUNT, ip).as_bytes(),
                      (count - 1).to_le_bytes());
        }
        db.write(batch).map_err(|e| NetworkError::Storage(crate::errors::StorageError::WriteFailed(e.to_string())))
    }

    pub fn peer_exists(&self, addr: &str) -> bool {
        let db = self.lock_db();
        db.get(format!("{}{}", PFX_PEER, addr).as_bytes())
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    pub fn get_peer(&self, addr: &str) -> Option<PeerRecord> {
        let db = self.lock_db();
        match db.get(format!("{}{}", PFX_PEER, addr).as_bytes()) {
            Ok(Some(data)) => bincode::deserialize(&data).ok(),
            Ok(None) => None,
            Err(e) => {
                slog_error!("p2p", "peer_manager_read_failed", op => "get_peer", error => &e.to_string());
                None
            }
        }
    }

    pub fn update_peer_height(&self, addr: &str, height: u64) {
        let db = self.lock_db();
        let mut batch = WriteBatch::default();
        batch.put(format!("{}{}", PFX_HEIGHT, addr).as_bytes(), height.to_le_bytes());
        if let Ok(Some(data)) = db.get(format!("{}{}", PFX_PEER, addr).as_bytes()) {
            if let Ok(mut rec) = bincode::deserialize::<PeerRecord>(&data) {
                rec.best_height = height;
                if let Ok(new_data) = bincode::serialize(&rec) {
                    batch.put(format!("{}{}", PFX_PEER, addr).as_bytes(), &new_data);
                }
            }
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "update_peer_height", error => &e.to_string());
        }
    }

    pub fn update_peer_latency(&self, addr: &str, latency_ms: u64) {
        let db = self.lock_db();
        let mut batch = WriteBatch::default();
        batch.put(format!("{}{}", PFX_LATENCY, addr).as_bytes(), latency_ms.to_le_bytes());
        if let Ok(Some(data)) = db.get(format!("{}{}", PFX_PEER, addr).as_bytes()) {
            if let Ok(mut rec) = bincode::deserialize::<PeerRecord>(&data) {
                rec.latency_ms = latency_ms;
                if let Ok(new_data) = bincode::serialize(&rec) {
                    batch.put(format!("{}{}", PFX_PEER, addr).as_bytes(), &new_data);
                }
            }
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "update_peer_latency", error => &e.to_string());
        }
    }

    pub fn touch_peer(&self, addr: &str) {
        let now = unix_now();
        let db = self.lock_db();
        let mut batch = WriteBatch::default();
        batch.put(format!("{}{}", PFX_LAST_SEEN, addr).as_bytes(),
                        now.to_le_bytes());
        if let Ok(Some(data)) = db.get(format!("{}{}", PFX_PEER, addr).as_bytes()) {
            if let Ok(mut rec) = bincode::deserialize::<PeerRecord>(&data) {
                rec.last_seen = now;
                if let Ok(new_data) = bincode::serialize(&rec) {
                    batch.put(format!("{}{}", PFX_PEER, addr).as_bytes(), &new_data);
                }
            }
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "touch_peer", error => &e.to_string());
        }
    }

    pub fn get_peers(&self) -> Vec<String> {
        let db     = self.lock_db();
        let prefix = PFX_PEER.as_bytes();
        db.iterator(IteratorMode::Start)
            .filter_map(|r| r.ok())
            .filter(|(k, _)| k.starts_with(prefix))
            .filter_map(|(k, _)| {
                let s = std::str::from_utf8(&k).ok()?;
                Some(s[PFX_PEER.len()..].to_string())
            })
            .collect()
    }

    pub fn get_peer_records(&self) -> Vec<PeerRecord> {
        let db     = self.lock_db();
        let prefix = PFX_PEER.as_bytes();
        db.iterator(IteratorMode::Start)
            .filter_map(|r| r.ok())
            .filter(|(k, _)| k.starts_with(prefix))
            .filter_map(|(_, v)| bincode::deserialize::<PeerRecord>(&v).ok())
            .collect()
    }

    pub fn get_best_peers(&self, limit: usize) -> Vec<PeerRecord> {
        let mut peers = self.get_peer_records();
        peers.retain(|p| !self.is_banned(&p.addr) && p.is_active());
        peers.sort_by(|a, b| {
            b.health_score().cmp(&a.health_score())
                .then_with(|| b.best_height.cmp(&a.best_height))
                .then_with(|| a.addr.cmp(&b.addr))
        });
        peers.truncate(limit);
        peers
    }

    pub fn count(&self) -> usize {
        self.get_peers().len()
    }

    pub fn ban_peer(&self, addr: &str, duration_secs: u64, _reason: &str) {
        let until = unix_now() + duration_secs;
        let db    = self.lock_db();
        // Increment persistent ban count (survives restarts)
        let ban_count = self.read_ban_count_inner(&db, addr).saturating_add(1);
        let mut batch = WriteBatch::default();
        batch.put(format!("{}{}", PFX_BAN, addr).as_bytes(), until.to_le_bytes());
        batch.put(format!("{}{}", PFX_BAN_COUNT, addr).as_bytes(), ban_count.to_le_bytes());
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "ban_peer", error => &e.to_string());
        }
    }

    /// Ban with category-aware escalating duration.
    /// Uses persistent ban_count to compute exponentially increasing durations.
    pub fn ban_peer_categorized(&self, addr: &str, category: BanCategory, reason: &str) {
        let db = self.lock_db();
        let ban_count = self.read_ban_count_inner(&db, addr);
        let base = category.base_ban_duration();
        let exponent = ban_count.min(4); // cap shift at 4 (×16)
        let multiplier = 1u64 << exponent;
        let duration = base.saturating_mul(multiplier).min(30 * 86_400); // cap 30d
        let until = unix_now() + duration;
        let new_count = ban_count.saturating_add(1);
        let mut batch = WriteBatch::default();
        batch.put(format!("{}{}", PFX_BAN, addr).as_bytes(), until.to_le_bytes());
        batch.put(format!("{}{}", PFX_BAN_COUNT, addr).as_bytes(), new_count.to_le_bytes());
        batch.put(format!("{}{}", PFX_BAN_CAT, addr).as_bytes(), [category as u8]);
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "ban_peer_categorized", error => &e.to_string());
        }
        slog_warn!("p2p", "peer_banned", addr => addr, duration_secs => duration, ban_count => new_count, category => &format!("{:?}", category), reason => reason);
    }

    /// Read persistent ban count (must hold db lock already).
    fn read_ban_count_inner(&self, db: &DB, addr: &str) -> u32 {
        db.get(format!("{}{}", PFX_BAN_COUNT, addr).as_bytes())
            .ok()
            .flatten()
            .and_then(|d| d.get(..4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes))
            .unwrap_or(0)
    }

    /// Get persistent ban count for a peer (survives restarts).
    pub fn get_ban_count(&self, addr: &str) -> u32 {
        let db = self.lock_db();
        self.read_ban_count_inner(&db, addr)
    }

    pub fn unban_peer(&self, addr: &str) {
        let db = self.lock_db();
        let _  = db.delete(format!("{}{}", PFX_BAN, addr).as_bytes());
    }

    pub fn is_banned(&self, addr: &str) -> bool {
        let db = self.lock_db();
        if let Ok(Some(data)) = db.get(format!("{}{}", PFX_BAN, addr).as_bytes()) {
            // Strict: exactly 8 bytes → u64 timestamp.
            // Corrupted/short data → treat as banned (fail-closed, not fail-open).
            // Returning false on corrupt data would let attackers evade bans.
            match <[u8; 8]>::try_from(&data[..data.len().min(8)]) {
                Ok(bytes) if data.len() == 8 => {
                    let until = u64::from_le_bytes(bytes);
                    if unix_now() < until {
                        return true;
                    }
                    // Cleanup expired ban
                    let _ = db.delete(format!("{}{}", PFX_BAN, addr).as_bytes());
                }
                _ => {
                    // Corrupted ban record — fail closed: treat as banned.
                    // Operator can fix by unbanning explicitly.
                    slog_warn!("p2p", "corrupted_ban_record", addr => addr, bytes => data.len());
                    return true;
                }
            }
        }
        false
    }

    pub fn get_ban_expiry(&self, addr: &str) -> u64 {
        let db = self.lock_db();
        db.get(format!("{}{}", PFX_BAN, addr).as_bytes())
            .ok()
            .flatten()
            .and_then(|d| if d.len() >= 8 { d[..8].try_into().ok().map(u64::from_le_bytes) } else { None })
            .unwrap_or(0)
    }

    pub fn add_penalty(&self, addr: &str, points: u64, reason: &str) {
        self.add_penalty_categorized(addr, points, reason, BanCategory::Malformed)
    }

    /// Add penalty with offense category — triggers category-aware escalating ban
    /// when score reaches AUTO_BAN_THRESHOLD.
    pub fn add_penalty_categorized(&self, addr: &str, points: u64, reason: &str, category: BanCategory) {
        let current   = self.get_penalty(addr);
        let new_score = current.saturating_add(points);
        {
            let db = self.lock_db();
            let _  = db.put(format!("{}{}", PFX_PENALTY, addr).as_bytes(),
                            new_score.to_le_bytes());
        }
        if new_score >= AUTO_BAN_THRESHOLD {
            self.ban_peer_categorized(addr, category, reason);
        }
    }

    pub fn get_penalty(&self, addr: &str) -> u64 {
        let db = self.lock_db();
        db.get(format!("{}{}", PFX_PENALTY, addr).as_bytes())
            .ok()
            .flatten()
            .and_then(|d| d.get(..8).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes))
            .unwrap_or(0)
    }

    /// Decay all penalty scores. Category-aware: Resource decays 5×/call,
    /// Malformed 2×/call, Malicious 1×/call. Removes entries that reach 0.
    pub fn decay_penalties(&self) {
        let db     = self.lock_db();
        let prefix = PFX_PENALTY.as_bytes();
        let entries: Vec<(Vec<u8>, u64, String)> = db.iterator(IteratorMode::Start)
            .filter_map(|r| r.ok())
            .filter(|(k, _)| k.starts_with(prefix))
            .filter_map(|(k, v)| {
                let score = v.get(..8).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes)?;
                let addr = std::str::from_utf8(&k[prefix.len()..]).ok()?.to_string();
                Some((k.to_vec(), score, addr))
            })
            .collect();
        let mut batch = WriteBatch::default();
        for (key, score, addr) in entries {
            // Look up category for this peer to get the right decay rate
            let cat_byte = db.get(format!("{}{}", PFX_BAN_CAT, addr).as_bytes())
                .ok()
                .flatten()
                .and_then(|d| d.first().copied())
                .unwrap_or(1); // default = Malformed
            let decay_rate = match cat_byte {
                0 => 5u64, // Resource
                2 => 1,    // Malicious
                _ => 2,    // Malformed (default)
            };
            let new_score = score.saturating_sub(decay_rate);
            if new_score == 0 {
                batch.delete(&key);
            } else {
                batch.put(&key, new_score.to_le_bytes());
            }
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "decay_penalties", error => &e.to_string());
        }
    }

    pub fn store_addr(&self, addr: &str) {
        let db = self.lock_db();
        if let Err(e) = db.put(format!("{}{}", PFX_ADDR, addr).as_bytes(),
                               unix_now().to_le_bytes()) {
            slog_error!("p2p", "peer_manager_write_failed", op => "store_addr", error => &e.to_string());
        }
        drop(db);
        self.evict_addr_cache_if_full();
        let mut cache = self.addr_cache.lock().unwrap_or_else(|e| e.into_inner());
        if !cache.contains(&addr.to_string()) {
            cache.push(addr.to_string());
        }
    }

    pub fn add_addr_batch(&self, addrs: &[String]) {
        let db  = self.lock_db();
        let mut batch = WriteBatch::default();
        let now = unix_now().to_le_bytes();
        for addr in addrs {
            batch.put(format!("{}{}", PFX_ADDR, addr).as_bytes(), now);
        }
        if let Err(e) = db.write(batch) {
            slog_error!("p2p", "peer_manager_write_failed", op => "add_addr_batch", error => &e.to_string());
        }
    }

    pub fn get_addr_list(&self) -> Vec<String> {
        self.get_addr_list_limited(MAX_GETADDR_RESPONSE)
    }

    pub fn get_addr_list_limited(&self, max: usize) -> Vec<String> {
        let db     = self.lock_db();
        let prefix = PFX_ADDR.as_bytes();
        let cap    = max.min(MAX_ADDR_CACHE_SIZE);
        let mut addrs: Vec<String> = db.iterator(IteratorMode::Start)
            .filter_map(|r| r.ok())
            .filter(|(k, _)| k.starts_with(prefix))
            .filter_map(|(k, _)| {
                let s = std::str::from_utf8(&k).ok()?;
                Some(s[PFX_ADDR.len()..].to_string())
            })
            .take(cap)
            .collect();
        addrs.sort();
        addrs
    }

    pub fn addr_cache_size(&self) -> usize {
        self.addr_cache.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn evict_addr_cache_if_full(&self) {
        let mut cache = self.addr_cache.lock().unwrap_or_else(|e| e.into_inner());
        while cache.len() >= MAX_ADDR_CACHE_SIZE {
            cache.remove(0);
        }
    }

    fn conn_count_for_ip(&self, ip: &str) -> u32 {
        let db = self.lock_db();
        match db.get(format!("{}{}", PFX_CONN_COUNT, ip).as_bytes()) {
            Ok(Some(data)) => {
                data.get(..4)
                    .and_then(|s| s.try_into().ok())
                    .map(u32::from_le_bytes)
                    .unwrap_or(0)
            }
            Ok(None) => 0,
            Err(e) => {
                slog_error!("p2p", "peer_manager_read_failed", op => "conn_count_for_ip", error => &e.to_string());
                0
            }
        }
    }

    pub fn has_enough_peers(&self, min: usize) -> bool {
        self.count() >= min
    }

    pub fn get_peer_height(&self, addr: &str) -> u64 {
        let db = self.lock_db();
        match db.get(format!("{}{}", PFX_HEIGHT, addr).as_bytes()) {
            Ok(Some(data)) => {
                data.get(..8)
                    .and_then(|s| s.try_into().ok())
                    .map(u64::from_le_bytes)
                    .unwrap_or(0)
            }
            Ok(None) => 0,
            Err(e) => {
                slog_error!("p2p", "peer_manager_read_failed", op => "get_peer_height", error => &e.to_string());
                0
            }
        }
    }

    /// Read the stored latency for a peer (stored separately from PeerRecord).
    /// This method mirrors the pattern of get_peer_height for use in tests.
    #[cfg(test)]
    pub fn get_peer_latency_ms(&self, addr: &str) -> u64 {
        let db = self.lock_db();
        db.get(format!("{}{}", PFX_LATENCY, addr).as_bytes())
            .ok()
            .flatten()
            .and_then(|d| d.get(..8).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes))
            .unwrap_or(9999)
    }

    pub fn best_peer_height(&self) -> u64 {
        let db     = self.lock_db();
        let prefix = PFX_HEIGHT.as_bytes();
        db.iterator(IteratorMode::Start)
            .filter_map(|r| r.ok())
            .filter(|(k, _)| k.starts_with(prefix))
            .filter_map(|(_, v)| v.get(..8).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes))
            .max()
            .unwrap_or(0)
    }

    pub fn stats(&self) -> HashMap<String, u64> {
        let mut map = HashMap::new();
        map.insert("total_peers".to_string(), self.count() as u64);
        map.insert("best_height".to_string(), self.best_peer_height());
        map
    }

    pub fn bootstrap_for_network(
        &self,
        network: &crate::config::node::node_config::NetworkMode,
    ) {
        use crate::config::network::bootstrap_nodes::BootstrapNodes;
        let seeds: Vec<String> = match network {
            crate::config::node::node_config::NetworkMode::Mainnet =>
                BootstrapNodes::mainnet().into_iter().map(|s| s.to_string()).collect(),
            crate::config::node::node_config::NetworkMode::Testnet =>
                BootstrapNodes::testnet().into_iter().map(|s| s.to_string()).collect(),
            crate::config::node::node_config::NetworkMode::Regtest =>
                BootstrapNodes::localhost().into_iter().map(|s| s.to_string()).collect(),
        };
        for addr in &seeds {
            if !self.peer_exists(addr) {
                let _ = self.add_peer(addr);
            }
        }
        self.add_addr_batch(&seeds);
    }

    pub fn discover_peers(&self) -> Vec<String> {
        self.get_addr_list()
    }

    pub fn bootstrap(&self) {
        self.bootstrap_for_network(&self.network);
    }

    pub fn bootstrap_with_seeds(&self, seeds: &[&str]) {
        let owned: Vec<String> = seeds.iter().map(|s| s.to_string()).collect();
        for addr in &owned {
            if !self.peer_exists(addr) {
                let _ = self.add_peer(addr);
            }
        }
        self.add_addr_batch(&owned);
    }
}

impl crate::domain::traits::sync_peers::SyncPeers for PeerManager {
    fn get_peers(&self) -> Vec<String> {
        self.get_peers()
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(label: &str) -> String { format!("/tmp/pm_test_{}", label) }

    #[test]
    fn add_and_remove_peer() {
        let path = tmp("add_rm");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        assert!(pm.add_peer("1.2.3.4:9333").is_ok());
        assert!(pm.peer_exists("1.2.3.4:9333"));
        assert!(pm.remove_peer("1.2.3.4:9333").is_ok());
        assert!(!pm.peer_exists("1.2.3.4:9333"));
    }

    #[test]
    fn ban_blocks_add() {
        let path = tmp("ban");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        pm.ban_peer("evil:9333", 9999, "spam");
        assert!(pm.is_banned("evil:9333"));
        assert!(pm.add_peer("evil:9333").is_err());
    }

    #[test]
    fn auto_ban_on_penalty() {
        let path = tmp("auto_ban");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        for _ in 0..AUTO_BAN_THRESHOLD {
            pm.add_penalty("bad:9333", 1, "test");
        }
        assert!(pm.is_banned("bad:9333"));
    }

    #[test]
    fn ban_expiry_returns_future_timestamp() {
        let path = tmp("ban_exp");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        pm.ban_peer("x:9333", 3600, "test");
        assert!(pm.get_ban_expiry("x:9333") > 0);
    }

    #[test]
    fn bootstrap_adds_mainnet_seeds() {
        let path = tmp("bootstrap");
        let _ = fs::remove_dir_all(&path);
        let pm = PeerManager::open(&path).unwrap();
        pm.bootstrap();
        assert!(pm.count() > 0);
    }
}
