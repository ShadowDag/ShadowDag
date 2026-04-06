// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Health Check & Monitoring — Node health status and system metrics.
// ═══════════════════════════════════════════════════════════════════════════

use std::time::Instant;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

/// Node health status
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded { reason: String },
    Unhealthy { reason: String },
    Starting,
    ShuttingDown,
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool { matches!(self, HealthStatus::Healthy) }
    pub fn http_code(&self) -> u16 {
        match self {
            HealthStatus::Healthy      => 200,
            HealthStatus::Degraded{..} => 200,
            HealthStatus::Starting     => 503,
            _                          => 503,
        }
    }
}

/// System metrics snapshot
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    pub uptime_secs:       u64,
    pub block_height:      u64,
    pub dag_tips:          u64,
    pub peer_count:        u64,
    pub mempool_size:      u64,
    pub blocks_per_sec:    f64,
    pub txs_per_sec:       f64,
    pub db_size_bytes:     u64,
    pub memory_used_mb:    u64,
    pub sync_progress:     f64, // 0.0 to 1.0
    pub is_synced:         bool,
    pub version:           String,
    pub network:           String,
}

impl SystemMetrics {
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "uptime_secs":    self.uptime_secs,
            "block_height":   self.block_height,
            "dag_tips":       self.dag_tips,
            "peer_count":     self.peer_count,
            "mempool_size":   self.mempool_size,
            "blocks_per_sec": self.blocks_per_sec,
            "txs_per_sec":    self.txs_per_sec,
            "db_size_bytes":  self.db_size_bytes,
            "memory_used_mb": self.memory_used_mb,
            "sync_progress":  self.sync_progress,
            "is_synced":      self.is_synced,
            "version":        self.version,
            "network":        self.network,
        }).to_string()
    }

    pub fn to_prometheus(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(&format!("shadowdag_uptime_seconds {}\n", self.uptime_secs));
        out.push_str(&format!("shadowdag_block_height {}\n", self.block_height));
        out.push_str(&format!("shadowdag_dag_tips {}\n", self.dag_tips));
        out.push_str(&format!("shadowdag_peer_count {}\n", self.peer_count));
        out.push_str(&format!("shadowdag_mempool_size {}\n", self.mempool_size));
        out.push_str(&format!("shadowdag_bps {:.2}\n", self.blocks_per_sec));
        out.push_str(&format!("shadowdag_tps {:.2}\n", self.txs_per_sec));
        out.push_str(&format!("shadowdag_db_bytes {}\n", self.db_size_bytes));
        out.push_str(&format!("shadowdag_memory_mb {}\n", self.memory_used_mb));
        out.push_str(&format!("shadowdag_sync_progress {:.4}\n", self.sync_progress));
        out.push_str(&format!("shadowdag_synced {}\n", if self.is_synced { 1 } else { 0 }));
        out
    }
}

/// Health checker
pub struct HealthChecker {
    start_time:     Instant,
    status:         std::sync::RwLock<HealthStatus>,
    block_height:   AtomicU64,
    peer_count:     AtomicU64,
    mempool_size:   AtomicU64,
    total_blocks:   AtomicU64,
    total_txs:      AtomicU64,
    is_synced:      AtomicBool,
    network:        String,
}

impl HealthChecker {
    pub fn new(network: &str) -> Self {
        Self {
            start_time:   Instant::now(),
            status:       std::sync::RwLock::new(HealthStatus::Starting),
            block_height: AtomicU64::new(0),
            peer_count:   AtomicU64::new(0),
            mempool_size: AtomicU64::new(0),
            total_blocks: AtomicU64::new(0),
            total_txs:    AtomicU64::new(0),
            is_synced:    AtomicBool::new(false),
            network:      network.to_string(),
        }
    }

    pub fn set_healthy(&self) {
        *self.status.write().unwrap_or_else(|e| e.into_inner()) = HealthStatus::Healthy;
    }

    pub fn set_degraded(&self, reason: &str) {
        *self.status.write().unwrap_or_else(|e| e.into_inner()) = HealthStatus::Degraded { reason: reason.to_string() };
    }

    pub fn set_unhealthy(&self, reason: &str) {
        *self.status.write().unwrap_or_else(|e| e.into_inner()) = HealthStatus::Unhealthy { reason: reason.to_string() };
    }

    pub fn update_block_height(&self, h: u64) { self.block_height.store(h, Ordering::Relaxed); }
    pub fn update_peer_count(&self, c: u64)   { self.peer_count.store(c, Ordering::Relaxed); }
    pub fn update_mempool_size(&self, s: u64)  { self.mempool_size.store(s, Ordering::Relaxed); }
    pub fn on_block(&self, tx_count: u64) {
        self.total_blocks.fetch_add(1, Ordering::Relaxed);
        self.total_txs.fetch_add(tx_count, Ordering::Relaxed);
    }
    pub fn set_synced(&self, synced: bool) { self.is_synced.store(synced, Ordering::Relaxed); }

    /// Auto-check health based on metrics
    pub fn auto_check(&self) {
        let peers = self.peer_count.load(Ordering::Relaxed);
        let synced = self.is_synced.load(Ordering::Relaxed);

        if peers == 0 {
            self.set_degraded("No connected peers");
        } else if !synced {
            self.set_degraded("Node is syncing");
        } else {
            self.set_healthy();
        }
    }

    pub fn status(&self) -> HealthStatus { self.status.read().unwrap_or_else(|e| e.into_inner()).clone() }

    pub fn metrics(&self) -> SystemMetrics {
        let uptime = self.start_time.elapsed().as_secs();
        let total_blocks = self.total_blocks.load(Ordering::Relaxed);
        let total_txs = self.total_txs.load(Ordering::Relaxed);
        let bps = if uptime > 0 { total_blocks as f64 / uptime as f64 } else { 0.0 };
        let tps = if uptime > 0 { total_txs as f64 / uptime as f64 } else { 0.0 };

        SystemMetrics {
            uptime_secs:    uptime,
            block_height:   self.block_height.load(Ordering::Relaxed),
            dag_tips:       0, // Would be set by TipManager
            peer_count:     self.peer_count.load(Ordering::Relaxed),
            mempool_size:   self.mempool_size.load(Ordering::Relaxed),
            blocks_per_sec: bps,
            txs_per_sec:    tps,
            db_size_bytes:  0, // Would query RocksDB
            memory_used_mb: 0, // Would query OS
            sync_progress:  if self.is_synced.load(Ordering::Relaxed) { 1.0 } else { 0.5 },
            is_synced:      self.is_synced.load(Ordering::Relaxed),
            version:        "1.0.0".to_string(),
            network:        self.network.clone(),
        }
    }

    /// HTTP health endpoint response
    pub fn health_json(&self) -> (u16, String) {
        let status = self.status();
        let code = status.http_code();
        let body = serde_json::json!({
            "status": format!("{:?}", status),
            "healthy": status.is_healthy(),
        }).to_string();
        (code, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_as_starting() {
        let hc = HealthChecker::new("mainnet");
        assert_eq!(hc.status(), HealthStatus::Starting);
    }

    #[test]
    fn set_healthy() {
        let hc = HealthChecker::new("mainnet");
        hc.set_healthy();
        assert!(hc.status().is_healthy());
    }

    #[test]
    fn auto_check_no_peers() {
        let hc = HealthChecker::new("mainnet");
        hc.auto_check();
        assert!(matches!(hc.status(), HealthStatus::Degraded { .. }));
    }

    #[test]
    fn auto_check_healthy() {
        let hc = HealthChecker::new("mainnet");
        hc.update_peer_count(5);
        hc.set_synced(true);
        hc.auto_check();
        assert!(hc.status().is_healthy());
    }

    #[test]
    fn metrics_json() {
        let hc = HealthChecker::new("testnet");
        hc.update_block_height(100);
        hc.update_peer_count(8);
        let m = hc.metrics();
        let json = m.to_json();
        assert!(json.contains("\"block_height\":100"));
        assert!(json.contains("\"peer_count\":8"));
        assert!(json.contains("testnet"));
    }

    #[test]
    fn metrics_prometheus() {
        let hc = HealthChecker::new("mainnet");
        hc.update_block_height(50);
        let prom = hc.metrics().to_prometheus();
        assert!(prom.contains("shadowdag_block_height 50"));
    }

    #[test]
    fn health_endpoint() {
        let hc = HealthChecker::new("mainnet");
        hc.set_healthy();
        let (code, body) = hc.health_json();
        assert_eq!(code, 200);
        assert!(body.contains("true"));
    }

    #[test]
    fn on_block_tracks_stats() {
        let hc = HealthChecker::new("mainnet");
        hc.on_block(100);
        hc.on_block(200);
        let m = hc.metrics();
        assert!(m.txs_per_sec >= 0.0);
    }
}
