// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::DB;
use std::sync::Arc;
use crate::slog_error;

pub struct RuntimeManager {
    db: Arc<DB>,
}

impl RuntimeManager {
    /// ياخذ DB جاهز من النظام (NodeDB)
    pub fn new(db: Arc<DB>) -> Self {
        Self { db }
    }

    /// تشغيل runtime
    pub fn start(&self) {
        self.set_state("runtime:status", "running");
        self.set_state("runtime:version", "0.1.0");
    }

    /// ايقاف runtime
    pub fn stop(&self) {
        self.set_state("runtime:status", "stopped");
    }

    /// كتابة state
    pub fn set_state(&self, key: &str, value: &str) {
        if let Err(e) = self.db.put(key.as_bytes(), value.as_bytes()) {
            slog_error!("runtime", "runtime_manager_db_put_error", error => &e.to_string());
        }
    }

    /// قراءة state
    pub fn get_state(&self, key: &str) -> Option<String> {
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => String::from_utf8(data.to_vec()).ok(),
            Ok(None) => None,
            Err(e) => {
                slog_error!("runtime", "runtime_manager_db_get_error", error => &e.to_string());
                None
            }
        }
    }
}
