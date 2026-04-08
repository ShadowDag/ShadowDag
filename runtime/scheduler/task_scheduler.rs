// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::DB;
use std::sync::Arc;
use crate::slog_error;

pub struct TaskScheduler {
    db: Arc<DB>,

}

impl TaskScheduler {
    pub fn new(db: Arc<DB>) -> Self {
        Self { db }

    }

    pub fn schedule(&self, task_id: &str, payload: &str) -> Result<(), rocksdb::Error> {
        let key = format!("task:{}", task_id);
        self.db.put(key.as_bytes(), payload.as_bytes())
    }

    pub fn get_task(&self, task_id: &str) -> Option<String> {
        let key = format!("task:{}", task_id);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => String::from_utf8(data.to_vec()).ok(),
            Ok(None) => None,
            Err(e) => {
                slog_error!("runtime", "get_task_read_failed", error => &e.to_string());
                None
            }
        }
    }

}
