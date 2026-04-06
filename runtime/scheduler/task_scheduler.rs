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

    pub fn schedule(&self, task_id: &str, payload: &str) {
        let key = format!("task:{}", task_id);
        if let Err(_e) = self.db.put(key.as_bytes(), payload.as_bytes()) { slog_error!("runtime", "task_scheduler_db_put_error", error => &_e.to_string()); }

    }

    pub fn get_task(&self, task_id: &str) -> Option<String> {
        let key = format!("task:{}", task_id);
        match self.db.get(key.as_bytes()).unwrap_or(None) {
            Some(data) => {
                Some(String::from_utf8(data.to_vec()).ok()?)
            }

            None => None

        }

    }

}
