// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

pub struct MinerStats {
    db: DB,

}

impl MinerStats {
    pub fn new(path: &str) -> Result<Self, crate::errors::StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;

        Ok(Self { db })

    }

    pub fn set_hashrate(&self, rate: u64) {
        if let Err(_e) = self.db.put("hashrate", rate.to_be_bytes()) { eprintln!("[DB] put error: {}", _e); }

    }

    pub fn get_hashrate(&self) -> Option<u64> {
        match self.db.get("hashrate").unwrap_or(None) {
            Some(bytes) => {
                if bytes.len() != 8 { return None; }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Some(u64::from_be_bytes(arr))
            }

            None => None

        }

    }

}
