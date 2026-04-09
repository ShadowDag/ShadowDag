// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

use crate::errors::StorageError;
use crate::slog_error;

pub struct BlockIndex {
    db: DB,

}

impl BlockIndex {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path))?;

        Ok(Self { db })
    }

    pub fn set_height(&self, hash: &str, height: u64) -> Result<(), StorageError> {
        self.db.put(hash, height.to_be_bytes())
            .map_err(|e| {
                slog_error!("storage", "height_index_write_failed", hash => hash, error => &e);
                StorageError::WriteFailed(e.to_string())
            })
    }

    pub fn get_height(&self, hash: &str) -> Option<u64> {
        match self.db.get(hash) {
            Ok(Some(bytes)) => {
                if bytes.len() < 8 {
                    slog_error!("storage", "block_index_corrupt_height", hash => hash, len => bytes.len());
                    return None;
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes[..8]);
                Some(u64::from_be_bytes(arr))
            }
            Ok(None) => None,
            Err(e) => {
                slog_error!("storage", "block_index_read_failed", hash => hash, error => e);
                None
            }
        }
    }

}
