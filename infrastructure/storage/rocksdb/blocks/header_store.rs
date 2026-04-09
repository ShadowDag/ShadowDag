// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;
use bincode;

use crate::domain::block::block_header::BlockHeader;
use crate::errors::StorageError;
use crate::slog_error;

pub struct HeaderStore {
    db: DB,
}

impl HeaderStore {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path))?;

        Ok(Self { db })
    }

    pub fn save_header(&self, header: &BlockHeader) -> Result<(), StorageError> {
        let data = bincode::serialize(header)
            .map_err(|e| StorageError::Serialization(format!("header serialize: {}", e)))?;
        if data.is_empty() {
            return Err(StorageError::Serialization("header serialized to empty bytes".into()));
        }
        self.db.put(&header.hash, &data)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    pub fn get_header(&self, hash: &str) -> Option<BlockHeader> {
        match self.db.get(hash.as_bytes()) {
            Ok(Some(data)) => {
                match bincode::deserialize(&data) {
                    Ok(h) => Some(h),
                    Err(e) => {
                        slog_error!("storage", "header_deserialize_failed", hash => hash, error => e);
                        None
                    }
                }
            }
            Ok(None) => None,
            Err(e) => {
                slog_error!("storage", "header_read_failed", hash => hash, error => e);
                None
            }
        }
    }

}
