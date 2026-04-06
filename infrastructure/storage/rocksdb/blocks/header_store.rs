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

    pub fn save_header(&self, header: &BlockHeader) {
        let data = bincode::serialize(header).unwrap_or_default();

        if let Err(e) = self.db.put(&header.hash, data) { slog_error!("storage", "header_put_error", error => e); }

    }

    pub fn get_header(&self, hash: &str) -> Option<BlockHeader> {
        match self.db.get(hash).unwrap_or(None) {
            Some(data) => {
                let header: BlockHeader =
                    bincode::deserialize(&data).ok()?;

                Some(header)
            }

            None => None
        }

    }

}
