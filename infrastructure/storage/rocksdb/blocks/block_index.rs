// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

use crate::errors::StorageError;

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

    pub fn set_height(&self, hash: &str, height: u64) {
        if let Err(_e) = self.db.put(hash, height.to_be_bytes()) { eprintln!("[DB] put error: {}", _e); }

    }

    pub fn get_height(&self, hash: &str) -> Option<u64> {
        match self.db.get(hash).unwrap_or(None) {
            Some(bytes) => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);

                Some(u64::from_be_bytes(arr))

            }

            None => None

        }

    }

}
