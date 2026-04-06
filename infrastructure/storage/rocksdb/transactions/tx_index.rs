// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;

use crate::errors::StorageError;

pub struct TxIndex {
    db: DB,

}

impl TxIndex {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path))?;

        Ok(Self { db })
    }

    pub fn index_tx(&self, txid: &str, block_hash: &str) {
        if let Err(_e) = self.db.put(txid, block_hash) { eprintln!("[DB] put error: {}", _e); }

    }

    pub fn get_tx_block(&self, txid: &str) -> Option<String> {
        match self.db.get(txid).unwrap_or(None) {
            Some(data) => {
                Some(String::from_utf8(data.to_vec()).ok()?)
            }

            None => None
        }

    }

}
