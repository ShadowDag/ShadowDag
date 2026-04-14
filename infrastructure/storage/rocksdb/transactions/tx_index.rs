// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{Options, DB};
use std::path::Path;

use crate::errors::StorageError;
use crate::slog_error;

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

    /// Index a transaction by its hash.
    ///
    /// WARNING: Returns () even on write failure (logs error only).
    /// Callers should check the transaction is queryable after indexing
    /// if correctness is critical.
    pub fn index_tx(&self, txid: &str, block_hash: &str) {
        if let Err(e) = self.db.put(txid, block_hash) {
            slog_error!("storage", "tx_index_put_error", txid => txid, error => e);
        }
    }

    pub fn get_tx_block(&self, txid: &str) -> Option<String> {
        match self.db.get(txid) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    slog_error!("storage", "tx_index_utf8_error", txid => txid, error => e);
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("storage", "tx_block_read_error_returns_none",
                    txid => txid, error => e);
                None
            }
        }
    }
}
