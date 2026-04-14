// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::NetworkError;
use crate::slog_error;
use rocksdb::{Options, DB};
use std::path::Path;

pub struct DnsSeeds {
    db: DB,
}

impl DnsSeeds {
    pub fn new(path: &str) -> Result<Self, NetworkError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path)).map_err(|e| {
            NetworkError::Storage(crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })
        })?;

        Ok(Self { db })
    }

    pub fn add_seed(&self, address: &str) {
        if let Err(_e) = self.db.put(address, b"seed") {
            slog_error!("p2p", "db_put_error", error => &_e.to_string());
        }
    }
}
