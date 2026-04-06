// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use serde::{Serialize, Deserialize};
use std::path::Path;

use crate::errors::StorageError;

#[derive(Serialize, Deserialize, Clone)]
pub struct DagNode {
    pub hash: String,
    pub parents: Vec<String>,

}

pub struct DagStore {
    db: DB,

}

impl DagStore {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        Ok(Self { db })
    }

    pub fn save_node(&self, node: &DagNode) -> Result<(), StorageError> {
        let data = bincode::serialize(node).map_err(|e| {
            eprintln!("[DagStore] serialize error for node '{}': {}", node.hash, e);
            StorageError::Serialization(e.to_string())
        })?;

        self.db.put(&node.hash, data).map_err(|e| {
            eprintln!("[DagStore] put error for node '{}': {}", node.hash, e);
            StorageError::WriteFailed(e.to_string())
        })
    }

    pub fn get_node(&self, hash: &str) -> Option<DagNode> {
        match self.db.get(hash) {
            Ok(Some(data)) => bincode::deserialize(&data).ok(),
            Ok(None) => None,
            Err(e) => {
                eprintln!("[DagStore] DB read error for node '{}': {}", hash, e);
                None
            }
        }
    }

}
