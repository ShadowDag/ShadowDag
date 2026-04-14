// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::StorageError;
use rocksdb::{IteratorMode, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SNAPSHOT_INTERVAL_BLOCKS: u64 = 10_000;
pub const MAX_SNAPSHOTS: usize = 5;
pub const SNAPSHOT_VERSION: u32 = 2;
pub const CHUNK_SIZE_BYTES: usize = 65_536;
pub const SNAPSHOT_MAGIC: &[u8] = b"SDAGSNAP";
/// Max allowed chunks per snapshot — prevents memory exhaustion from crafted metadata.
pub const MAX_SNAPSHOT_CHUNKS: u64 = 500_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoSnapshotEntry {
    pub txid: String,
    pub index: u32,
    pub address: String,
    pub amount: u64,
    pub height: u64,
    pub is_coinbase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub version: u32,
    pub block_hash: String,
    pub block_height: u64,
    pub utxo_count: u64,
    pub merkle_root: String,
    pub size_bytes: u64,
    pub chunk_count: u64,
    pub created_at: u64,
    pub network: String,
}

impl SnapshotMetadata {
    pub fn chunk_count_for(utxo_count: u64) -> u64 {
        let entries_per_chunk = (CHUNK_SIZE_BYTES / 128) as u64;
        utxo_count.div_ceil(entries_per_chunk)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotChunk {
    pub chunk_index: u64,
    pub total_chunks: u64,
    pub entries: Vec<UtxoSnapshotEntry>,
    pub chunk_hash: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotProgress {
    pub meta: SnapshotMetadata,
    pub received: Vec<bool>,
    pub from_peers: HashMap<u64, String>,
}

impl SnapshotProgress {
    pub fn new(meta: SnapshotMetadata) -> Self {
        let chunks = meta.chunk_count as usize;
        Self {
            meta,
            received: vec![false; chunks],
            from_peers: HashMap::new(),
        }
    }

    pub fn mark_received(&mut self, chunk_index: u64, peer: &str) {
        if (chunk_index as usize) < self.received.len() {
            self.received[chunk_index as usize] = true;
            self.from_peers.insert(chunk_index, peer.to_string());
        }
    }

    pub fn is_complete(&self) -> bool {
        self.received.iter().all(|r| *r)
    }

    pub fn completion_pct(&self) -> u64 {
        let done = self.received.iter().filter(|r| **r).count();
        (done as u64 * 100) / self.received.len().max(1) as u64
    }

    pub fn missing_chunks(&self) -> Vec<u64> {
        self.received
            .iter()
            .enumerate()
            .filter(|(_, r)| !*r)
            .map(|(i, _)| i as u64)
            .collect()
    }
}

pub struct SnapshotManager {
    db: Arc<Mutex<DB>>,
    progress: Arc<Mutex<Option<SnapshotProgress>>>,
    network: String,
}

impl SnapshotManager {
    pub fn new(path: &str, network: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        let db = DB::open(&opts, Path::new(path)).map_err(|e| StorageError::OpenFailed {
            path: path.to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            progress: Arc::new(Mutex::new(None)),
            network: network.to_string(),
        })
    }

    fn lock_db(&self) -> std::sync::MutexGuard<'_, DB> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn create_snapshot(
        &self,
        block_hash: &str,
        block_height: u64,
        utxos: &[UtxoSnapshotEntry],
    ) -> Result<SnapshotMetadata, StorageError> {
        let merkle_root = self.compute_merkle_root(utxos);
        let chunk_count = SnapshotMetadata::chunk_count_for(utxos.len() as u64);

        let meta = SnapshotMetadata {
            version: SNAPSHOT_VERSION,
            block_hash: block_hash.to_string(),
            block_height,
            utxo_count: utxos.len() as u64,
            merkle_root: merkle_root.clone(),
            size_bytes: (utxos.len() * 128) as u64,
            chunk_count,
            created_at: unix_now(),
            network: self.network.clone(),
        };

        let db = self.lock_db();
        let meta_key = format!("snap:meta:{}", block_height);
        let meta_data =
            bincode::serialize(&meta).map_err(|e| StorageError::Serialization(e.to_string()))?;
        db.put(meta_key.as_bytes(), &meta_data)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;

        let entries_per_chunk = (CHUNK_SIZE_BYTES / 128).max(1);
        let mut batch = WriteBatch::default();

        for (chunk_idx, chunk_entries) in utxos.chunks(entries_per_chunk).enumerate() {
            let chunk = SnapshotChunk {
                chunk_index: chunk_idx as u64,
                total_chunks: chunk_count,
                entries: chunk_entries.to_vec(),
                chunk_hash: self.hash_chunk(chunk_entries),
            };
            let chunk_key = format!("snap:chunk:{}:{}", block_height, chunk_idx);
            let chunk_data = bincode::serialize(&chunk)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            batch.put(chunk_key.as_bytes(), &chunk_data);
        }
        db.write(batch)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;

        self.prune_old_snapshots(&db);

        Ok(meta)
    }

    pub fn list_snapshots(&self) -> Vec<SnapshotMetadata> {
        let db = self.lock_db();
        let prefix = b"snap:meta:";
        let mut metas: Vec<SnapshotMetadata> = Vec::new();
        for item in db.iterator(IteratorMode::Start) {
            match item {
                Ok((k, v)) => {
                    if !k.starts_with(prefix) {
                        continue;
                    }
                    match bincode::deserialize::<SnapshotMetadata>(&v) {
                        Ok(m) => metas.push(m),
                        Err(e) => {
                            log::error!("[Snapshot] failed to deserialize metadata: {}", e);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    log::error!("[Snapshot] DB iterator read failed: {}", e);
                    continue;
                }
            }
        }
        metas.sort_by(|a, b| b.block_height.cmp(&a.block_height));
        metas
    }

    pub fn best_snapshot(&self) -> Option<SnapshotMetadata> {
        self.list_snapshots().into_iter().next()
    }

    pub fn get_chunk(&self, height: u64, chunk_index: u64) -> Option<SnapshotChunk> {
        let db = self.lock_db();
        let key = format!("snap:chunk:{}:{}", height, chunk_index);
        let data = match db.get(key.as_bytes()) {
            Ok(Some(d)) => d,
            Ok(None) => return None,
            Err(e) => {
                log::error!(
                    "[Snapshot] DB read failed for chunk {}:{}: {}",
                    height,
                    chunk_index,
                    e
                );
                return None;
            }
        };
        match bincode::deserialize(&data) {
            Ok(chunk) => Some(chunk),
            Err(e) => {
                log::error!(
                    "[Snapshot] failed to deserialize chunk {}:{}: {}",
                    height,
                    chunk_index,
                    e
                );
                None
            }
        }
    }

    pub fn begin_download(&self, meta: SnapshotMetadata) {
        let mut prog = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        *prog = Some(SnapshotProgress::new(meta));
    }

    pub fn receive_chunk(&self, chunk: SnapshotChunk, peer: &str) -> Result<bool, StorageError> {
        let expected = self.hash_chunk(&chunk.entries);
        if expected != chunk.chunk_hash {
            return Err(StorageError::Other(format!(
                "Chunk {} hash mismatch",
                chunk.chunk_index
            )));
        }

        // Check active download FIRST — avoid writing to DB if no download is in progress
        {
            let prog = self.progress.lock().unwrap_or_else(|e| e.into_inner());
            match prog.as_ref() {
                None => return Err(StorageError::Other("No active download".to_string())),
                Some(p) => {
                    if chunk.chunk_index >= p.meta.chunk_count {
                        return Err(StorageError::Other(format!(
                            "chunk index {} exceeds total chunks {}",
                            chunk.chunk_index, p.meta.chunk_count
                        )));
                    }
                }
            }
        }

        // THEN write chunk to DB
        {
            let db = self.lock_db();
            let key = format!("snap:dl:chunk:{}", chunk.chunk_index);
            let data = bincode::serialize(&chunk)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            db.put(key.as_bytes(), &data)
                .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        }

        let mut prog = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = prog.as_mut() {
            p.mark_received(chunk.chunk_index, peer);
            let pct = p.completion_pct();
            if pct % 10 == 0 {
                log::info!("Snapshot download progress: {}%", pct);
            }
            Ok(p.is_complete())
        } else {
            Err(StorageError::Other("No active download".to_string()))
        }
    }

    pub fn apply_snapshot(&self) -> Result<SnapshotMetadata, StorageError> {
        let meta = {
            let prog = self.progress.lock().unwrap_or_else(|e| e.into_inner());
            match prog.as_ref() {
                Some(p) if p.is_complete() => p.meta.clone(),
                Some(_) => {
                    return Err(StorageError::Other(
                        "Snapshot download incomplete".to_string(),
                    ))
                }
                None => return Err(StorageError::Other("No active download".to_string())),
            }
        };

        // Validate snapshot version
        if meta.version != SNAPSHOT_VERSION {
            return Err(StorageError::Other(format!(
                "snapshot version {} != expected {}",
                meta.version, SNAPSHOT_VERSION
            )));
        }

        // Validate network matches
        if meta.network != self.network {
            return Err(StorageError::Other(format!(
                "snapshot network '{}' != expected '{}'",
                meta.network, self.network
            )));
        }

        if meta.chunk_count > MAX_SNAPSHOT_CHUNKS {
            return Err(StorageError::Other(format!(
                "chunk_count {} exceeds maximum {}",
                meta.chunk_count, MAX_SNAPSHOT_CHUNKS
            )));
        }

        let db = self.lock_db();
        let mut all_entries: Vec<UtxoSnapshotEntry> = Vec::new();
        for chunk_idx in 0..meta.chunk_count {
            let key = format!("snap:dl:chunk:{}", chunk_idx);
            let data = db
                .get(key.as_bytes())
                .map_err(|e| StorageError::ReadFailed(e.to_string()))?
                .ok_or_else(|| StorageError::KeyNotFound(format!("Missing chunk {}", chunk_idx)))?;
            let chunk: SnapshotChunk = bincode::deserialize(&data)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            all_entries.extend(chunk.entries);
        }

        let root = self.compute_merkle_root(&all_entries);
        if root != meta.merkle_root {
            return Err(StorageError::Other(format!(
                "Merkle root mismatch: got {} expected {}",
                root, meta.merkle_root
            )));
        }

        // Clear existing UTXO state before applying snapshot.
        // This prevents stale UTXOs from persisting after snapshot restore.
        {
            let mut clear_batch = WriteBatch::default();
            let iter = db.iterator(IteratorMode::Start);
            for (k, _) in iter.flatten() {
                // UTXO entries use 36-byte binary keys (UtxoKey format)
                if k.len() == 36 {
                    clear_batch.delete(&k);
                }
            }
            db.write(clear_batch)
                .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        }

        let mut batch = WriteBatch::default();
        for entry in &all_entries {
            // Use canonical binary UtxoKey (36 bytes) — matches the format used by
            // apply_block_dag_ordered and all other UTXO operations. Previously used
            // "utxo:txid:index" string which would be invisible to the UTXO layer.
            let key = crate::domain::utxo::utxo_set::utxo_key(&entry.txid, entry.index)?;
            let data = bincode::serialize(entry)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            batch.put(key.as_ref(), &data);
        }
        db.write(batch)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;

        Ok(meta)
    }

    pub fn download_progress(&self) -> Option<u64> {
        self.progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|p| p.completion_pct())
    }

    pub fn missing_chunks(&self) -> Vec<u64> {
        self.progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|p| p.missing_chunks())
            .unwrap_or_default()
    }

    fn prune_old_snapshots(&self, db: &DB) {
        let prefix = b"snap:meta:";
        let mut metas: Vec<SnapshotMetadata> = db
            .iterator(IteratorMode::Start)
            .filter_map(|r| r.ok())
            .filter(|(k, _)| k.starts_with(prefix))
            .filter_map(|(_, v)| bincode::deserialize::<SnapshotMetadata>(&v).ok())
            .collect();
        metas.sort_by(|a, b| b.block_height.cmp(&a.block_height));
        if metas.len() <= MAX_SNAPSHOTS {
            return;
        }
        let to_delete = &metas[MAX_SNAPSHOTS..];
        let mut batch = WriteBatch::default();
        for m in to_delete {
            let meta_key = format!("snap:meta:{}", m.block_height);
            batch.delete(meta_key.as_bytes());
            for c in 0..m.chunk_count {
                let ck = format!("snap:chunk:{}:{}", m.block_height, c);
                batch.delete(ck.as_bytes());
            }
        }
        if let Err(e) = db.write(batch) {
            log::error!("[Snapshot] prune_old_snapshots write failed: {}", e);
        }
    }

    fn compute_merkle_root(&self, utxos: &[UtxoSnapshotEntry]) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        for u in utxos {
            hasher.update(u.txid.as_bytes());
            hasher.update(u.index.to_le_bytes());
            hasher.update(u.amount.to_le_bytes());
            hasher.update(u.address.as_bytes());
            hasher.update(u.height.to_le_bytes());
            hasher.update([if u.is_coinbase { 1u8 } else { 0u8 }]);
        }
        hex::encode(hasher.finalize())
    }

    fn hash_chunk(&self, entries: &[UtxoSnapshotEntry]) -> String {
        self.compute_merkle_root(entries)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(l: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let pid = std::process::id();
        format!("/tmp/snap_{}_{}_{}", l, pid, ts)
    }
    fn mgr(l: &str) -> SnapshotManager {
        let p = tmp(l);
        let _ = fs::remove_dir_all(&p);
        SnapshotManager::new(&p, "mainnet").unwrap()
    }
    fn utxo(txid: &str, idx: u32, amt: u64) -> UtxoSnapshotEntry {
        UtxoSnapshotEntry {
            txid: txid.to_string(),
            index: idx,
            address: "addr1".to_string(),
            amount: amt,
            height: 100,
            is_coinbase: false,
        }
    }

    #[test]
    fn create_and_list() {
        let m = mgr("create");
        let utxos = vec![utxo("tx1", 0, 1000), utxo("tx2", 0, 2000)];
        let meta = m.create_snapshot("blockhash1", 10000, &utxos).unwrap();
        assert_eq!(meta.block_height, 10000);
        assert_eq!(meta.utxo_count, 2);
        let list = m.list_snapshots();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn chunk_roundtrip() {
        let m = mgr("chunk");
        let utxos: Vec<_> = (0..1000)
            .map(|i| utxo(&format!("tx{}", i), 0, i * 100))
            .collect();
        let meta = m.create_snapshot("hash1", 20000, &utxos).unwrap();
        for i in 0..meta.chunk_count {
            let chunk = m.get_chunk(20000, i).expect("chunk missing");
            assert_eq!(chunk.total_chunks, meta.chunk_count);
        }
    }

    #[test]
    fn snapshot_download_flow() {
        let m = mgr("download");
        let utxos = vec![utxo("tx1", 0, 500)];
        let meta = m.create_snapshot("bh", 5000, &utxos).unwrap();
        m.begin_download(meta.clone());

        for i in 0..meta.chunk_count {
            let chunk = m.get_chunk(5000, i).unwrap();
            m.receive_chunk(chunk, "peer1").unwrap();
        }
        assert_eq!(m.download_progress(), Some(100));
    }
}
