// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options,
    WriteOptions, ReadOptions,
    SliceTransform, WriteBatch,
};

use std::path::Path;

// ─────────────────────────────────────────
// PREFIX
// ─────────────────────────────────────────
const SIG_PREFIX: &[u8] = b"ssig:";
const PREFIX_LEN: usize = 5;

// ─────────────────────────────────────────
// STORE
// ─────────────────────────────────────────

pub struct SchnorrStore {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl SchnorrStore {

    // ─────────────────────────────────────────
    // INIT
    // ─────────────────────────────────────────
    pub fn new(path: &str) -> Result<Self, crate::errors::StorageError> {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(PREFIX_LEN));

        opts.increase_parallelism(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4) as i32
        );

        opts.optimize_level_style_compaction(256 * 1024 * 1024);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;

        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(false);
        write_opts.set_sync(false);
        write_opts.set_no_slowdown(true);

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(true);
        read_opts.set_prefix_same_as_start(true);

        Ok(Self { db, write_opts, read_opts })
    }

    // ─────────────────────────────────────────
    // KEY BUILDER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn with_key<F, R>(key: &str, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        assert!(!key.is_empty(), "key must not be empty");

        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(SIG_PREFIX);
        buf.extend_from_slice(key.as_bytes());
        f(&buf)
    }

    #[inline(always)]
    fn build_keys(&self, keys: &[&str]) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(keys.len());
        for &key in keys {
            out.push(Self::with_key(key, |k| k.to_vec()));
        }
        out
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn store_signature_raw(&self, key: &str, sig: &[u8]) {
        Self::with_key(key, |k| {
            let _ = self.db.put_opt(k, sig, &self.write_opts);
        });
    }

    #[inline(always)]
    pub fn store_signature_hex(&self, key: &str, sig_hex: &str) {
        Self::with_key(key, |k| {
            let _ = self.db.put_opt(k, sig_hex.as_bytes(), &self.write_opts);
        });
    }

    // ─────────────────────────────────────────
    // GET
    // ─────────────────────────────────────────

    #[inline(always)]
    #[must_use]
    pub fn get_signature_raw(&self, key: &str) -> Option<Vec<u8>> {
        Self::with_key(key, |k| {
            self.db.get_pinned_opt(k, &self.read_opts)
                .ok()
                .flatten()
                .map(|v| v.to_vec())
        })
    }

    #[inline(always)]
    #[must_use]
    pub fn get_signature_hex(&self, key: &str) -> Option<String> {
        Self::with_key(key, |k| {
            self.db.get_pinned_opt(k, &self.read_opts)
                .ok()
                .flatten()
                .and_then(|v| std::str::from_utf8(&v).ok().map(|s| s.to_string()))
        })
    }

    // ─────────────────────────────────────────
    // MULTI GET
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn multi_get_signatures(&self, keys: &[&str]) -> Vec<Option<Vec<u8>>> {
        let db_keys = self.build_keys(keys);

        self.db.multi_get(db_keys)
            .into_iter()
            .map(|res| match res {
                Ok(Some(v)) => Some(v.to_vec()),
                _ => None,
            })
            .collect()
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn signature_exists(&self, key: &str) -> bool {
        Self::with_key(key, |k| {
            self.db.get_pinned_opt(k, &self.read_opts)
                .map(|v| v.is_some())
                .unwrap_or(false)
        })
    }

    // ─────────────────────────────────────────
    // DELETE
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn delete_signature(&self, key: &str) {
        Self::with_key(key, |k| {
            let _ = self.db.delete_opt(k, &self.write_opts);
        });
    }

    #[inline(always)]
    pub fn delete_batch(&self, keys: &[&str]) {
        let mut batch = WriteBatch::default();

        for &key in keys {
            Self::with_key(key, |k| {
                batch.delete(k);
            });
        }

        let _ = self.db.write_opt(batch, &self.write_opts);
    }

    // ─────────────────────────────────────────
    // CLEAR (🔥 fastest safe)
    // ─────────────────────────────────────────

    pub fn clear_signatures(&self) {
        let iter = self.db.prefix_iterator(SIG_PREFIX);
        for (k, _) in iter.flatten() {
            if !k.starts_with(SIG_PREFIX) { break; }
            let _ = self.db.delete(&*k);
        }
    }
}