// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{
    DB, Options,
    WriteOptions, ReadOptions,
    SliceTransform, WriteBatch,
    IteratorMode, Direction,
};

use std::path::Path;

// ─────────────────────────────────────────
// PREFIX
// ─────────────────────────────────────────
const SIG_PREFIX: &[u8] = b"edsig:";
const PREFIX_LEN: usize = 6;
const PREFIX_UPPER: &[u8] = b"edsig:\xFF";

// ─────────────────────────────────────────
// STORE
// ─────────────────────────────────────────

pub struct Ed25519Store {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl Ed25519Store {

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

        // Simple allocation — correctness over micro-optimization.
        let mut buf = Vec::with_capacity(SIG_PREFIX.len() + key.len());
        buf.extend_from_slice(SIG_PREFIX);
        buf.extend_from_slice(key.as_bytes());
        f(&buf)
    }

    // ─────────────────────────────────────────
    // STORE
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn store_signature(&self, key: &str, signature: &str) {
        Self::with_key(key, |k| {
            let _ = self.db.put_opt(k, signature.as_bytes(), &self.write_opts);
        });
    }

    #[inline(always)]
    pub fn store_signature_raw(&self, key: &str, sig: &[u8]) {
        Self::with_key(key, |k| {
            let _ = self.db.put_opt(k, sig, &self.write_opts);
        });
    }

    // ─────────────────────────────────────────
    // GET
    // ─────────────────────────────────────────

    #[inline(always)]
    #[must_use]
    pub fn get_signature(&self, key: &str) -> Option<String> {
        Self::with_key(key, |k| {
            self.db.get_pinned_opt(k, &self.read_opts)
                .ok()
                .flatten()
                .and_then(|v| std::str::from_utf8(&v).ok().map(|s| s.to_string()))
        })
    }

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

    // ─────────────────────────────────────────
    // MULTI GET
    // ─────────────────────────────────────────

    #[inline(always)]
    #[must_use]
    pub fn multi_get_raw(&self, keys: &[&str]) -> Vec<Option<Vec<u8>>> {
        let mut db_keys = Vec::with_capacity(keys.len());

        for key in keys {
            db_keys.push(Self::with_key(key, |k| k.to_vec()));
        }

        self.db.multi_get(db_keys)
            .into_iter()
            .map(|res| res.ok().flatten().map(|v| v.to_vec()))
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

        for key in keys {
            Self::with_key(key, |k| {
                batch.delete(k);
            });
        }

        let _ = self.db.write_opt(batch, &self.write_opts);
    }

    // ─────────────────────────────────────────
    // CLEAR
    // ─────────────────────────────────────────

    pub fn clear_signatures(&self) {
        let mut batch = WriteBatch::default();

        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_upper_bound(PREFIX_UPPER.to_vec());
        read_opts.set_prefix_same_as_start(true);

        let iter = self.db.iterator_opt(
            IteratorMode::From(SIG_PREFIX, Direction::Forward),
            read_opts,
        );

        for item in iter {
            let (k, _) = match item {
                Ok(kv) => kv,
                Err(_) => break,
            };
            batch.delete(&*k);
        }

        let _ = self.db.write_opt(batch, &self.write_opts);
    }
}