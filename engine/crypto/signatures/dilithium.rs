// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};

use rocksdb::{
    DB, Options,
    WriteOptions, ReadOptions,
    SliceTransform, WriteBatch,
    IteratorMode, Direction,
};

use std::path::Path;

// ─────────────────────────────────────────
// PREFIXES
// ─────────────────────────────────────────
const SIG_PREFIX: &[u8] = b"sig:";
const PREFIX_LEN: usize = 3;

const SIG_UPPER: &[u8] = b"sig:\xFF";

// ─────────────────────────────────────────
// DATA STRUCTS
// ─────────────────────────────────────────

pub struct DilithiumKeypair {
    pub public_key: dilithium3::PublicKey,
    pub secret_key: dilithium3::SecretKey,
    pub pk_hex:     String,
}

pub struct DilithiumSignatureData {
    pub signature:  dilithium3::DetachedSignature,
    pub sig_hex:    String,
}

// ─────────────────────────────────────────
// SIGNER
// ─────────────────────────────────────────

pub struct DilithiumSigner;

impl DilithiumSigner {

    #[inline(always)]
    pub fn generate_keypair() -> DilithiumKeypair {
        let (pk, sk) = dilithium3::keypair();

        DilithiumKeypair {
            pk_hex: hex::encode(pk.as_bytes()),
            public_key: pk,
            secret_key: sk,
        }
    }

    #[inline(always)]
    pub fn sign(message: &[u8], sk: &dilithium3::SecretKey) -> DilithiumSignatureData {
        let sig = dilithium3::detached_sign(message, sk);

        DilithiumSignatureData {
            sig_hex: hex::encode(sig.as_bytes()),
            signature: sig,
        }
    }

    #[inline(always)]
    pub fn verify(
        message: &[u8],
        sig:     &dilithium3::DetachedSignature,
        pk:      &dilithium3::PublicKey,
    ) -> bool {
        dilithium3::verify_detached_signature(sig, message, pk).is_ok()
    }

    #[inline(always)]
    pub fn sign_and_verify(message: &[u8]) -> bool {
        let kp  = Self::generate_keypair();
        let sig = Self::sign(message, &kp.secret_key);
        Self::verify(message, &sig.signature, &kp.public_key)
    }

    #[inline(always)]
    pub fn sign_str(data: &str, sk: &dilithium3::SecretKey) -> String {
        hex::encode(dilithium3::detached_sign(data.as_bytes(), sk).as_bytes())
    }
}

// ─────────────────────────────────────────
// STORE
// ─────────────────────────────────────────

pub struct DilithiumStore {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl DilithiumStore {

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

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(true);
        read_opts.set_prefix_same_as_start(true);

        Ok(Self { db, write_opts, read_opts })
    }

    // ─────────────────────────────────────────
    // KEY BUILDER
    // ─────────────────────────────────────────
    #[inline(always)]
    fn with_key<F, R>(prefix: &[u8], key: &str, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(key.as_bytes());
        f(&buf)
    }

    // ─────────────────────────────────────────
    // SIGNATURE
    // ─────────────────────────────────────────

    pub fn store_signature(&self, key: &str, signature: &str) {
        Self::with_key(SIG_PREFIX, key, |k| {
            let _ = self.db.put_opt(k, signature.as_bytes(), &self.write_opts);
        });
    }

    pub fn get_signature(&self, key: &str) -> Option<String> {
        Self::with_key(SIG_PREFIX, key, |k| {
            self.db.get_pinned_opt(k, &self.read_opts)
                .ok()
                .flatten()
                .and_then(|v| std::str::from_utf8(&v).ok().map(|s| s.to_string()))
        })
    }

    pub fn store_signature_raw(&self, key: &str, sig: &[u8]) {
        Self::with_key(SIG_PREFIX, key, |k| {
            let _ = self.db.put_opt(k, sig, &self.write_opts);
        });
    }

    pub fn get_signature_raw(&self, key: &str) -> Option<Vec<u8>> {
        Self::with_key(SIG_PREFIX, key, |k| {
            self.db.get_pinned_opt(k, &self.read_opts)
                .ok()
                .flatten()
                .map(|v| v.to_vec())
        })
    }

    // ─────────────────────────────────────────
    // MULTI GET (🔥 قوي)
    // ─────────────────────────────────────────

    pub fn multi_get_signatures(&self, keys: &[&str]) -> Vec<Option<Vec<u8>>> {
        let mut results = Vec::with_capacity(keys.len());

        for key in keys {
            let val = Self::with_key(SIG_PREFIX, key, |k| {
                self.db.get_pinned_opt(k, &self.read_opts)
                    .ok()
                    .flatten()
                    .map(|v| v.to_vec())
            });

            results.push(val);
        }

        results
    }

    // ─────────────────────────────────────────
    // EXISTS
    // ─────────────────────────────────────────

    pub fn signature_exists(&self, key: &str) -> bool {
        Self::with_key(SIG_PREFIX, key, |k| {
            self.db.get_pinned_opt(k, &self.read_opts)
                .map(|v| v.is_some())
                .unwrap_or(false)
        })
    }

    // ─────────────────────────────────────────
    // BATCH WRITE
    // ─────────────────────────────────────────

    pub fn batch_store_signatures(&self, items: &[(&str, &[u8])]) {
        let mut batch = WriteBatch::default();

        for (key, sig) in items {
            Self::with_key(SIG_PREFIX, key, |k| {
                batch.put(k, sig);
            });
        }

        let _ = self.db.write_opt(batch, &self.write_opts);
    }

    // ─────────────────────────────────────────
    // CLEAR (🔥 optimized)
    // ─────────────────────────────────────────

    pub fn clear_signatures(&self) {
        let mut batch = WriteBatch::default();

        let iter = self.db.iterator(IteratorMode::From(SIG_PREFIX, Direction::Forward));

        for item in iter {
            let (k, _) = match item {
                Ok(kv) => kv,
                Err(_) => break,
            };
            if k.as_ref() >= SIG_UPPER {
                break;
            }
            batch.delete(&*k);
        }

        let _ = self.db.write_opt(batch, &self.write_opts);
    }
}