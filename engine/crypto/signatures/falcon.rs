// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};

use rocksdb::{
    DB, Options,
    WriteOptions, ReadOptions,
    SliceTransform,
};

use std::path::Path;
use crate::slog_error;

// ─────────────────────────────────────────
// PREFIX
// ─────────────────────────────────────────
const SIG_PREFIX: &[u8] = b"fsig:";
const PK_PREFIX:  &[u8] = b"fpk:";
const PREFIX_LEN: usize = 5;


// ─────────────────────────────────────────
// DATA STRUCTS
// ─────────────────────────────────────────

pub struct FalconKeypair {
    pub public_key: falcon512::PublicKey,
    pub secret_key: falcon512::SecretKey,
    pub pk_hex:     String,
}

pub struct FalconSignatureData {
    pub signature:   falcon512::DetachedSignature,
    pub sig_hex:     String,
    pub message_len: usize,
}

// ─────────────────────────────────────────
// SIGNER
// ─────────────────────────────────────────

pub struct FalconSigner;

impl FalconSigner {

    #[inline(always)]
    pub fn generate_keypair() -> FalconKeypair {
        let (pk, sk) = falcon512::keypair();

        FalconKeypair {
            pk_hex: hex::encode(pk.as_bytes()),
            public_key: pk,
            secret_key: sk,
        }
    }

    #[inline(always)]
    pub fn sign(message: &[u8], sk: &falcon512::SecretKey) -> FalconSignatureData {
        let sig = falcon512::detached_sign(message, sk);

        FalconSignatureData {
            sig_hex: hex::encode(sig.as_bytes()),
            message_len: message.len(),
            signature: sig,
        }
    }

    #[inline(always)]
    pub fn verify(
        message: &[u8],
        sig:     &falcon512::DetachedSignature,
        pk:      &falcon512::PublicKey,
    ) -> bool {
        falcon512::verify_detached_signature(sig, message, pk).is_ok()
    }

    #[inline(always)]
    pub fn sign_str(data: &str, sk: &falcon512::SecretKey) -> String {
        hex::encode(falcon512::detached_sign(data.as_bytes(), sk).as_bytes())
    }
}

// ─────────────────────────────────────────
// STORE
// ─────────────────────────────────────────

pub struct FalconStore {
    db: DB,
    write_opts: WriteOptions,
    read_opts: ReadOptions,
}

impl FalconStore {

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
    fn with_key<F, R>(prefix: &[u8], key: &str, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        assert!(!key.is_empty(), "key must not be empty");

        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(key.as_bytes());
        f(&buf)
    }

    #[inline(always)]
    fn build_keys(&self, prefix: &[u8], keys: &[&str]) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            out.push(Self::with_key(prefix, key, |k| k.to_vec()));
        }
        out
    }

    // ─────────────────────────────────────────
    // SIGNATURE
    // ─────────────────────────────────────────

    pub fn store_signature_raw(&self, key: &str, sig: &[u8]) {
        Self::with_key(SIG_PREFIX, key, |k| {
            if let Err(e) = self.db.put_opt(k, sig, &self.write_opts) {
                slog_error!("crypto", "falcon_store_sig_failed", error => e);
            }
        });
    }

    pub fn get_signature_raw(&self, key: &str) -> Option<Vec<u8>> {
        Self::with_key(SIG_PREFIX, key, |k| {
            match self.db.get_pinned_opt(k, &self.read_opts) {
                Ok(Some(v)) => Some(v.to_vec()),
                Ok(None) => None,
                Err(e) => {
                    slog_error!("crypto", "falcon_read_sig_failed", error => e);
                    None
                }
            }
        })
    }

    pub fn signature_exists(&self, key: &str) -> bool {
        Self::with_key(SIG_PREFIX, key, |k| {
            match self.db.get_pinned_opt(k, &self.read_opts) {
                Ok(v) => v.is_some(),
                Err(e) => {
                    slog_error!("crypto", "falcon_sig_exists_failed", error => e);
                    false
                }
            }
        })
    }

    pub fn multi_get_signatures(&self, keys: &[&str]) -> Vec<Option<Vec<u8>>> {
        let db_keys = self.build_keys(SIG_PREFIX, keys);

        self.db.multi_get(db_keys)
            .into_iter()
            .map(|r| match r {
                Ok(opt) => opt.map(|v| v.to_vec()),
                Err(e) => {
                    slog_error!("crypto", "falcon_multi_read_sig_failed", error => e);
                    None
                }
            })
            .collect()
    }

    pub fn delete_signature(&self, key: &str) {
        Self::with_key(SIG_PREFIX, key, |k| {
            if let Err(e) = self.db.delete_opt(k, &self.write_opts) {
                slog_error!("crypto", "falcon_delete_sig_failed", error => e);
            }
        });
    }

    // ─────────────────────────────────────────
    // PUBLIC KEY
    // ─────────────────────────────────────────

    pub fn store_public_key_raw(&self, key: &str, pk: &[u8]) {
        Self::with_key(PK_PREFIX, key, |k| {
            if let Err(e) = self.db.put_opt(k, pk, &self.write_opts) {
                slog_error!("crypto", "falcon_store_pk_failed", error => e);
            }
        });
    }

    pub fn get_public_key_raw(&self, key: &str) -> Option<Vec<u8>> {
        Self::with_key(PK_PREFIX, key, |k| {
            match self.db.get_pinned_opt(k, &self.read_opts) {
                Ok(Some(v)) => Some(v.to_vec()),
                Ok(None) => None,
                Err(e) => {
                    slog_error!("crypto", "falcon_read_pk_failed", error => e);
                    None
                }
            }
        })
    }

    pub fn public_key_exists(&self, key: &str) -> bool {
        Self::with_key(PK_PREFIX, key, |k| {
            match self.db.get_pinned_opt(k, &self.read_opts) {
                Ok(v) => v.is_some(),
                Err(e) => {
                    slog_error!("crypto", "falcon_pk_exists_failed", error => e);
                    false
                }
            }
        })
    }

    // ─────────────────────────────────────────
    // CLEAR (🔥 أسرع نسخة ممكنة)
    // ─────────────────────────────────────────

    pub fn clear_signatures(&self) {
        let iter = self.db.prefix_iterator(SIG_PREFIX);
        for (k, _) in iter.flatten() {
            if !k.starts_with(SIG_PREFIX) { break; }
            if let Err(e) = self.db.delete(&*k) {
                slog_error!("crypto", "falcon_clear_sig_failed", error => e);
            }
        }
    }

    pub fn clear_public_keys(&self) {
        let iter = self.db.prefix_iterator(PK_PREFIX);
        for (k, _) in iter.flatten() {
            if !k.starts_with(PK_PREFIX) { break; }
            if let Err(e) = self.db.delete(&*k) {
                slog_error!("crypto", "falcon_clear_pk_failed", error => e);
            }
        }
    }
}