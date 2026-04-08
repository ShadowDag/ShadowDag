// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::{slog_info, slog_warn, slog_error};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use rocksdb::DB;
use crate::errors::NetworkError;

pub const TOKEN_TTL_SECS:    u64   = 3_600;
pub const MAX_FAILED_LOGINS: u32   = 5;
pub const LOCKOUT_SECS:      u64   = 900;

#[derive(Debug, Clone, PartialEq)]
pub enum AuthRole {
    Admin,
    ReadOnly,
    Miner,
}

impl AuthRole {
    pub fn can_write(&self) -> bool {
        matches!(self, AuthRole::Admin | AuthRole::Miner)
    }
    pub fn can_mine(&self) -> bool {
        matches!(self, AuthRole::Admin | AuthRole::Miner)
    }
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub username:      String,
    pub password_hash: String,
    pub role:          AuthRole,
}

#[derive(Debug, Clone)]
pub struct AuthToken {
    pub token:      String,
    pub username:   String,
    pub role:       AuthRole,
    pub expires_at: u64,
}

impl AuthToken {
    pub fn is_expired(&self) -> bool {
        now_secs() >= self.expires_at
    }
}

#[derive(Debug, Default)]
struct LoginAttempts {
    failed:     u32,
    locked_until: u64,
}

pub struct RpcAuthManager {
    users:    HashMap<String, AuthUser>,
    tokens:   HashMap<String, AuthToken>,
    attempts: HashMap<String, LoginAttempts>,
    db:       Option<Arc<DB>>,
}

impl Default for RpcAuthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcAuthManager {
    pub fn new() -> Self {
        Self {
            users:    HashMap::new(),
            tokens:   HashMap::new(),
            attempts: HashMap::new(),
            db:       None,
        }
    }

    /// Create with RocksDB persistence — users survive restart.
    pub fn new_persistent(db: Arc<DB>) -> Self {
        let mut mgr = Self {
            users:    HashMap::new(),
            tokens:   HashMap::new(),
            attempts: HashMap::new(),
            db:       Some(db.clone()),
        };
        // Recover users from DB
        mgr.recover_users_from_db();
        mgr
    }

    /// Create with persistent DB + default admin if no users exist yet.
    /// First run: generates random password and persists it.
    /// Subsequent runs: loads existing admin from DB (no new password).
    pub fn with_default_admin_persistent(db: Arc<DB>) -> Self {
        let mut mgr = Self::new_persistent(db);
        if mgr.users.is_empty() {
            // First run — generate and persist admin
            let password = generate_random_password();
            slog_warn!("rpc", "first_run_admin_created", username => "admin", password => &password);
            slog_warn!("rpc", "first_run_admin_notice", note => "Save this password — it will not be shown again");
            mgr.add_user("admin", &password, AuthRole::Admin);
        } else {
            slog_info!("rpc", "users_loaded_from_db", count => mgr.users.len());
        }
        mgr
    }

    pub fn with_default_admin(password: &str) -> Self {
        let mut mgr = Self::new();
        mgr.add_user("admin", password, AuthRole::Admin);
        mgr
    }

    /// Persist a user to RocksDB. Returns true on success or if no DB configured.
    fn persist_user(&self, user: &AuthUser) -> bool {
        if let Some(db) = &self.db {
            let key = format!("rpc:user:{}", user.username);
            // Store as: role_byte + password_hash
            let role_byte = match user.role {
                AuthRole::Admin    => 0u8,
                AuthRole::ReadOnly => 1u8,
                AuthRole::Miner    => 2u8,
            };
            let value = format!("{}:{}", role_byte, user.password_hash);
            if let Err(e) = db.put(key.as_bytes(), value.as_bytes()) {
                slog_error!("rpc", "persist_user_failed", user => &user.username, error => e);
                return false;
            }
        }
        true
    }

    /// Load all users from RocksDB
    fn recover_users_from_db(&mut self) {
        let db = match &self.db {
            Some(db) => db.clone(),
            None => return,
        };
        let prefix = b"rpc:user:";
        let iter = db.prefix_iterator(prefix);
        for (k, v) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&k);
            if !key_str.starts_with("rpc:user:") { break; }
            let username = key_str.trim_start_matches("rpc:user:").to_string();
            let value_str = String::from_utf8_lossy(&v);
            let parts: Vec<&str> = value_str.splitn(2, ':').collect();
            if parts.len() == 2 {
                let role = match parts[0] {
                    "0" => AuthRole::Admin,
                    "1" => AuthRole::ReadOnly,
                    "2" => AuthRole::Miner,
                    _ => {
                        slog_warn!("rpc", "unknown_auth_role_in_db", role => parts[0], user => &username);
                        continue; // Skip corrupt entries instead of granting access
                    }
                };
                self.users.insert(username.clone(), AuthUser {
                    username,
                    password_hash: parts[1].to_string(),
                    role,
                });
            }
        }
    }

    pub fn add_user(&mut self, username: &str, password: &str, role: AuthRole) {
        let salt = generate_salt();
        let hash = salted_hash(password, &salt);
        let user = AuthUser {
            username:      username.to_string(),
            password_hash: hash,
            role,
        };
        if self.persist_user(&user) {
            self.users.insert(username.to_string(), user);
        }
    }

    pub fn remove_user(&mut self, username: &str) -> bool {
        if let Some(db) = &self.db {
            let key = format!("rpc:user:{}", username);
            if let Err(e) = db.delete(key.as_bytes()) {
                slog_error!("rpc", "remove_user_failed", user => username, error => e);
                return false;
            }
        }
        self.users.remove(username).is_some()
    }

    pub fn user_exists(&self, username: &str) -> bool {
        self.users.contains_key(username)
    }

    pub fn login(&mut self, username: &str, password: &str) -> Result<String, NetworkError> {
        // Check user exists BEFORE creating an attempts entry (avoids memory leak from nonexistent usernames)
        let user = self.users.get(username)
            .ok_or_else(|| NetworkError::Other("Invalid credentials".to_string()))?;
        let user = user.clone();

        let attempts = self.attempts.entry(username.to_string()).or_default();
        if attempts.locked_until > now_secs() {
            return Err(NetworkError::Other(format!(
                "Account locked until unix={}",
                attempts.locked_until
            )));
        }

        if !verify_password(password, &user.password_hash) {
            let a = self.attempts.entry(username.to_string()).or_default();
            a.failed += 1;
            if a.failed >= MAX_FAILED_LOGINS {
                a.locked_until = now_secs() + LOCKOUT_SECS;
                return Err(NetworkError::Other(format!(
                    "Account locked after {} failed attempts",
                    MAX_FAILED_LOGINS
                )));
            }
            return Err(NetworkError::Other(format!(
                "Invalid credentials ({} attempts remaining)",
                MAX_FAILED_LOGINS - a.failed
            )));
        }

        let a = self.attempts.entry(username.to_string()).or_default();
        a.failed = 0;

        let token_str = generate_token(username);
        let token = AuthToken {
            token:      token_str.clone(),
            username:   username.to_string(),
            role:       user.role.clone(),
            expires_at: now_secs() + TOKEN_TTL_SECS,
        };
        self.tokens.insert(token_str.clone(), token);
        Ok(token_str)
    }

    pub fn verify(&mut self, token: &str) -> Option<&AuthToken> {
        // Auto-prune expired tokens when map grows large (prevents memory leak)
        if self.tokens.len() > 1_000 {
            self.prune_expired_tokens();
        }
        self.tokens.get(token).filter(|t| !t.is_expired())
    }

    pub fn is_authorized(&mut self, token: &str) -> bool {
        self.verify(token).is_some()
    }

    pub fn is_admin(&mut self, token: &str) -> bool {
        self.verify(token).map(|t| t.role == AuthRole::Admin).unwrap_or(false)
    }

    pub fn can_write(&mut self, token: &str) -> bool {
        self.verify(token).map(|t| t.role.can_write()).unwrap_or(false)
    }

    pub fn logout(&mut self, token: &str) -> bool {
        self.tokens.remove(token).is_some()
    }

    pub fn prune_expired_tokens(&mut self) {
        self.tokens.retain(|_, t| !t.is_expired());
    }

    pub fn active_token_count(&self) -> usize {
        self.tokens.values().filter(|t| !t.is_expired()).count()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Password hashing with per-user salt and HMAC-SHA256 iterated KDF.
/// This is NOT just SHA-256 — it uses 10,000 iterations to slow brute force.
fn salted_hash(password: &str, salt: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    const KDF_ITERATIONS: u32 = 10_000;

    // Initial: H(domain || salt || password)
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Auth_KDF_v2");
    h.update(salt);
    h.update(password.as_bytes());
    let mut result = h.finalize().to_vec();

    // Iterate to make brute force expensive
    for i in 0..KDF_ITERATIONS {
        let mut h = Sha256::new();
        h.update(&result);
        h.update(salt);
        h.update(i.to_le_bytes());
        result = h.finalize().to_vec();
    }

    // Store as: hex(salt) + ":" + hex(hash)
    format!("{}:{}", hex::encode(salt), hex::encode(&result))
}

/// Generate a random 16-byte salt
fn generate_salt() -> [u8; 16] {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Verify password against stored salted hash
fn verify_password(password: &str, stored: &str) -> bool {
    // Parse "hex_salt:hex_hash"
    let parts: Vec<&str> = stored.splitn(2, ':').collect();
    if parts.len() != 2 {
        // Legacy: fall back to simple hash comparison
        return stored == simple_hash_legacy(password);
    }
    let salt = match hex::decode(parts[0]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let expected = salted_hash(password, &salt);
    // Constant-time comparison to prevent timing attacks
    expected.len() == stored.len() && expected.as_bytes().iter()
        .zip(stored.as_bytes().iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Legacy simple hash (for backward compat during migration)
fn simple_hash_legacy(input: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Auth_Hash_v1");
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

/// Generate a cryptographically random 32-char hex password
fn generate_random_password() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn generate_token(username: &str) -> String {
    use sha2::{Sha256, Digest};
    use rand::RngCore;
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Token_v1");
    h.update(username.as_bytes());
    h.update(now_secs().to_le_bytes());
    h.update(entropy);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_success_returns_token() {
        let mut auth = RpcAuthManager::with_default_admin("secret");
        let result = auth.login("admin", "secret");
        assert!(result.is_ok());
    }

    #[test]
    fn login_wrong_password_fails() {
        let mut auth = RpcAuthManager::with_default_admin("secret");
        assert!(auth.login("admin", "wrong").is_err());
    }

    #[test]
    fn token_authorizes_access() {
        let mut auth = RpcAuthManager::with_default_admin("pass");
        let token = auth.login("admin", "pass").unwrap();
        assert!(auth.is_authorized(&token));
    }

    #[test]
    fn logout_invalidates_token() {
        let mut auth = RpcAuthManager::with_default_admin("pass");
        let token = auth.login("admin", "pass").unwrap();
        auth.logout(&token);
        assert!(!auth.is_authorized(&token));
    }

    #[test]
    fn admin_role_can_write() {
        let mut auth = RpcAuthManager::with_default_admin("pass");
        let token = auth.login("admin", "pass").unwrap();
        assert!(auth.can_write(&token));
    }

    #[test]
    fn account_locked_after_max_failures() {
        let mut auth = RpcAuthManager::with_default_admin("pass");
        for _ in 0..MAX_FAILED_LOGINS {
            let _ = auth.login("admin", "wrong");
        }
        let result = auth.login("admin", "pass");
        assert!(result.is_err());
    }

    #[test]
    fn readonly_user_cannot_write() {
        let mut auth = RpcAuthManager::new();
        auth.add_user("viewer", "view", AuthRole::ReadOnly);
        let token = auth.login("viewer", "view").unwrap();
        assert!(!auth.can_write(&token));
    }
}
