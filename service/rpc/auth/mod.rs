// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::NetworkError;
use crate::{slog_error, slog_info, slog_warn};
use rocksdb::DB;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TOKEN_TTL_SECS: u64 = 3_600;
pub const MAX_FAILED_LOGINS: u32 = 5;
pub const LOCKOUT_SECS: u64 = 900;
pub const MAX_ACTIVE_TOKENS: usize = 10_000;
pub const MAX_ACTIVE_TOKENS_PER_USER: usize = 16;
const PBKDF2_ITERATIONS: u32 = 210_000;
const PBKDF2_PREFIX: &str = "pbkdf2-sha256";

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
    pub username: String,
    pub password_hash: String,
    pub role: AuthRole,
}

#[derive(Debug, Clone)]
pub struct AuthToken {
    pub token: String,
    pub username: String,
    pub role: AuthRole,
    pub expires_at: u64,
}

impl AuthToken {
    pub fn is_expired(&self) -> bool {
        now_secs() >= self.expires_at
    }
}

#[derive(Debug, Default)]
struct LoginAttempts {
    failed: u32,
    locked_until: u64,
}

pub struct RpcAuthManager {
    users: HashMap<String, AuthUser>,
    tokens: HashMap<String, AuthToken>,
    attempts: HashMap<String, LoginAttempts>,
    db: Option<Arc<DB>>,
}

impl Default for RpcAuthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcAuthManager {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            tokens: HashMap::new(),
            attempts: HashMap::new(),
            db: None,
        }
    }

    /// Create with RocksDB persistence — users survive restart.
    pub fn new_persistent(db: Arc<DB>) -> Self {
        let mut mgr = Self {
            users: HashMap::new(),
            tokens: HashMap::new(),
            attempts: HashMap::new(),
            db: Some(db.clone()),
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
            slog_warn!("rpc", "first_run_admin_created", username => "admin");
            slog_warn!("rpc", "first_run_admin_notice", note => "Default admin password was generated — retrieve it from the secure config or reset it");
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
                AuthRole::Admin => 0u8,
                AuthRole::ReadOnly => 1u8,
                AuthRole::Miner => 2u8,
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
        for item in iter {
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    slog_error!("rpc", "db_iterator_error", error => e);
                    continue;
                }
            };
            let key_str = String::from_utf8_lossy(&k);
            if !key_str.starts_with("rpc:user:") {
                break;
            }
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
                self.users.insert(
                    username.clone(),
                    AuthUser {
                        username,
                        password_hash: parts[1].to_string(),
                        role,
                    },
                );
            }
        }
    }

    pub fn add_user(&mut self, username: &str, password: &str, role: AuthRole) {
        let salt = generate_salt();
        let hash = salted_hash(password, &salt);
        // Role/password rotation for an existing user must invalidate all
        // previously-issued tokens to avoid stale-privilege sessions.
        self.revoke_user_tokens(username);
        let user = AuthUser {
            username: username.to_string(),
            password_hash: hash,
            role,
        };
        if self.persist_user(&user) {
            self.users.insert(username.to_string(), user);
        }
    }

    pub fn remove_user(&mut self, username: &str) -> bool {
        self.revoke_user_tokens(username);
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
        // Resolve user once without creating attempts entries for unknown names.
        // Unknown-username path still performs one password verification with a
        // decoy hash to reduce username-enumeration timing side channels.
        let user = match self.users.get(username).cloned() {
            Some(u) => u,
            None => {
                let decoy_hash = self
                    .users
                    .values()
                    .next()
                    .map(|u| u.password_hash.as_str())
                    .unwrap_or(
                        "pbkdf2-sha256$210000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000",
                    );
                let _ = verify_password(password, decoy_hash);
                return Err(NetworkError::Other("Invalid credentials".to_string()));
            }
        };

        let attempts = self.attempts.entry(username.to_string()).or_default();
        if attempts.locked_until > now_secs() {
            // Don't reveal lockout timing — use generic message
            return Err(NetworkError::Other("Invalid credentials".to_string()));
        }

        if !verify_password(password, &user.password_hash) {
            let a = self.attempts.entry(username.to_string()).or_default();
            a.failed += 1;
            if a.failed >= MAX_FAILED_LOGINS {
                a.locked_until = now_secs() + LOCKOUT_SECS;
                return Err(NetworkError::Other("Invalid credentials".to_string()));
            }
            return Err(NetworkError::Other("Invalid credentials".to_string()));
        }

        let a = self.attempts.entry(username.to_string()).or_default();
        a.failed = 0;

        // Opportunistic hash migration:
        // if a legacy hash verifies, immediately upgrade it to PBKDF2.
        let mut upgraded_user: Option<AuthUser> = None;
        if hash_needs_upgrade(&user.password_hash) {
            let salt = generate_salt();
            let new_hash = hash_password_pbkdf2(password, &salt, PBKDF2_ITERATIONS);
            if let Some(entry) = self.users.get_mut(username) {
                entry.password_hash = new_hash;
                upgraded_user = Some(entry.clone());
            }
        }
        if let Some(u) = upgraded_user.as_ref() {
            let _ = self.persist_user(u);
        }

        // Keep token table bounded to avoid memory DoS from repeated logins.
        self.prune_expired_tokens();
        if self.tokens.len() >= MAX_ACTIVE_TOKENS {
            return Err(NetworkError::Other(
                "Too many active sessions; retry later".to_string(),
            ));
        }
        let user_active_tokens = self
            .tokens
            .values()
            .filter(|t| t.username == username && !t.is_expired())
            .count();
        if user_active_tokens >= MAX_ACTIVE_TOKENS_PER_USER {
            return Err(NetworkError::Other(
                "Too many active sessions for this user".to_string(),
            ));
        }

        let token_str = generate_token(username);
        let token = AuthToken {
            token: token_str.clone(),
            username: username.to_string(),
            role: user.role.clone(),
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
        let invalid = match self.tokens.get(token) {
            Some(t) => {
                t.is_expired()
                    // Token must still map to an existing user with the same role.
                    || !self
                        .users
                        .get(&t.username)
                        .is_some_and(|u| u.role == t.role)
            }
            None => return None,
        };
        if invalid {
            let _ = self.tokens.remove(token);
            return None;
        }
        self.tokens.get(token)
    }

    pub fn is_authorized(&mut self, token: &str) -> bool {
        self.verify(token).is_some()
    }

    pub fn is_admin(&mut self, token: &str) -> bool {
        self.verify(token)
            .map(|t| t.role == AuthRole::Admin)
            .unwrap_or(false)
    }

    pub fn can_write(&mut self, token: &str) -> bool {
        self.verify(token)
            .map(|t| t.role.can_write())
            .unwrap_or(false)
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

    fn revoke_user_tokens(&mut self, username: &str) {
        self.tokens.retain(|_, t| t.username != username);
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Password hashing with per-user salt and HMAC-SHA256 iterated KDF.
/// Stored format: pbkdf2-sha256$<iterations>$<hex_salt>$<hex_hash>
fn salted_hash(password: &str, salt: &[u8]) -> String {
    hash_password_pbkdf2(password, salt, PBKDF2_ITERATIONS)
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
    // New format: pbkdf2-sha256$iter$salt_hex$hash_hex
    if let Some(rest) = stored.strip_prefix(&(PBKDF2_PREFIX.to_string() + "$")) {
        let parts: Vec<&str> = rest.split('$').collect();
        if parts.len() != 3 {
            return false;
        }
        let iterations = match parts[0].parse::<u32>() {
            Ok(i) if i > 0 => i,
            _ => return false,
        };
        let salt = match hex::decode(parts[1]) {
            Ok(s) if !s.is_empty() => s,
            _ => return false,
        };
        let expected = hash_password_pbkdf2(password, &salt, iterations);
        return const_time_eq(expected.as_bytes(), stored.as_bytes());
    }

    // Parse "hex_salt:hex_hash"
    let parts: Vec<&str> = stored.splitn(2, ':').collect();
    if parts.len() != 2 {
        // SECURITY: Legacy password hash support has been removed.
        // Old SHA256-only hashes (no salt) are rejected outright.
        // If you see this in production, re-generate the RPC password
        // with: shadowdag-rotate-rpc-password
        return false;
    }
    let salt = match hex::decode(parts[0]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Compatibility with older "salt:hash" format.
    let expected = hash_password_v2_compat(password, &salt);
    // Constant-time comparison to prevent timing attacks
    const_time_eq(expected.as_bytes(), stored.as_bytes())
}

// simple_hash_legacy removed — legacy password support is no longer accepted.
// Re-generate passwords with: shadowdag-rotate-rpc-password

/// Generate a cryptographically random 32-char hex password
fn generate_random_password() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn generate_token(username: &str) -> String {
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Token_v1");
    h.update(username.as_bytes());
    h.update(now_secs().to_le_bytes());
    h.update(entropy);
    hex::encode(h.finalize())
}

fn const_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn hash_password_pbkdf2(password: &str, salt: &[u8], iterations: u32) -> String {
    use pbkdf2::pbkdf2_hmac_array;
    use sha2::Sha256;

    let hash: [u8; 32] = pbkdf2_hmac_array::<Sha256, 32>(
        password.as_bytes(),
        salt,
        iterations,
    );
    format!(
        "{}${}${}${}",
        PBKDF2_PREFIX,
        iterations,
        hex::encode(salt),
        hex::encode(hash)
    )
}

fn hash_password_v2_compat(password: &str, salt: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const KDF_ITERATIONS: u32 = 10_000;

    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Auth_KDF_v2");
    h.update(salt);
    h.update(password.as_bytes());
    let mut result = h.finalize().to_vec();

    for i in 0..KDF_ITERATIONS {
        let mut h = Sha256::new();
        h.update(&result);
        h.update(salt);
        h.update(i.to_le_bytes());
        result = h.finalize().to_vec();
    }

    format!("{}:{}", hex::encode(salt), hex::encode(&result))
}

fn hash_needs_upgrade(stored: &str) -> bool {
    !stored.starts_with(&(PBKDF2_PREFIX.to_string() + "$"))
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

    #[test]
    fn pbkdf2_hash_roundtrip_verifies() {
        let salt = generate_salt();
        let stored = salted_hash("s3cret", &salt);
        assert!(verify_password("s3cret", &stored));
        assert!(!verify_password("wrong", &stored));
    }

    #[test]
    fn legacy_v2_hash_migrates_after_successful_login() {
        let mut auth = RpcAuthManager::new();
        let salt = generate_salt();
        let legacy = hash_password_v2_compat("pass123", &salt);
        auth.users.insert(
            "admin".to_string(),
            AuthUser {
                username: "admin".to_string(),
                password_hash: legacy,
                role: AuthRole::Admin,
            },
        );

        let token = auth.login("admin", "pass123").expect("login should succeed");
        assert!(!token.is_empty());
        let upgraded = &auth.users.get("admin").unwrap().password_hash;
        assert!(upgraded.starts_with("pbkdf2-sha256$"));
    }

    #[test]
    fn unknown_user_does_not_create_attempt_record() {
        let mut auth = RpcAuthManager::with_default_admin("secret");
        let before = auth.attempts.len();
        let _ = auth.login("not_a_real_user", "whatever");
        assert_eq!(auth.attempts.len(), before);
    }

    #[test]
    fn remove_user_revokes_existing_tokens() {
        let mut auth = RpcAuthManager::new();
        auth.add_user("alice", "pw", AuthRole::Admin);
        let token = auth.login("alice", "pw").expect("login must succeed");
        assert!(auth.is_authorized(&token));
        assert!(auth.remove_user("alice"));
        assert!(!auth.is_authorized(&token));
    }

    #[test]
    fn role_change_revokes_existing_tokens() {
        let mut auth = RpcAuthManager::new();
        auth.add_user("bob", "pw", AuthRole::ReadOnly);
        let token = auth.login("bob", "pw").expect("login must succeed");
        assert!(!auth.can_write(&token));

        // Rotate role to admin; old token must be revoked.
        auth.add_user("bob", "pw", AuthRole::Admin);
        assert!(!auth.is_authorized(&token));
    }
}
