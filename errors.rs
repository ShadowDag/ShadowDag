// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Structured error types for ShadowDAG.
//
// Every module returns typed errors instead of `Result<T, String>`.
// Each error enum implements `Display` via thiserror.
// ═══════════════════════════════════════════════════════════════════════════

use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────
//  Storage
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("[Storage] RocksDB error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    #[error("[Storage] serialization error: {0}")]
    Serialization(String),

    #[error("[Storage] column family '{0}' not found")]
    ColumnFamilyNotFound(String),

    #[error("[Storage] key not found: {0}")]
    KeyNotFound(String),

    #[error("[Storage] DB open failed at '{path}': {reason}")]
    OpenFailed { path: String, reason: String },

    #[error("[Storage] migration failed: {0}")]
    Migration(String),

    #[error("[Storage] lock poisoned: {0}")]
    LockPoisoned(String),

    #[error("[Storage] write failed: {0}")]
    WriteFailed(String),

    #[error("[Storage] read failed: {0}")]
    ReadFailed(String),

    #[error("[Storage] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  DAG
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DagError {
    #[error("[DAG] storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("[DAG] block '{0}' not found")]
    BlockNotFound(String),

    #[error("[DAG] duplicate block '{0}'")]
    DuplicateBlock(String),

    #[error("[DAG] orphan block '{0}': missing parent '{1}'")]
    OrphanBlock(String, String),

    #[error("[DAG] invalid parent reference: {0}")]
    InvalidParent(String),

    #[error("[DAG] too many parents: {0} (max {1})")]
    TooManyParents(usize, usize),

    #[error("[DAG] self-referencing parent in block '{0}'")]
    SelfParent(String),

    #[error("[DAG] duplicate parents in block '{0}'")]
    DuplicateParents(String),

    #[error("[DAG] tip manager error: {0}")]
    TipManager(String),

    #[error("[DAG] serialization error: {0}")]
    Serialization(String),

    #[error("[DAG] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  Consensus
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("[Consensus] storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("[Consensus] DAG error: {0}")]
    Dag(#[from] DagError),

    #[error("[Consensus] block validation failed: {0}")]
    BlockValidation(String),

    #[error("[Consensus] invalid difficulty: {0}")]
    Difficulty(String),

    #[error("[Consensus] invalid timestamp: {0}")]
    Timestamp(String),

    #[error("[Consensus] invalid PoW: {0}")]
    InvalidPow(String),

    #[error("[Consensus] reorg rejected: {0}")]
    ReorgRejected(String),

    #[error("[Consensus] genesis error: {0}")]
    Genesis(String),

    #[error("[Consensus] invalid transaction at index {index}: {reason}")]
    InvalidTransaction { index: usize, reason: String },

    #[error("[Consensus] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  Network
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("[Network] connection failed: {0}")]
    ConnectionFailed(String),

    #[error("[Network] invalid message: {0}")]
    InvalidMessage(String),

    #[error("[Network] peer '{0}' banned")]
    PeerBanned(String),

    #[error("[Network] message serialization: {0}")]
    Serialization(String),

    #[error("[Network] rate limited: {0}")]
    RateLimited(String),

    #[error("[Network] DoS guard: {0}")]
    DosGuard(String),

    #[error("[Network] peer not found: {0}")]
    PeerNotFound(String),

    #[error("[Network] storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("[Network] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  VM
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum VmError {
    #[error("[VM] out of gas: used {used}, limit {limit}")]
    OutOfGas { used: u64, limit: u64 },

    #[error("[VM] stack overflow: depth {0}")]
    StackOverflow(usize),

    #[error("[VM] stack underflow: need {need}, have {have}")]
    StackUnderflow { need: usize, have: usize },

    #[error("[VM] invalid opcode: 0x{0:02x}")]
    InvalidOpcode(u8),

    #[error("[VM] memory access out of bounds: offset {0}")]
    MemoryOutOfBounds(usize),

    #[error("[VM] division by zero")]
    DivisionByZero,

    #[error("[VM] contract error: {0}")]
    ContractError(String),

    #[error("[VM] storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("[VM] code size exceeds limit: {size} > {limit}")]
    CodeTooLarge { size: usize, limit: usize },

    #[error("[VM] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  Mempool
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("[Mempool] pool full ({0}/{1})")]
    PoolFull(usize, usize),

    #[error("[Mempool] duplicate transaction '{0}'")]
    DuplicateTx(String),

    #[error("[Mempool] RBF rejected: {0}")]
    RbfRejected(String),

    #[error("[Mempool] validation failed: {0}")]
    ValidationFailed(String),

    #[error("[Mempool] conflicting input: {0}")]
    ConflictingInput(String),

    #[error("[Mempool] fee too low: {fee} < {minimum}")]
    FeeTooLow { fee: u64, minimum: u64 },

    #[error("[Mempool] transaction too large: {0} bytes")]
    TxTooLarge(usize),

    #[error("[Mempool] storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("[Mempool] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  Wallet
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("[Wallet] locked")]
    Locked,

    #[error("[Wallet] authentication failed")]
    AuthFailed,

    #[error("[Wallet] key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("[Wallet] insufficient funds: need {need}, have {have}")]
    InsufficientFunds { need: u64, have: u64 },

    #[error("[Wallet] address not found: {0}")]
    AddressNotFound(String),

    #[error("[Wallet] encryption error: {0}")]
    Encryption(String),

    #[error("[Wallet] balance overflow")]
    BalanceOverflow,

    #[error("[Wallet] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  Crypto
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("[Crypto] invalid key: {0}")]
    InvalidKey(String),

    #[error("[Crypto] signature verification failed")]
    SignatureVerification,

    #[error("[Crypto] encoding error: {0}")]
    Encoding(String),

    #[error("[Crypto] hash error: {0}")]
    Hash(String),

    #[error("[Crypto] invalid ring index {index} for ring of size {ring_size}")]
    InvalidRingIndex { index: usize, ring_size: usize },

    #[error("[Crypto] non-canonical scalar (>= group order L)")]
    NonCanonicalScalar,

    #[error("[Crypto] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  Node (top-level)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum NodeError {
    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Dag(#[from] DagError),

    #[error(transparent)]
    Consensus(#[from] ConsensusError),

    #[error(transparent)]
    Network(#[from] NetworkError),

    #[error(transparent)]
    Vm(#[from] VmError),

    #[error(transparent)]
    Mempool(#[from] MempoolError),

    #[error(transparent)]
    Wallet(#[from] WalletError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error("[Node] initialization failed: {0}")]
    Init(String),

    #[error("[Node] block rejected: {0}")]
    BlockRejected(String),

    #[error("[Node] peer banned: {peer} — {reason}")]
    PeerBanned { peer: String, reason: String },

    #[error("[Node] recovery failed: {0}")]
    Recovery(String),

    #[error("[Node] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  DEX (Decentralized Exchange)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DexError {
    #[error("[DEX] order not found: {0}")]
    OrderNotFound(String),

    #[error("[DEX] insufficient balance for order: need {need}, have {have}")]
    InsufficientBalance { need: u64, have: u64 },

    #[error("[DEX] invalid price: {0}")]
    InvalidPrice(u64),

    #[error("[DEX] invalid amount: {0}")]
    InvalidAmount(u64),

    #[error("[DEX] trading pair not found: {0}")]
    PairNotFound(String),

    #[error("[DEX] order book full: {0} orders")]
    OrderBookFull(usize),

    #[error("[DEX] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  Atomic Swap
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SwapError {
    #[error("[Swap] HTLC not found: {0}")]
    HtlcNotFound(String),

    #[error("[Swap] invalid secret: hash mismatch")]
    InvalidSecret,

    #[error("[Swap] HTLC expired at height {0}")]
    Expired(u64),

    #[error("[Swap] HTLC already redeemed")]
    AlreadyRedeemed,

    #[error("[Swap] HTLC already refunded")]
    AlreadyRefunded,

    #[error("[Swap] timeout too short: {0} < minimum {1}")]
    TimeoutTooShort(u64, u64),

    #[error("[Swap] {0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────────────────────────
//  Privacy
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PrivacyError {
    #[error("[Privacy] key image already spent: {0}")]
    DoubleSpend(String),

    #[error("[Privacy] invalid ring size: {0} (min {1}, max {2})")]
    InvalidRingSize(usize, usize, usize),

    #[error("[Privacy] commitment verification failed")]
    CommitmentVerification,

    #[error("[Privacy] range proof verification failed")]
    RangeProofVerification,

    #[error("[Privacy] decoy selection failed: {0}")]
    DecoySelection(String),

    #[error("[Privacy] {0}")]
    Other(String),
}

