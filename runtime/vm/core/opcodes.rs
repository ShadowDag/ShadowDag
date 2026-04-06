// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// ShadowVM Opcodes — Complete instruction set definition.
//
// 90+ opcodes organized by category. Each opcode is 1 byte.
// Gas costs are calibrated for fair resource pricing.
//
// Categories:
//   0x00-0x0F : Control flow
//   0x10-0x1F : Stack operations (PUSH, POP, DUP, SWAP)
//   0x20-0x2F : Arithmetic
//   0x30-0x3F : Comparison & bitwise
//   0x40-0x4F : Bitwise operations
//   0x50-0x5F : Storage
//   0x60-0x6F : Cryptographic
//   0x70-0x7F : Context (block, tx, caller)
//   0x80-0x8F : Flow control (JUMP)
//   0x90-0x9F : Memory
//   0xA0-0xAF : Logging
//   0xB0-0xBF : System (CALL, CREATE, RETURN)
//   0xC0-0xCF : Call data
//   0xD0-0xDF : Extended stack (DUP2-16, SWAP2-16)
//   0xE0-0xEF : Extended ops
//   0xFF      : INVALID
// ═══════════════════════════════════════════════════════════════════════════

/// Complete ShadowVM opcode set (90+ instructions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpCode {
    // ═══ 0x00: CONTROL ═══════════════════════════════════════════════════
    STOP         = 0x00,
    NOP          = 0x01,
    PC           = 0x02,  // Push program counter
    GAS          = 0x03,  // Push remaining gas
    GASLIMIT     = 0x04,  // Push gas limit
    JUMPDEST     = 0x05,  // Mark valid jump destination

    // ═══ 0x10: STACK (PUSH/POP) ═════════════════════════════════════════
    PUSH1        = 0x10,
    PUSH2        = 0x11,
    PUSH4        = 0x12,
    PUSH8        = 0x13,
    PUSH16       = 0x14,
    PUSH32       = 0x15,
    POP          = 0x16,
    DUP1         = 0x17,
    SWAP1        = 0x18,

    // ═══ 0x20: ARITHMETIC ════════════════════════════════════════════════
    ADD          = 0x20,
    SUB          = 0x21,
    MUL          = 0x22,
    DIV          = 0x23,
    SDIV         = 0x24,  // Signed division
    MOD          = 0x25,
    SMOD         = 0x26,  // Signed modulo
    ADDMOD       = 0x27,  // (a + b) % N
    MULMOD       = 0x28,  // (a * b) % N
    EXP          = 0x29,
    SIGNEXTEND   = 0x2A,
    MIN          = 0x2B,  // min(a, b)
    MAX          = 0x2C,  // max(a, b)

    // ═══ 0x30: COMPARISON ═══════════════════════════════════════════════
    LT           = 0x30,
    GT           = 0x31,
    SLT          = 0x32,  // Signed less-than
    SGT          = 0x33,  // Signed greater-than
    EQ           = 0x34,
    ISZERO       = 0x35,
    NEQ          = 0x36,  // a != b (ShadowVM extension)

    // ═══ 0x40: BITWISE ══════════════════════════════════════════════════
    AND          = 0x40,
    OR           = 0x41,
    XOR          = 0x42,
    NOT          = 0x43,
    BYTE         = 0x44,  // Extract byte from value
    SHL          = 0x45,
    SHR          = 0x46,
    SAR          = 0x47,  // Arithmetic (signed) shift right
    ROL          = 0x48,  // Rotate left (ShadowVM extension)
    ROR          = 0x49,  // Rotate right (ShadowVM extension)

    // ═══ 0x50: STORAGE ══════════════════════════════════════════════════
    SLOAD        = 0x50,
    SSTORE       = 0x51,
    SDELETE      = 0x52,
    SSIZE        = 0x53,  // Number of storage slots used

    // ═══ 0x60: CRYPTO ═══════════════════════════════════════════════════
    SHA256       = 0x60,
    KECCAK256    = 0x61,
    SHA3         = 0x62,  // SHA3-256
    BLAKE3       = 0x63,  // Blake3 hash (ShadowVM extension)
    ECRECOVER    = 0x64,  // Recover signer from signature
    VERIFY       = 0x65,  // Verify Ed25519 signature

    // ═══ 0x70: CONTEXT ══════════════════════════════════════════════════
    CALLER       = 0x70,
    CALLVALUE    = 0x71,
    ORIGIN       = 0x72,  // Original transaction sender
    TIMESTAMP    = 0x73,
    BLOCKHASH    = 0x74,
    BLOCKHEIGHT  = 0x75,
    DIFFICULTY   = 0x76,
    CHAINID      = 0x77,
    SELFBALANCE  = 0x78,
    BASEFEE      = 0x79,
    ADDRESS      = 0x7A,  // Current contract address
    BALANCE      = 0x7B,  // Balance of address on stack
    GASPRICE     = 0x7C,

    // ═══ 0x80: FLOW CONTROL ═════════════════════════════════════════════
    JUMP         = 0x80,
    JUMPI        = 0x81,
    JUMPF        = 0x82,  // Jump if false (zero) — ShadowVM extension

    // ═══ 0x90: MEMORY ═══════════════════════════════════════════════════
    MLOAD        = 0x90,
    MSTORE       = 0x91,
    MSTORE8      = 0x92,  // Store single byte
    MSIZE        = 0x93,  // Memory size in bytes
    MCOPY        = 0x94,  // Memory-to-memory copy
    MZERO        = 0x95,  // Zero out memory range

    // ═══ 0xA0: LOGGING ══════════════════════════════════════════════════
    LOG0         = 0xA0,  // Log with 0 topics
    LOG1         = 0xA1,  // Log with 1 topic
    LOG2         = 0xA2,  // Log with 2 topics
    LOG3         = 0xA3,  // Log with 3 topics
    LOG4         = 0xA4,  // Log with 4 topics

    // ═══ 0xB0: SYSTEM ═══════════════════════════════════════════════════
    CALL         = 0xB0,
    CALLCODE     = 0xB1,
    DELEGATECALL = 0xB2,
    STATICCALL   = 0xB3,  // Read-only call (no state changes)
    CREATE       = 0xB4,
    CREATE2      = 0xB5,  // Deterministic CREATE
    RETURN       = 0xB6,
    REVERT       = 0xB7,
    SELFDESTRUCT = 0xB8,

    // ═══ 0xC0: CALL DATA ════════════════════════════════════════════════
    CALLDATALOAD = 0xC0,  // Load 8 bytes from call data
    CALLDATASIZE = 0xC1,  // Push call data size
    CALLDATACOPY = 0xC2,  // Copy call data to memory
    CODESIZE     = 0xC3,  // Push code size
    CODECOPY     = 0xC4,  // Copy code to memory
    EXTCODESIZE  = 0xC5,  // External contract code size
    RETURNDATASIZE = 0xC6, // Size of last return data
    RETURNDATACOPY = 0xC7, // Copy return data to memory

    // ═══ 0xD0: EXTENDED STACK ═══════════════════════════════════════════
    DUP2         = 0xD0,
    DUP3         = 0xD1,
    DUP4         = 0xD2,
    DUP5         = 0xD3,
    DUP6         = 0xD4,
    DUP7         = 0xD5,
    DUP8         = 0xD6,
    DUP16        = 0xD7,
    SWAP2        = 0xD8,
    SWAP3        = 0xD9,
    SWAP4        = 0xDA,
    SWAP8        = 0xDB,
    SWAP16       = 0xDC,

    // ═══ 0xE0: SHADOWVM EXTENSIONS (unique to ShadowDAG) ════════════════
    /// Privacy: check if a stealth address belongs to caller
    STEALTHCHECK = 0xE0,
    /// Privacy: generate a ring signature proof
    RINGPROOF    = 0xE1,
    /// Privacy: verify a confidential transaction amount
    CTVERIFY     = 0xE2,
    /// DAG: get current tip count
    DAGTIPS      = 0xE3,
    /// DAG: get current BPS rate
    DAGBPS       = 0xE4,
    /// Cross-shard: atomic swap
    ATOMICSWAP   = 0xE5,
    /// Debug: emit debug log (stripped in production)
    DEBUG        = 0xEF,

    // ═══ 0xFF: INVALID ══════════════════════════════════════════════════
    INVALID      = 0xFF,
}

impl OpCode {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::STOP,    0x01 => Self::NOP,     0x02 => Self::PC,
            0x03 => Self::GAS,     0x04 => Self::GASLIMIT,0x05 => Self::JUMPDEST,
            0x10 => Self::PUSH1,   0x11 => Self::PUSH2,   0x12 => Self::PUSH4,
            0x13 => Self::PUSH8,   0x14 => Self::PUSH16,  0x15 => Self::PUSH32,
            0x16 => Self::POP,     0x17 => Self::DUP1,    0x18 => Self::SWAP1,
            0x20 => Self::ADD,     0x21 => Self::SUB,     0x22 => Self::MUL,
            0x23 => Self::DIV,     0x24 => Self::SDIV,    0x25 => Self::MOD,
            0x26 => Self::SMOD,    0x27 => Self::ADDMOD,  0x28 => Self::MULMOD,
            0x29 => Self::EXP,     0x2A => Self::SIGNEXTEND, 0x2B => Self::MIN,
            0x2C => Self::MAX,
            0x30 => Self::LT,      0x31 => Self::GT,      0x32 => Self::SLT,
            0x33 => Self::SGT,     0x34 => Self::EQ,      0x35 => Self::ISZERO,
            0x36 => Self::NEQ,
            0x40 => Self::AND,     0x41 => Self::OR,      0x42 => Self::XOR,
            0x43 => Self::NOT,     0x44 => Self::BYTE,    0x45 => Self::SHL,
            0x46 => Self::SHR,     0x47 => Self::SAR,     0x48 => Self::ROL,
            0x49 => Self::ROR,
            0x50 => Self::SLOAD,   0x51 => Self::SSTORE,  0x52 => Self::SDELETE,
            0x53 => Self::SSIZE,
            0x60 => Self::SHA256,  0x61 => Self::KECCAK256, 0x62 => Self::SHA3,
            0x63 => Self::BLAKE3,  0x64 => Self::ECRECOVER, 0x65 => Self::VERIFY,
            0x70 => Self::CALLER,  0x71 => Self::CALLVALUE, 0x72 => Self::ORIGIN,
            0x73 => Self::TIMESTAMP, 0x74 => Self::BLOCKHASH, 0x75 => Self::BLOCKHEIGHT,
            0x76 => Self::DIFFICULTY, 0x77 => Self::CHAINID, 0x78 => Self::SELFBALANCE,
            0x79 => Self::BASEFEE, 0x7A => Self::ADDRESS,  0x7B => Self::BALANCE,
            0x7C => Self::GASPRICE,
            0x80 => Self::JUMP,    0x81 => Self::JUMPI,    0x82 => Self::JUMPF,
            0x90 => Self::MLOAD,   0x91 => Self::MSTORE,   0x92 => Self::MSTORE8,
            0x93 => Self::MSIZE,   0x94 => Self::MCOPY,    0x95 => Self::MZERO,
            0xA0 => Self::LOG0,    0xA1 => Self::LOG1,     0xA2 => Self::LOG2,
            0xA3 => Self::LOG3,    0xA4 => Self::LOG4,
            0xB0 => Self::CALL,    0xB1 => Self::CALLCODE, 0xB2 => Self::DELEGATECALL,
            0xB3 => Self::STATICCALL, 0xB4 => Self::CREATE, 0xB5 => Self::CREATE2,
            0xB6 => Self::RETURN,  0xB7 => Self::REVERT,   0xB8 => Self::SELFDESTRUCT,
            0xC0 => Self::CALLDATALOAD, 0xC1 => Self::CALLDATASIZE,
            0xC2 => Self::CALLDATACOPY, 0xC3 => Self::CODESIZE,
            0xC4 => Self::CODECOPY, 0xC5 => Self::EXTCODESIZE,
            0xC6 => Self::RETURNDATASIZE, 0xC7 => Self::RETURNDATACOPY,
            0xD0 => Self::DUP2,    0xD1 => Self::DUP3,     0xD2 => Self::DUP4,
            0xD3 => Self::DUP5,    0xD4 => Self::DUP6,     0xD5 => Self::DUP7,
            0xD6 => Self::DUP8,    0xD7 => Self::DUP16,
            0xD8 => Self::SWAP2,   0xD9 => Self::SWAP3,    0xDA => Self::SWAP4,
            0xDB => Self::SWAP8,   0xDC => Self::SWAP16,
            0xE0 => Self::STEALTHCHECK, 0xE1 => Self::RINGPROOF,
            0xE2 => Self::CTVERIFY, 0xE3 => Self::DAGTIPS,
            0xE4 => Self::DAGBPS,  0xE5 => Self::ATOMICSWAP,
            0xEF => Self::DEBUG,
            _    => Self::INVALID,
        }
    }

    /// Gas cost for executing this opcode
    pub fn gas_cost(&self) -> u64 {
        match self {
            // Minimal cost (1 gas) — prevents infinite-loop DoS via free opcodes.
            // Previously 0, but a contract like `LOOP: NOP JUMP(LOOP)` would run
            // forever without consuming gas. Minimum 1 gas ensures termination.
            Self::STOP | Self::NOP | Self::JUMPDEST | Self::RETURN | Self::REVERT => 1,

            // Very cheap (2 gas) — stack & context reads
            Self::PC | Self::GAS | Self::GASLIMIT | Self::POP |
            Self::CALLER | Self::CALLVALUE | Self::ORIGIN | Self::TIMESTAMP |
            Self::BLOCKHASH | Self::BLOCKHEIGHT | Self::DIFFICULTY | Self::CHAINID |
            Self::ADDRESS | Self::BASEFEE | Self::GASPRICE |
            Self::CALLDATASIZE | Self::CODESIZE | Self::RETURNDATASIZE |
            Self::MSIZE => 2,

            // Cheap (3 gas) — stack manipulation & simple arithmetic
            Self::PUSH1 | Self::PUSH2 | Self::PUSH4 | Self::PUSH8 |
            Self::PUSH16 | Self::PUSH32 |
            Self::DUP1 | Self::SWAP1 |
            Self::DUP2 | Self::DUP3 | Self::DUP4 | Self::DUP5 |
            Self::DUP6 | Self::DUP7 | Self::DUP8 | Self::DUP16 |
            Self::SWAP2 | Self::SWAP3 | Self::SWAP4 | Self::SWAP8 | Self::SWAP16 |
            Self::ADD | Self::SUB | Self::LT | Self::GT | Self::SLT | Self::SGT |
            Self::EQ | Self::NEQ | Self::ISZERO |
            Self::AND | Self::OR | Self::XOR | Self::NOT |
            Self::BYTE | Self::SHL | Self::SHR | Self::SAR |
            Self::ROL | Self::ROR |
            Self::MIN | Self::MAX | Self::SIGNEXTEND |
            Self::MLOAD | Self::MSTORE | Self::MSTORE8 => 3,

            // Medium (5 gas) — multiplication, division
            Self::MUL | Self::DIV | Self::SDIV | Self::MOD | Self::SMOD |
            Self::MCOPY | Self::MZERO => 5,

            // Moderate (8 gas) — modular arithmetic, jumps, data ops
            Self::ADDMOD | Self::MULMOD |
            Self::JUMP | Self::JUMPI | Self::JUMPF |
            Self::CALLDATALOAD | Self::CALLDATACOPY | Self::CODECOPY |
            Self::RETURNDATACOPY => 8,

            // Crypto (30 gas)
            Self::SHA256 | Self::KECCAK256 | Self::SHA3 | Self::BLAKE3 => 30,

            // Expensive crypto (3000 gas)
            Self::ECRECOVER | Self::VERIFY => 3_000,

            // Expensive (50 gas)
            Self::EXP => 50,

            // Storage reads (200 gas)
            Self::SLOAD | Self::SSIZE | Self::BALANCE | Self::SELFBALANCE |
            Self::EXTCODESIZE => 200,

            // Logging (375 base + per topic)
            Self::LOG0 => 375,
            Self::LOG1 => 750,
            Self::LOG2 => 1_125,
            Self::LOG3 => 1_500,
            Self::LOG4 => 1_875,

            // Calls (700 base gas)
            Self::CALL | Self::CALLCODE | Self::DELEGATECALL | Self::STATICCALL => 700,

            // Contract creation (32000 gas)
            Self::CREATE | Self::CREATE2 => 32_000,

            // Storage writes (5000 gas)
            Self::SSTORE => 5_000,

            // Storage delete (5000 gas but with gas refund)
            Self::SDELETE => 5_000,

            // Self destruct (25000 gas)
            Self::SELFDESTRUCT => 25_000,

            // ShadowVM extensions (privacy ops are expensive)
            Self::STEALTHCHECK => 500,
            Self::RINGPROOF    => 10_000,
            Self::CTVERIFY     => 5_000,
            Self::DAGTIPS      => 10,
            Self::DAGBPS       => 10,
            Self::ATOMICSWAP   => 50_000,

            // Debug (1 gas in testnet, blocked in mainnet via validator)
            Self::DEBUG => 1,

            // Invalid — costs all remaining gas
            Self::INVALID => u64::MAX,
        }
    }

    /// Number of operand bytes following this opcode
    pub fn operand_size(&self) -> usize {
        match self {
            Self::PUSH1  => 1,
            Self::PUSH2  => 2,
            Self::PUSH4  => 4,
            Self::PUSH8  => 8,
            Self::PUSH16 => 16,
            Self::PUSH32 => 32,
            _            => 0,
        }
    }

    /// Number of stack items popped
    pub fn stack_pop(&self) -> usize {
        match self {
            Self::STOP | Self::NOP | Self::JUMPDEST | Self::PC | Self::GAS |
            Self::GASLIMIT | Self::CALLER | Self::CALLVALUE | Self::ORIGIN |
            Self::TIMESTAMP | Self::BLOCKHASH | Self::BLOCKHEIGHT | Self::DIFFICULTY |
            Self::CHAINID | Self::ADDRESS | Self::BASEFEE | Self::GASPRICE |
            Self::SELFBALANCE | Self::MSIZE | Self::CALLDATASIZE | Self::CODESIZE |
            Self::RETURNDATASIZE | Self::DAGTIPS | Self::DAGBPS | Self::DEBUG |
            Self::PUSH1 | Self::PUSH2 | Self::PUSH4 | Self::PUSH8 |
            Self::PUSH16 | Self::PUSH32 => 0,

            Self::POP | Self::ISZERO | Self::NOT | Self::SLOAD | Self::JUMP |
            Self::BALANCE | Self::EXTCODESIZE | Self::CALLDATALOAD |
            Self::SHA256 | Self::KECCAK256 | Self::SHA3 | Self::BLAKE3 |
            Self::SDELETE | Self::SSIZE | Self::MLOAD | Self::MSTORE8 |
            Self::LOG0 | Self::DUP1 | Self::STEALTHCHECK |
            Self::SELFDESTRUCT => 1,

            Self::ADD | Self::SUB | Self::MUL | Self::DIV | Self::SDIV |
            Self::MOD | Self::SMOD | Self::EXP | Self::MIN | Self::MAX |
            Self::LT | Self::GT | Self::SLT | Self::SGT | Self::EQ |
            Self::NEQ | Self::AND | Self::OR | Self::XOR |
            Self::BYTE | Self::SHL | Self::SHR | Self::SAR | Self::ROL |
            Self::ROR | Self::SIGNEXTEND |
            Self::SSTORE | Self::MSTORE | Self::JUMPI | Self::JUMPF |
            Self::RETURN | Self::REVERT | Self::SWAP1 | Self::LOG1 |
            Self::DUP2 | Self::SWAP2 => 2,

            Self::ADDMOD | Self::MULMOD |
            Self::CALLDATACOPY | Self::CODECOPY | Self::RETURNDATACOPY |
            Self::MCOPY | Self::MZERO | Self::LOG2 |
            Self::DUP3 | Self::SWAP3 | Self::CREATE => 3,

            Self::LOG3 | Self::DUP4 | Self::SWAP4 | Self::CREATE2 => 4,
            Self::LOG4 | Self::DUP5 => 5,
            Self::DUP6 => 6,
            Self::CALL | Self::CALLCODE | Self::DELEGATECALL | Self::STATICCALL |
            Self::DUP7 | Self::ECRECOVER | Self::VERIFY => 7,
            Self::DUP8 | Self::SWAP8 => 8,
            Self::DUP16 | Self::SWAP16 | Self::RINGPROOF | Self::CTVERIFY |
            Self::ATOMICSWAP => 16,
            Self::INVALID => 0,
        }
    }

    /// Number of stack items pushed
    pub fn stack_push(&self) -> usize {
        match self {
            Self::STOP | Self::NOP | Self::JUMPDEST | Self::POP |
            Self::SSTORE | Self::SDELETE | Self::MSTORE | Self::MSTORE8 |
            Self::MCOPY | Self::MZERO |
            Self::LOG0 | Self::LOG1 | Self::LOG2 | Self::LOG3 | Self::LOG4 |
            Self::JUMP | Self::JUMPI | Self::JUMPF |
            Self::RETURN | Self::REVERT | Self::SELFDESTRUCT |
            Self::CALLDATACOPY | Self::CODECOPY | Self::RETURNDATACOPY |
            Self::DEBUG => 0,

            _ => 1, // Most opcodes push exactly 1 value
        }
    }

    /// Human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::STOP => "STOP", Self::NOP => "NOP", Self::PC => "PC",
            Self::GAS => "GAS", Self::GASLIMIT => "GASLIMIT", Self::JUMPDEST => "JUMPDEST",
            Self::PUSH1 => "PUSH1", Self::PUSH2 => "PUSH2", Self::PUSH4 => "PUSH4",
            Self::PUSH8 => "PUSH8", Self::PUSH16 => "PUSH16", Self::PUSH32 => "PUSH32",
            Self::POP => "POP", Self::DUP1 => "DUP1", Self::SWAP1 => "SWAP1",
            Self::ADD => "ADD", Self::SUB => "SUB", Self::MUL => "MUL",
            Self::DIV => "DIV", Self::SDIV => "SDIV", Self::MOD => "MOD",
            Self::SMOD => "SMOD", Self::ADDMOD => "ADDMOD", Self::MULMOD => "MULMOD",
            Self::EXP => "EXP", Self::SIGNEXTEND => "SIGNEXTEND",
            Self::MIN => "MIN", Self::MAX => "MAX",
            Self::LT => "LT", Self::GT => "GT", Self::SLT => "SLT", Self::SGT => "SGT",
            Self::EQ => "EQ", Self::ISZERO => "ISZERO", Self::NEQ => "NEQ",
            Self::AND => "AND", Self::OR => "OR", Self::XOR => "XOR", Self::NOT => "NOT",
            Self::BYTE => "BYTE", Self::SHL => "SHL", Self::SHR => "SHR",
            Self::SAR => "SAR", Self::ROL => "ROL", Self::ROR => "ROR",
            Self::SLOAD => "SLOAD", Self::SSTORE => "SSTORE", Self::SDELETE => "SDELETE",
            Self::SSIZE => "SSIZE",
            Self::SHA256 => "SHA256", Self::KECCAK256 => "KECCAK256", Self::SHA3 => "SHA3",
            Self::BLAKE3 => "BLAKE3", Self::ECRECOVER => "ECRECOVER", Self::VERIFY => "VERIFY",
            Self::CALLER => "CALLER", Self::CALLVALUE => "CALLVALUE", Self::ORIGIN => "ORIGIN",
            Self::TIMESTAMP => "TIMESTAMP", Self::BLOCKHASH => "BLOCKHASH",
            Self::BLOCKHEIGHT => "BLOCKHEIGHT", Self::DIFFICULTY => "DIFFICULTY",
            Self::CHAINID => "CHAINID", Self::SELFBALANCE => "SELFBALANCE",
            Self::BASEFEE => "BASEFEE", Self::ADDRESS => "ADDRESS",
            Self::BALANCE => "BALANCE", Self::GASPRICE => "GASPRICE",
            Self::JUMP => "JUMP", Self::JUMPI => "JUMPI", Self::JUMPF => "JUMPF",
            Self::MLOAD => "MLOAD", Self::MSTORE => "MSTORE", Self::MSTORE8 => "MSTORE8",
            Self::MSIZE => "MSIZE", Self::MCOPY => "MCOPY", Self::MZERO => "MZERO",
            Self::LOG0 => "LOG0", Self::LOG1 => "LOG1", Self::LOG2 => "LOG2",
            Self::LOG3 => "LOG3", Self::LOG4 => "LOG4",
            Self::CALL => "CALL", Self::CALLCODE => "CALLCODE",
            Self::DELEGATECALL => "DELEGATECALL", Self::STATICCALL => "STATICCALL",
            Self::CREATE => "CREATE", Self::CREATE2 => "CREATE2",
            Self::RETURN => "RETURN", Self::REVERT => "REVERT",
            Self::SELFDESTRUCT => "SELFDESTRUCT",
            Self::CALLDATALOAD => "CALLDATALOAD", Self::CALLDATASIZE => "CALLDATASIZE",
            Self::CALLDATACOPY => "CALLDATACOPY", Self::CODESIZE => "CODESIZE",
            Self::CODECOPY => "CODECOPY", Self::EXTCODESIZE => "EXTCODESIZE",
            Self::RETURNDATASIZE => "RETURNDATASIZE", Self::RETURNDATACOPY => "RETURNDATACOPY",
            Self::DUP2 => "DUP2", Self::DUP3 => "DUP3", Self::DUP4 => "DUP4",
            Self::DUP5 => "DUP5", Self::DUP6 => "DUP6", Self::DUP7 => "DUP7",
            Self::DUP8 => "DUP8", Self::DUP16 => "DUP16",
            Self::SWAP2 => "SWAP2", Self::SWAP3 => "SWAP3", Self::SWAP4 => "SWAP4",
            Self::SWAP8 => "SWAP8", Self::SWAP16 => "SWAP16",
            Self::STEALTHCHECK => "STEALTHCHECK", Self::RINGPROOF => "RINGPROOF",
            Self::CTVERIFY => "CTVERIFY", Self::DAGTIPS => "DAGTIPS",
            Self::DAGBPS => "DAGBPS", Self::ATOMICSWAP => "ATOMICSWAP",
            Self::DEBUG => "DEBUG", Self::INVALID => "INVALID",
        }
    }

    /// Whether this opcode terminates execution
    pub fn is_terminating(&self) -> bool {
        matches!(self, Self::STOP | Self::RETURN | Self::REVERT | Self::SELFDESTRUCT | Self::INVALID)
    }

    /// Whether this opcode modifies state
    pub fn is_state_modifying(&self) -> bool {
        matches!(self, Self::SSTORE | Self::SDELETE | Self::CREATE | Self::CREATE2 |
            Self::CALL | Self::CALLCODE | Self::DELEGATECALL | Self::SELFDESTRUCT |
            Self::LOG0 | Self::LOG1 | Self::LOG2 | Self::LOG3 | Self::LOG4)
    }

    /// Total number of defined opcodes
    pub fn total_opcodes() -> usize { 119 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_byte_roundtrip() {
        for b in 0..=255u8 {
            let op = OpCode::from_byte(b);
            if op != OpCode::INVALID {
                assert_eq!(op as u8, b, "Opcode {:?} byte mismatch", op);
            }
        }
    }

    #[test]
    fn all_opcodes_have_names() {
        for b in 0..=255u8 {
            let op = OpCode::from_byte(b);
            assert!(!op.name().is_empty());
        }
    }

    #[test]
    fn gas_costs_are_sane() {
        assert_eq!(OpCode::STOP.gas_cost(), 0);
        assert_eq!(OpCode::ADD.gas_cost(), 3);
        assert!(OpCode::SSTORE.gas_cost() > OpCode::SLOAD.gas_cost());
        assert!(OpCode::CREATE.gas_cost() > OpCode::CALL.gas_cost());
        assert!(OpCode::SELFDESTRUCT.gas_cost() > OpCode::SSTORE.gas_cost());
    }

    #[test]
    fn push_operand_sizes() {
        assert_eq!(OpCode::PUSH1.operand_size(), 1);
        assert_eq!(OpCode::PUSH2.operand_size(), 2);
        assert_eq!(OpCode::PUSH4.operand_size(), 4);
        assert_eq!(OpCode::PUSH8.operand_size(), 8);
        assert_eq!(OpCode::PUSH32.operand_size(), 32);
        assert_eq!(OpCode::ADD.operand_size(), 0);
    }

    #[test]
    fn terminating_opcodes() {
        assert!(OpCode::STOP.is_terminating());
        assert!(OpCode::RETURN.is_terminating());
        assert!(OpCode::REVERT.is_terminating());
        assert!(!OpCode::ADD.is_terminating());
        assert!(!OpCode::JUMP.is_terminating());
    }

    #[test]
    fn state_modifying_opcodes() {
        assert!(OpCode::SSTORE.is_state_modifying());
        assert!(OpCode::CREATE.is_state_modifying());
        assert!(OpCode::LOG0.is_state_modifying());
        assert!(!OpCode::SLOAD.is_state_modifying());
        assert!(!OpCode::ADD.is_state_modifying());
    }

    #[test]
    fn shadowvm_extensions_exist() {
        assert_ne!(OpCode::STEALTHCHECK, OpCode::INVALID);
        assert_ne!(OpCode::RINGPROOF, OpCode::INVALID);
        assert_ne!(OpCode::CTVERIFY, OpCode::INVALID);
        assert_ne!(OpCode::DAGTIPS, OpCode::INVALID);
        assert_ne!(OpCode::DAGBPS, OpCode::INVALID);
        assert_ne!(OpCode::ATOMICSWAP, OpCode::INVALID);
    }

    #[test]
    fn opcode_count() {
        let mut count = 0;
        for b in 0..=255u8 {
            if OpCode::from_byte(b) != OpCode::INVALID {
                count += 1;
            }
        }
        assert_eq!(count, OpCode::total_opcodes(),
            "Opcode count mismatch: found {} but total_opcodes() says {}",
            count, OpCode::total_opcodes());
    }

    #[test]
    fn privacy_opcodes_are_expensive() {
        assert!(OpCode::RINGPROOF.gas_cost() >= 10_000);
        assert!(OpCode::CTVERIFY.gas_cost() >= 5_000);
        assert!(OpCode::ATOMICSWAP.gas_cost() >= 50_000);
    }
}
