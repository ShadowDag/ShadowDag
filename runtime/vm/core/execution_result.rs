// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Execution Result — complete output of smart contract execution.
// Contains gas accounting, logs, return data, state changes, and errors.
// ═══════════════════════════════════════════════════════════════════════════

use super::event_log::LogEntry;

/// The result of executing a smart contract call
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Whether execution succeeded
    pub success: bool,
    /// Gas used by this execution
    pub gas_used: u64,
    /// Gas refunded (capped at 50% of gas_used)
    pub gas_refund: u64,
    /// Return data (output bytes from the contract)
    pub return_data: Vec<u8>,
    /// Logs emitted during execution
    pub logs: Vec<LogEntry>,
    /// Error message if execution failed
    pub error: Option<String>,
    /// Execution status code
    pub status: ExecutionStatus,
    /// Contract address (if this was a CREATE)
    pub created_address: Option<String>,
    /// Internal calls made during execution
    pub call_trace: Vec<CallTrace>,
}

/// Execution status codes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExecutionStatus {
    /// Execution completed successfully
    Success,
    /// Execution reverted (REVERT opcode)
    Revert,
    /// Ran out of gas
    OutOfGas,
    /// Invalid opcode encountered
    InvalidOpcode,
    /// Stack overflow/underflow
    StackError,
    /// Memory limit exceeded
    MemoryError,
    /// Call depth exceeded
    CallDepthError,
    /// Static call attempted state modification
    StaticCallViolation,
    /// Contract code too large
    CodeSizeError,
    /// Internal error (bug)
    InternalError,
}

impl ExecutionStatus {
    pub fn is_success(&self) -> bool {
        matches!(self, ExecutionStatus::Success)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionStatus::Success => "success",
            ExecutionStatus::Revert => "revert",
            ExecutionStatus::OutOfGas => "out_of_gas",
            ExecutionStatus::InvalidOpcode => "invalid_opcode",
            ExecutionStatus::StackError => "stack_error",
            ExecutionStatus::MemoryError => "memory_error",
            ExecutionStatus::CallDepthError => "call_depth_error",
            ExecutionStatus::StaticCallViolation => "static_call_violation",
            ExecutionStatus::CodeSizeError => "code_size_error",
            ExecutionStatus::InternalError => "internal_error",
        }
    }
}

/// Trace of an internal contract call
#[derive(Debug, Clone)]
pub struct CallTrace {
    pub from: String,
    pub to: String,
    pub value: u64,
    pub gas_used: u64,
    pub input_size: usize,
    pub output_size: usize,
    pub success: bool,
    pub depth: usize,
    pub call_type: CallType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CallType {
    Call,
    StaticCall,
    DelegateCall,
    Create,
    Create2,
}

impl ExecutionResult {
    /// Successful execution
    pub fn success(gas_used: u64, return_data: Vec<u8>, logs: Vec<LogEntry>) -> Self {
        Self {
            success: true,
            gas_used,
            gas_refund: 0,
            return_data,
            logs,
            error: None,
            status: ExecutionStatus::Success,
            created_address: None,
            call_trace: Vec::new(),
        }
    }

    /// Reverted execution (REVERT opcode — gas is consumed, state is rolled back)
    pub fn revert(gas_used: u64, return_data: Vec<u8>) -> Self {
        Self {
            success: false,
            gas_used,
            gas_refund: 0,
            return_data,
            logs: Vec::new(),
            error: Some("execution reverted".to_string()),
            status: ExecutionStatus::Revert,
            created_address: None,
            call_trace: Vec::new(),
        }
    }

    /// Failed execution (error — ALL gas consumed)
    pub fn failure(gas_limit: u64, status: ExecutionStatus, error: String) -> Self {
        Self {
            success: false,
            gas_used: gas_limit, // All gas consumed on failure
            gas_refund: 0,
            return_data: Vec::new(),
            logs: Vec::new(),
            error: Some(error),
            status,
            created_address: None,
            call_trace: Vec::new(),
        }
    }

    /// Effective gas used after refund
    pub fn effective_gas_used(&self) -> u64 {
        // Refund capped at 50% of gas used
        let max_refund = self.gas_used / 2;
        let actual_refund = self.gas_refund.min(max_refund);
        self.gas_used.saturating_sub(actual_refund)
    }

    /// Add a call trace entry
    pub fn add_trace(&mut self, trace: CallTrace) {
        self.call_trace.push(trace);
    }
}

/// Transaction receipt (stored on-chain)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: String,
    pub block_hash: String,
    pub block_height: u64,
    pub success: bool,
    pub gas_used: u64,
    pub cumulative_gas: u64,
    pub contract_address: Option<String>,
    pub logs: Vec<LogEntry>,
    pub status: u8, // 1 = success, 0 = failure
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_result() {
        let r = ExecutionResult::success(1000, vec![0xAB], vec![]);
        assert!(r.success);
        assert_eq!(r.gas_used, 1000);
        assert_eq!(r.status, ExecutionStatus::Success);
    }

    #[test]
    fn revert_result() {
        let r = ExecutionResult::revert(500, vec![0x08]);
        assert!(!r.success);
        assert_eq!(r.status, ExecutionStatus::Revert);
    }

    #[test]
    fn failure_consumes_all_gas() {
        let r = ExecutionResult::failure(
            1_000_000, ExecutionStatus::OutOfGas, "out of gas".into()
        );
        assert_eq!(r.gas_used, 1_000_000);
    }

    #[test]
    fn effective_gas_caps_refund() {
        let mut r = ExecutionResult::success(1000, vec![], vec![]);
        r.gas_refund = 800; // More than 50%
        assert_eq!(r.effective_gas_used(), 500); // Capped at 50% refund
    }

    #[test]
    fn status_strings() {
        assert_eq!(ExecutionStatus::Success.as_str(), "success");
        assert_eq!(ExecutionStatus::OutOfGas.as_str(), "out_of_gas");
        assert!(ExecutionStatus::Success.is_success());
        assert!(!ExecutionStatus::Revert.is_success());
    }
}
