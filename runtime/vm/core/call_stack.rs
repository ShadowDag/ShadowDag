// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Call Stack — manages nested contract calls with depth limiting.
//
// Each contract CALL creates a new frame on the stack with its own:
//   - Code, PC, Stack, Memory
//   - Caller, value, gas allocation
//   - Return data buffer
//
// Max depth = 1024 (same as EVM, prevents stack overflow attacks)
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::VmError;

/// Maximum call depth (prevents stack overflow DoS)
pub const MAX_CALL_DEPTH: usize = 1024;

/// Maximum code size per contract (24 KB, same as Ethereum)
pub const MAX_CODE_SIZE: usize = 24_576;

/// A single execution frame in the call stack
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// Contract address being executed
    pub address: String,
    /// Caller address (msg.sender)
    pub caller: String,
    /// Value sent with this call
    pub value: u64,
    /// Gas allocated to this frame
    pub gas_limit: u64,
    /// Gas used so far in this frame
    pub gas_used: u64,
    /// Contract bytecode
    pub code: Vec<u8>,
    /// Program counter
    pub pc: usize,
    /// Execution stack (u64 values)
    pub stack: Vec<u64>,
    /// Call data (input to the contract)
    pub calldata: Vec<u8>,
    /// Return data from the last sub-call
    pub return_data: Vec<u8>,
    /// Whether this is a static (read-only) call
    pub is_static: bool,
    /// Whether this is a delegate call
    pub is_delegate: bool,
    /// Depth in the call stack (0 = top-level)
    pub depth: usize,
}

impl CallFrame {
    /// Create a new top-level call frame
    pub fn new(
        address: String,
        caller: String,
        value: u64,
        gas_limit: u64,
        code: Vec<u8>,
        calldata: Vec<u8>,
    ) -> Self {
        Self {
            address,
            caller,
            value,
            gas_limit,
            gas_used: 0,
            code,
            pc: 0,
            stack: Vec::with_capacity(256),
            calldata,
            return_data: Vec::new(),
            is_static: false,
            is_delegate: false,
            depth: 0,
        }
    }

    /// Remaining gas in this frame
    pub fn gas_remaining(&self) -> u64 {
        self.gas_limit.saturating_sub(self.gas_used)
    }
}

/// The call stack manager
pub struct CallStack {
    frames: Vec<CallFrame>,
    max_depth: usize,
}

impl Default for CallStack {
    fn default() -> Self {
        Self::new()
    }
}

impl CallStack {
    pub fn new() -> Self {
        Self {
            frames: Vec::with_capacity(16),
            max_depth: MAX_CALL_DEPTH,
        }
    }

    /// Push a new call frame onto the stack
    pub fn push(&mut self, frame: CallFrame) -> Result<(), VmError> {
        if self.frames.len() >= self.max_depth {
            return Err(VmError::StackOverflow(self.frames.len() + 1));
        }

        if frame.code.len() > MAX_CODE_SIZE {
            return Err(VmError::CodeTooLarge {
                size: frame.code.len(),
                limit: MAX_CODE_SIZE,
            });
        }

        self.frames.push(frame);
        Ok(())
    }

    /// Pop the top frame, returning it
    pub fn pop(&mut self) -> Option<CallFrame> {
        self.frames.pop()
    }

    /// Get the current (top) frame
    pub fn current(&self) -> Option<&CallFrame> {
        self.frames.last()
    }

    /// Get the current (top) frame mutably
    pub fn current_mut(&mut self) -> Option<&mut CallFrame> {
        self.frames.last_mut()
    }

    /// Get the parent (caller) frame
    pub fn parent(&self) -> Option<&CallFrame> {
        if self.frames.len() >= 2 {
            self.frames.get(self.frames.len() - 2)
        } else {
            None
        }
    }

    /// Current call depth
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Check if stack is empty
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Create a sub-call frame (CALL opcode)
    pub fn create_call(
        &self,
        target_address: String,
        value: u64,
        gas_limit: u64,
        code: Vec<u8>,
        calldata: Vec<u8>,
    ) -> Result<CallFrame, VmError> {
        let current = self.current().ok_or(VmError::Other(
            "no current frame for creating sub-call".to_string(),
        ))?;

        if self.depth() >= self.max_depth {
            return Err(VmError::StackOverflow(self.depth()));
        }

        // Sub-call gets at most 63/64 of parent's remaining gas (EIP-150)
        let parent_remaining = current.gas_remaining();
        let max_gas = parent_remaining - parent_remaining / 64;
        let allocated_gas = gas_limit.min(max_gas);

        Ok(CallFrame {
            address: target_address,
            caller: current.address.clone(),
            value,
            gas_limit: allocated_gas,
            gas_used: 0,
            code,
            pc: 0,
            stack: Vec::with_capacity(256),
            calldata,
            return_data: Vec::new(),
            is_static: current.is_static, // Inherit static mode
            is_delegate: false,
            depth: self.depth(),
        })
    }

    /// Create a static call frame (STATICCALL — read-only)
    pub fn create_static_call(
        &self,
        target_address: String,
        gas_limit: u64,
        code: Vec<u8>,
        calldata: Vec<u8>,
    ) -> Result<CallFrame, VmError> {
        let mut frame = self.create_call(target_address, 0, gas_limit, code, calldata)?;
        frame.is_static = true;
        Ok(frame)
    }

    /// Create a delegate call frame (DELEGATECALL — uses caller's storage)
    pub fn create_delegate_call(
        &self,
        _code_address: String,
        gas_limit: u64,
        code: Vec<u8>,
        calldata: Vec<u8>,
    ) -> Result<CallFrame, VmError> {
        let current = self.current().ok_or(VmError::Other(
            "no current frame for delegate call".to_string(),
        ))?;

        let mut frame = self.create_call(
            current.address.clone(), // Keep caller's address for storage
            current.value,
            gas_limit,
            code,
            calldata,
        )?;
        frame.is_delegate = true;
        frame.caller = current.caller.clone(); // Preserve original caller
        Ok(frame)
    }

    /// Total gas used across all frames
    pub fn total_gas_used(&self) -> u64 {
        self.frames.iter().map(|f| f.gas_used).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_push_pop() {
        let mut cs = CallStack::new();
        let frame = CallFrame::new(
            "contract_a".into(),
            "user".into(),
            100,
            1_000_000,
            vec![0x00],
            vec![],
        );
        cs.push(frame).unwrap();
        assert_eq!(cs.depth(), 1);
        assert!(cs.current().is_some());
        cs.pop();
        assert_eq!(cs.depth(), 0);
    }

    #[test]
    fn max_depth_enforced() {
        let mut cs = CallStack::new();
        for i in 0..MAX_CALL_DEPTH {
            let frame = CallFrame::new(
                format!("contract_{}", i),
                "user".into(),
                0,
                1000,
                vec![0x00],
                vec![],
            );
            cs.push(frame).unwrap();
        }
        // One more should fail
        let frame = CallFrame::new(
            "overflow".into(),
            "user".into(),
            0,
            1000,
            vec![0x00],
            vec![],
        );
        assert!(cs.push(frame).is_err());
    }

    #[test]
    fn sub_call_inherits_static() {
        let mut cs = CallStack::new();
        let mut frame = CallFrame::new("a".into(), "user".into(), 0, 1_000_000, vec![], vec![]);
        frame.is_static = true;
        cs.push(frame).unwrap();

        let sub = cs
            .create_call("b".into(), 0, 500_000, vec![], vec![])
            .unwrap();
        assert!(sub.is_static); // Inherited
    }

    #[test]
    fn gas_capped_at_63_64() {
        let mut cs = CallStack::new();
        let frame = CallFrame::new("a".into(), "user".into(), 0, 640_000, vec![], vec![]);
        cs.push(frame).unwrap();

        let sub = cs
            .create_call("b".into(), 0, 1_000_000, vec![], vec![])
            .unwrap();
        // Should be capped at 630000 (640000 - 640000/64 = 630000)
        assert!(sub.gas_limit <= 630_000);
    }

    #[test]
    fn code_size_limit() {
        let mut cs = CallStack::new();
        let big_code = vec![0x00; MAX_CODE_SIZE + 1];
        let frame = CallFrame::new("a".into(), "user".into(), 0, 1000, big_code, vec![]);
        assert!(cs.push(frame).is_err());
    }
}
