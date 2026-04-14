//! Execution Trace -- records VM execution for debugging.

use serde::{Deserialize, Serialize};

/// A single step in execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    pub pc: usize,
    pub opcode: u8,
    pub opcode_name: String,
    pub gas_before: u64,
    pub gas_after: u64,
    pub gas_cost: u64,
    pub stack_depth: usize,
    pub memory_size: usize,
    pub depth: usize,
}

/// A log entry captured during traced execution (serializable version)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceLogEntry {
    pub contract: String,
    pub topic_count: usize,
    pub data_len: usize,
}

/// A complete execution trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub contract: String,
    pub caller: String,
    pub value: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub success: bool,
    pub return_data: Vec<u8>,
    pub steps: Vec<TraceStep>,
    pub logs: Vec<TraceLogEntry>,
    pub storage_changes: Vec<StorageChange>,
    pub calls: Vec<CallTrace>,
}

/// Storage change during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChange {
    pub contract: String,
    pub key: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Nested call trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTrace {
    pub call_type: String, // "CALL", "STATICCALL", "DELEGATECALL", "CREATE"
    pub from: String,
    pub to: String,
    pub value: u64,
    pub gas: u64,
    pub gas_used: u64,
    pub success: bool,
    pub return_data: Vec<u8>,
    pub depth: usize,
}

impl ExecutionTrace {
    pub fn new(contract: &str, caller: &str, value: u64, gas_limit: u64) -> Self {
        Self {
            contract: contract.into(),
            caller: caller.into(),
            value,
            gas_limit,
            gas_used: 0,
            success: false,
            return_data: vec![],
            steps: Vec::with_capacity(1024),
            logs: vec![],
            storage_changes: vec![],
            calls: vec![],
        }
    }

    pub fn add_step(&mut self, step: TraceStep) {
        self.steps.push(step);
    }

    pub fn add_storage_change(&mut self, change: StorageChange) {
        self.storage_changes.push(change);
    }

    pub fn add_call(&mut self, call: CallTrace) {
        self.calls.push(call);
    }

    /// Get total gas used
    pub fn total_gas(&self) -> u64 {
        self.gas_used
    }

    /// Get number of execution steps
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Format as human-readable trace output
    pub fn format_pretty(&self) -> String {
        let mut out = String::new();
        out.push_str("=== Execution Trace ===\n");
        out.push_str(&format!("  Contract:  {}\n", self.contract));
        out.push_str(&format!("  Caller:    {}\n", self.caller));
        out.push_str(&format!("  Value:     {}\n", self.value));
        out.push_str(&format!(
            "  Gas:       {} / {} ({}%)\n",
            self.gas_used,
            self.gas_limit,
            if self.gas_limit > 0 {
                self.gas_used * 100 / self.gas_limit
            } else {
                0
            }
        ));
        out.push_str(&format!(
            "  Status:    {}\n",
            if self.success { "SUCCESS" } else { "FAILED" }
        ));
        out.push_str(&format!("  Steps:     {}\n", self.steps.len()));

        if !self.storage_changes.is_empty() {
            out.push_str("\n  Storage Changes:\n");
            for c in &self.storage_changes {
                out.push_str(&format!(
                    "    {} {} -> {}\n",
                    c.key,
                    c.old_value.as_deref().unwrap_or("(empty)"),
                    c.new_value.as_deref().unwrap_or("(empty)")
                ));
            }
        }

        if !self.calls.is_empty() {
            out.push_str("\n  Calls:\n");
            for c in &self.calls {
                out.push_str(&format!(
                    "    {} {} -> {} (gas: {}, {})\n",
                    c.call_type,
                    c.from,
                    c.to,
                    c.gas_used,
                    if c.success { "OK" } else { "FAIL" }
                ));
            }
        }

        if !self.logs.is_empty() {
            out.push_str(&format!("\n  Logs: {} emitted\n", self.logs.len()));
        }

        out
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_create_and_format() {
        let mut trace = ExecutionTrace::new("SD1c_abc", "user", 0, 100_000);
        trace.gas_used = 5000;
        trace.success = true;
        trace.add_step(TraceStep {
            pc: 0,
            opcode: 0x10,
            opcode_name: "PUSH1".into(),
            gas_before: 100_000,
            gas_after: 99_997,
            gas_cost: 3,
            stack_depth: 0,
            memory_size: 256,
            depth: 0,
        });
        trace.add_storage_change(StorageChange {
            contract: "SD1c_abc".into(),
            key: "slot:0".into(),
            old_value: None,
            new_value: Some("0x2a".into()),
        });

        let pretty = trace.format_pretty();
        assert!(pretty.contains("SD1c_abc"));
        assert!(pretty.contains("SUCCESS"));
        assert!(pretty.contains("slot:0"));
    }

    #[test]
    fn trace_json_roundtrip() {
        let trace = ExecutionTrace::new("c", "u", 100, 50_000);
        let json = trace.to_json().unwrap();
        assert!(
            json.contains("\"contract\""),
            "JSON should contain contract field"
        );
        assert!(
            json.contains("\"c\""),
            "JSON should contain contract value 'c'"
        );
    }
}
