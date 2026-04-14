// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// VM Memory Manager — page-based, gas-metered, bounded memory for contracts.
//
// Design:
//   - Memory grows in 32-byte words (pages)
//   - Expansion costs gas (quadratic, like EVM)
//   - Maximum 1 MB per contract execution
//   - Zero-initialized on first access
//   - Memory is ephemeral (cleared after execution)
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum memory size: 1 MB (prevents DoS)
pub const MAX_MEMORY_SIZE: usize = 1_048_576;

/// Gas cost per word for memory expansion
pub const MEMORY_GAS_PER_WORD: u64 = 3;

/// Quadratic cost coefficient (gas = words * 3 + words^2 / 512)
pub const MEMORY_QUADRATIC_DIVISOR: u64 = 512;

/// Word size in bytes
pub const WORD_SIZE: usize = 32;

use crate::errors::VmError;

/// VM Memory with gas-metered expansion
pub struct Memory {
    data: Vec<u8>,
    max_size: usize,
    highest_accessed: usize,
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Memory {
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(4096), // Pre-allocate 4KB
            max_size: MAX_MEMORY_SIZE,
            highest_accessed: 0,
        }
    }

    pub fn with_limit(max_bytes: usize) -> Self {
        Self {
            data: Vec::with_capacity(max_bytes.min(4096)),
            max_size: max_bytes.min(MAX_MEMORY_SIZE),
            highest_accessed: 0,
        }
    }

    /// Calculate the gas cost for expanding memory to `new_size`
    pub fn expansion_cost(&self, offset: usize, size: usize) -> u64 {
        if size == 0 {
            return 0;
        }

        let new_end = offset.saturating_add(size);
        if new_end <= self.data.len() {
            return 0; // No expansion needed
        }

        let new_words = new_end.div_ceil(WORD_SIZE);
        let old_words = self.data.len().div_ceil(WORD_SIZE);

        if new_words <= old_words {
            return 0;
        }

        let new_cost = (new_words as u64)
            .saturating_mul(MEMORY_GAS_PER_WORD)
            .saturating_add(
                (new_words as u64).saturating_mul(new_words as u64) / MEMORY_QUADRATIC_DIVISOR,
            );

        let old_cost = (old_words as u64)
            .saturating_mul(MEMORY_GAS_PER_WORD)
            .saturating_add(
                (old_words as u64).saturating_mul(old_words as u64) / MEMORY_QUADRATIC_DIVISOR,
            );

        new_cost.saturating_sub(old_cost)
    }

    /// Ensure memory is at least `new_size` bytes, zero-extending as needed.
    /// Returns Err if exceeds max.
    fn ensure_size(&mut self, new_size: usize) -> Result<(), VmError> {
        if new_size > self.max_size {
            return Err(VmError::MemoryOutOfBounds(new_size));
        }

        if new_size > self.data.len() {
            self.data.resize(new_size, 0);
        }

        if new_size > self.highest_accessed {
            self.highest_accessed = new_size;
        }

        Ok(())
    }

    /// Load 32 bytes from offset
    pub fn load(&mut self, offset: usize) -> Result<[u8; 32], VmError> {
        let end = offset
            .checked_add(32)
            .ok_or(VmError::MemoryOutOfBounds(offset))?;
        self.ensure_size(end)?;

        let mut word = [0u8; 32];
        word.copy_from_slice(&self.data[offset..end]);
        Ok(word)
    }

    /// Store 32 bytes at offset
    pub fn store(&mut self, offset: usize, value: &[u8; 32]) -> Result<(), VmError> {
        let end = offset
            .checked_add(32)
            .ok_or(VmError::MemoryOutOfBounds(offset))?;
        self.ensure_size(end)?;

        self.data[offset..end].copy_from_slice(value);
        Ok(())
    }

    /// Load a single byte
    pub fn load_byte(&mut self, offset: usize) -> Result<u8, VmError> {
        let end = offset
            .checked_add(1)
            .ok_or(VmError::MemoryOutOfBounds(offset))?;
        self.ensure_size(end)?;
        Ok(self.data[offset])
    }

    /// Store a single byte
    pub fn store_byte(&mut self, offset: usize, value: u8) -> Result<(), VmError> {
        let end = offset
            .checked_add(1)
            .ok_or(VmError::MemoryOutOfBounds(offset))?;
        self.ensure_size(end)?;
        self.data[offset] = value;
        Ok(())
    }

    /// Load arbitrary bytes from memory
    pub fn load_range(&mut self, offset: usize, size: usize) -> Result<Vec<u8>, VmError> {
        if size == 0 {
            return Ok(vec![]);
        }
        let end = offset
            .checked_add(size)
            .ok_or(VmError::MemoryOutOfBounds(offset))?;
        self.ensure_size(end)?;
        Ok(self.data[offset..end].to_vec())
    }

    /// Store arbitrary bytes into memory
    pub fn store_range(&mut self, offset: usize, data: &[u8]) -> Result<(), VmError> {
        if data.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(data.len())
            .ok_or(VmError::MemoryOutOfBounds(offset))?;
        self.ensure_size(end)?;
        self.data[offset..end].copy_from_slice(data);
        Ok(())
    }

    /// Current memory size in bytes
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Peak memory usage
    pub fn peak_usage(&self) -> usize {
        self.highest_accessed
    }

    /// Current memory size in words (32-byte)
    pub fn word_count(&self) -> usize {
        self.data.len().div_ceil(WORD_SIZE)
    }

    /// Copy a range within memory (for MCOPY-like operations)
    pub fn copy_within(&mut self, src: usize, dst: usize, size: usize) -> Result<(), VmError> {
        if size == 0 {
            return Ok(());
        }
        let max_end = src
            .max(dst)
            .checked_add(size)
            .ok_or(VmError::MemoryOutOfBounds(src.max(dst)))?;
        self.ensure_size(max_end)?;
        self.data.copy_within(src..src + size, dst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_memory_is_empty() {
        let m = Memory::new();
        assert_eq!(m.size(), 0);
    }

    #[test]
    fn store_and_load() {
        let mut m = Memory::new();
        let value = [0xAB; 32];
        m.store(0, &value).unwrap();
        assert_eq!(m.load(0).unwrap(), value);
    }

    #[test]
    fn auto_expand() {
        let mut m = Memory::new();
        m.store_byte(1000, 0xFF).unwrap();
        assert!(m.size() >= 1001);
        assert_eq!(m.load_byte(1000).unwrap(), 0xFF);
        assert_eq!(m.load_byte(999).unwrap(), 0); // zero-initialized
    }

    #[test]
    fn max_limit_enforced() {
        let mut m = Memory::with_limit(1024);
        assert!(m.store_byte(2000, 0xFF).is_err());
    }

    #[test]
    fn expansion_cost_zero_when_no_growth() {
        let mut m = Memory::new();
        m.store(0, &[0; 32]).unwrap(); // Expand to 32 bytes
        assert_eq!(m.expansion_cost(0, 32), 0); // No growth needed
    }

    #[test]
    fn expansion_cost_grows() {
        let m = Memory::new();
        let cost1 = m.expansion_cost(0, 32); // 1 word
        let cost2 = m.expansion_cost(0, 320); // 10 words
        assert!(cost2 > cost1);
    }

    #[test]
    fn copy_within_works() {
        let mut m = Memory::new();
        let value = [0xBB; 32];
        m.store(0, &value).unwrap();
        m.copy_within(0, 64, 32).unwrap();
        assert_eq!(m.load(64).unwrap(), value);
    }

    #[test]
    fn load_range_and_store_range() {
        let mut m = Memory::new();
        let data = vec![1, 2, 3, 4, 5];
        m.store_range(100, &data).unwrap();
        assert_eq!(m.load_range(100, 5).unwrap(), data);
    }
}
