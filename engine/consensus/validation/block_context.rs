// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block::Block;
use core::hash::{Hash, Hasher};
use core::ops::Deref;

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct BlockContext<'a> {
    block: &'a Block,
}

impl<'a> BlockContext<'a> {
    #[inline(always)]
    #[must_use]
    pub const fn new(block: &'a Block) -> Self {
        Self { block }
    }

    #[inline(always)]
    #[must_use]
    pub const fn block(&self) -> &'a Block {
        self.block
    }

    #[inline(always)]
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.block.header.hash
    }

    #[inline(always)]
    #[must_use]
    pub fn hash_bytes(&self) -> &[u8] {
        self.block.header.hash.as_bytes()
    }

    #[inline(always)]
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.block.header.height
    }

    #[inline(always)]
    pub fn parents(&self) -> &[String] {
        &self.block.header.parents
    }
}

impl<'a> Deref for BlockContext<'a> {
    type Target = Block;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.block
    }
}

impl<'a> AsRef<Block> for BlockContext<'a> {
    #[inline(always)]
    fn as_ref(&self) -> &Block {
        self.block
    }
}

impl<'a> BlockContext<'a> {
    /// Validate that block timestamp >= max parent timestamp (causality check).
    /// Without this, miners can backdate blocks to manipulate difficulty.
    pub fn validate_timestamp_causality(&self, parent_timestamps: &[u64]) -> bool {
        if parent_timestamps.is_empty() {
            // Only genesis (height 0) is allowed to have no parents
            return self.block.header.height == 0;
        }
        let max_parent_ts = parent_timestamps.iter().copied().max().unwrap_or(0);
        self.block.header.timestamp >= max_parent_ts
    }
}

impl<'a> From<&'a Block> for BlockContext<'a> {
    #[inline(always)]
    fn from(block: &'a Block) -> Self {
        Self::new(block)
    }
}

impl<'a> Hash for BlockContext<'a> {
    #[inline(always)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.block.header.hash.as_bytes());
    }
}

impl<'a> PartialEq for BlockContext<'a> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.block, other.block) || self.block.header.hash == other.block.header.hash
    }
}

impl<'a> Eq for BlockContext<'a> {}
