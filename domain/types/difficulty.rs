// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

pub type DifficultyValue = u64;

pub struct DifficultyHelper;

impl DifficultyHelper {
    pub const MIN: u64 = 1;
    pub const MAX: u64 = 1_000_000;

    pub fn is_valid(d: u64) -> bool {
        (Self::MIN..=Self::MAX).contains(&d)
    }

    pub fn clamp(d: u64) -> u64 {
        d.clamp(Self::MIN, Self::MAX)
    }
}
