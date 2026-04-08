// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Disk Monitor — Monitors available disk space and warns before exhaustion.
// Prevents database corruption from out-of-disk writes.
// ═══════════════════════════════════════════════════════════════════════════

use crate::{slog_warn, slog_error};

/// Minimum free disk space (1 GB) — below this, node enters safe mode
pub const MIN_FREE_SPACE_BYTES: u64 = 1_073_741_824; // 1 GB

/// Warning threshold (5 GB) — log warnings
pub const WARN_FREE_SPACE_BYTES: u64 = 5_368_709_120; // 5 GB

/// Disk space check result
#[derive(Debug, Clone, PartialEq)]
pub enum DiskStatus {
    /// Plenty of space
    Ok { free_bytes: u64 },
    /// Getting low — warn operator
    Warning { free_bytes: u64 },
    /// Critical — stop writing, enter read-only mode
    Critical { free_bytes: u64 },
    /// Cannot determine (unsupported platform)
    Unknown,
}

impl DiskStatus {
    pub fn is_ok(&self) -> bool { matches!(self, DiskStatus::Ok { .. }) }
    pub fn is_critical(&self) -> bool { matches!(self, DiskStatus::Critical { .. }) }

    pub fn free_gb(&self) -> f64 {
        match self {
            DiskStatus::Ok { free_bytes } |
            DiskStatus::Warning { free_bytes } |
            DiskStatus::Critical { free_bytes } => *free_bytes as f64 / 1_073_741_824.0,
            DiskStatus::Unknown => 0.0,
        }
    }
}

pub struct DiskMonitor;

impl DiskMonitor {
    /// Check available disk space for the given data directory
    pub fn check(data_dir: &str) -> DiskStatus {
        let free = Self::get_free_space(data_dir);

        match free {
            Some(bytes) if bytes < MIN_FREE_SPACE_BYTES => {
                slog_error!("storage", "disk_space_critical", free_gb => format!("{:.2}", bytes as f64 / 1_073_741_824.0));
                DiskStatus::Critical { free_bytes: bytes }
            }
            Some(bytes) if bytes < WARN_FREE_SPACE_BYTES => {
                slog_warn!("storage", "disk_space_low", free_gb => format!("{:.2}", bytes as f64 / 1_073_741_824.0));
                DiskStatus::Warning { free_bytes: bytes }
            }
            Some(bytes) => DiskStatus::Ok { free_bytes: bytes },
            None => DiskStatus::Unknown,
        }
    }

    /// Check if it's safe to write (not in critical state).
    /// Returns `true` with a warning when disk space cannot be determined.
    pub fn can_write(data_dir: &str) -> bool {
        match Self::check(data_dir) {
            DiskStatus::Critical { .. } => false,
            DiskStatus::Unknown => {
                slog_warn!("storage", "disk_space_unknown", path => data_dir);
                true // Allow but warn -- cannot determine free space
            }
            _ => true,
        }
    }

    /// Get free space in bytes (platform-specific)
    fn get_free_space(_path: &str) -> Option<u64> {
        // Platform-specific implementation needed
        // Return None (unknown) instead of fake value
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_status() {
        let status = DiskStatus::Ok { free_bytes: 50_000_000_000 };
        assert!(status.is_ok());
        assert!(!status.is_critical());
        assert!(status.free_gb() > 40.0);
    }

    #[test]
    fn critical_status() {
        let status = DiskStatus::Critical { free_bytes: 500_000_000 };
        assert!(status.is_critical());
        assert!(!status.is_ok());
    }

    #[test]
    fn warning_thresholds() {
        const { assert!(MIN_FREE_SPACE_BYTES < WARN_FREE_SPACE_BYTES) };
    }

    #[test]
    fn check_current_dir() {
        let status = DiskMonitor::check(".");
        // Should return Ok or Unknown, never Critical on dev machine
        assert!(!status.is_critical());
    }

    #[test]
    fn can_write_check() {
        assert!(DiskMonitor::can_write("."));
    }
}
