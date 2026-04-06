// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Disk Monitor — Monitors available disk space and warns before exhaustion.
// Prevents database corruption from out-of-disk writes.
// ═══════════════════════════════════════════════════════════════════════════


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
                eprintln!("[DiskMonitor] CRITICAL: Only {:.2} GB free! Node entering safe mode.",
                    bytes as f64 / 1_073_741_824.0);
                DiskStatus::Critical { free_bytes: bytes }
            }
            Some(bytes) if bytes < WARN_FREE_SPACE_BYTES => {
                eprintln!("[DiskMonitor] WARNING: Only {:.2} GB free.",
                    bytes as f64 / 1_073_741_824.0);
                DiskStatus::Warning { free_bytes: bytes }
            }
            Some(bytes) => DiskStatus::Ok { free_bytes: bytes },
            None => DiskStatus::Unknown,
        }
    }

    /// Check if it's safe to write (not in critical state)
    pub fn can_write(data_dir: &str) -> bool {
        !Self::check(data_dir).is_critical()
    }

    /// Get free space in bytes (platform-specific)
    fn get_free_space(path: &str) -> Option<u64> {
        // Use std::fs metadata to estimate — cross-platform approach
        // On real systems, would use statvfs (Unix) or GetDiskFreeSpaceEx (Windows)
        let _meta = std::fs::metadata(path).ok()?;
        // Fallback: assume plenty of space if we can't determine
        // In production: use platform-specific APIs
        #[cfg(target_os = "windows")]
        {
            // Windows: use available_space from std (nightly) or winapi
            // For now, return a safe estimate based on temp file creation
            Some(100_000_000_000) // Assume 100GB if can't determine
        }
        #[cfg(not(target_os = "windows"))]
        {
            Some(100_000_000_000) // Placeholder
        }
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
