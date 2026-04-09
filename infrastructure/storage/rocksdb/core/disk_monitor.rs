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
    /// When disk space cannot be determined, probes writability directly.
    pub fn can_write(data_dir: &str) -> bool {
        match Self::check(data_dir) {
            DiskStatus::Critical { .. } => false,
            DiskStatus::Unknown => {
                // Unknown free space -- probe writability directly
                let probe_path = format!("{}/.disk_probe_{}", data_dir, std::process::id());
                let writable = std::fs::write(&probe_path, b"probe").is_ok();
                let _ = std::fs::remove_file(&probe_path);
                if !writable {
                    slog_warn!("storage", "disk_write_probe_failed", path => data_dir);
                }
                writable
            }
            _ => true,
        }
    }

    /// Get free space in bytes (platform-specific).
    ///
    /// Returns `None` when the platform API is unavailable; callers must
    /// fall back to a write-probe (see `can_write`).
    fn get_free_space(path: &str) -> Option<u64> {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            let c_path = match CString::new(path) {
                Ok(p) => p,
                Err(_) => return None,
            };
            unsafe {
                let mut stat: libc::statvfs = std::mem::zeroed();
                if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                    return Some(stat.f_bavail as u64 * stat.f_frsize as u64);
                }
            }
            None
        }

        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            extern "system" {
                fn GetDiskFreeSpaceExW(
                    lpDirectoryName: *const u16,
                    lpFreeBytesAvailableToCaller: *mut u64,
                    lpTotalNumberOfBytes: *mut u64,
                    lpTotalNumberOfFreeBytes: *mut u64,
                ) -> i32;
            }

            let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
            let mut free_available: u64 = 0;
            let mut total: u64 = 0;
            let mut total_free: u64 = 0;
            let ret = unsafe {
                GetDiskFreeSpaceExW(wide.as_ptr(), &mut free_available, &mut total, &mut total_free)
            };
            if ret != 0 {
                return Some(free_available);
            }
            None
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            None
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
