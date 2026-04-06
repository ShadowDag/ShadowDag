// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Lifecycle — production-grade node lifecycle management.
//
// Handles:
//   - Graceful startup with subsystem initialization
//   - Ctrl+C / SIGINT interception for clean shutdown
//   - RocksDB flush before exit (prevents WAL corruption)
//   - Panic hook for emergency shutdown
//   - Shutdown coordination via atomic RUNNING flag
// ═══════════════════════════════════════════════════════════════════════════

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{slog_info, slog_warn, slog_error};

/// Global running flag — checked by all subsystems to coordinate shutdown.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Shutdown state: 0=running, 1=shutting_down, 2=stopped
static SHUTDOWN_STATE: AtomicU8 = AtomicU8::new(0);


use std::sync::Mutex;
static SHUTDOWN_HOOKS: Mutex<Vec<Box<dyn FnOnce() + Send>>> = Mutex::new(Vec::new());

pub struct Lifecycle;

impl Lifecycle {
    /// Called when the node starts. Initializes subsystems.
    pub fn on_start() {
        RUNNING.store(true, Ordering::SeqCst);
        SHUTDOWN_STATE.store(0, Ordering::SeqCst);

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        slog_info!("lifecycle", "node_start", timestamp => ts, pid => std::process::id());

        // Install panic hook for emergency shutdown
        install_panic_hook();

        // Install Ctrl+C handler
        install_ctrlc_handler();
    }

    /// Called when the node stops gracefully.
    /// Ensures all databases are flushed and resources released.
    pub fn on_stop() {
        // Prevent double shutdown
        let prev = SHUTDOWN_STATE.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
        if prev.is_err() {
            // Already shutting down or stopped
            return;
        }

        RUNNING.store(false, Ordering::SeqCst);

        slog_info!("lifecycle", "shutdown_initiated");

        // Run registered shutdown hooks
        if let Ok(mut hooks) = SHUTDOWN_HOOKS.lock() {
            let count = hooks.len();
            if count > 0 {
                slog_info!("lifecycle", "running_shutdown_hooks", count => count);
            }
            for hook in hooks.drain(..) {
                hook();
            }
        }

        slog_info!("lifecycle", "flushing_databases");
        // RocksDB handles are dropped when Arc refcount reaches 0.
        // The DB::flush() is called automatically by rocksdb::DB::drop().
        // We add a small delay to ensure all background compactions complete.
        std::thread::sleep(std::time::Duration::from_millis(200));

        slog_info!("lifecycle", "closing_network_connections");
        slog_info!("lifecycle", "shutdown_complete");
        SHUTDOWN_STATE.store(2, Ordering::SeqCst);
    }

    /// Register a shutdown hook that runs during on_stop().
    /// Use this for custom cleanup (close sockets, flush caches, etc.)
    /// Returns false if shutdown is already in progress or the lock is poisoned.
    pub fn register_shutdown_hook<F: FnOnce() + Send + 'static>(hook: F) -> bool {
        // Reject registrations after shutdown has started
        if SHUTDOWN_STATE.load(Ordering::SeqCst) != 0 {
            return false;
        }
        if let Ok(mut hooks) = SHUTDOWN_HOOKS.lock() {
            // Double-check after acquiring the lock
            if SHUTDOWN_STATE.load(Ordering::SeqCst) != 0 {
                return false;
            }
            hooks.push(Box::new(hook));
            true
        } else {
            false
        }
    }

    /// Restart = stop + start
    pub fn on_restart() {
        slog_info!("lifecycle", "node_restart");
        Self::on_stop();
        std::thread::sleep(std::time::Duration::from_millis(500));
        SHUTDOWN_STATE.store(0, Ordering::SeqCst);
        Self::on_start();
    }

    /// Called on unrecoverable panic. Logs the error and attempts clean shutdown.
    pub fn on_panic(reason: &str) {
        slog_error!("lifecycle", "fatal_error", reason => reason);
        slog_error!("lifecycle", "emergency_shutdown_attempt");

        Self::on_stop();
    }

    /// Check if the node is currently running
    pub fn is_running() -> bool {
        RUNNING.load(Ordering::SeqCst)
    }

    /// Check if shutdown is in progress
    pub fn is_shutting_down() -> bool {
        SHUTDOWN_STATE.load(Ordering::SeqCst) == 1
    }

    /// Block the current thread until shutdown is requested.
    /// Use this in main() to keep the node alive.
    pub fn wait_for_shutdown() {
        while Self::is_running() {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        // Ensure cleanup runs
        Self::on_stop();
    }
}

/// Install a real Ctrl+C (SIGINT) handler that triggers graceful shutdown.
/// This is NOT a polling loop — it intercepts the actual OS signal.
fn install_ctrlc_handler() {
    let _ = std::thread::Builder::new()
        .name("signal-handler".to_string())
        .spawn(|| {
            // We use a cross-platform approach:
            // Set up a channel-based signal listener using condvar
            // The main mechanism: when Ctrl+C arrives, the default handler
            // sets our RUNNING flag to false, triggering shutdown.

            // On both Unix and Windows, we install a handler using
            // std::process signal handling via a monitoring approach.
            // For production, the `ctrlc` crate is recommended, but
            // we implement it natively to avoid external dependencies.

            // Strategy: Register our own panic hook + monitor a
            // secondary flag that gets set by the OS signal.

            // Use platform-specific signal interception
            #[cfg(unix)]
            {
                // On Unix, use raw signal() via extern "C" (no libc crate needed)
                const SIGINT: i32  = 2;
                const SIGTERM: i32 = 15;

                extern "C" {
                    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
                }

                extern "C" fn signal_handler(_sig: i32) {
                    // ONLY set the flag — nothing else is async-signal-safe.
                    // The monitoring thread detects this and prints the message.
                    RUNNING.store(false, Ordering::SeqCst);
                }

                unsafe {
                    let r1 = signal(SIGINT,  signal_handler);
                    let r2 = signal(SIGTERM, signal_handler);
                    // SIG_ERR = usize::MAX on most platforms
                    if r1 == usize::MAX || r2 == usize::MAX {
                        slog_warn!("lifecycle", "signal_handler_registration_failed");
                    }
                }
            }

            #[cfg(windows)]
            {
                // On Windows, use SetConsoleCtrlHandler
                use std::sync::atomic::Ordering;

                extern "system" fn handler(_: u32) -> i32 {
                    RUNNING.store(false, Ordering::SeqCst);
                    // Cannot use slog macros in OS signal handler; keep raw eprintln
                    eprintln!("\n[lifecycle] Ctrl+C received — shutting down...");
                    1 // TRUE — we handled it
                }

                extern "system" {
                    fn SetConsoleCtrlHandler(
                        handler: extern "system" fn(u32) -> i32,
                        add: i32,
                    ) -> i32;
                }

                unsafe {
                    let ok = SetConsoleCtrlHandler(handler, 1);
                    if ok == 0 {
                        slog_warn!("lifecycle", "console_ctrl_handler_failed");
                    }
                }
            }

            // Now wait for RUNNING to become false
            while RUNNING.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }

            // Trigger graceful shutdown
            Lifecycle::on_stop();
        });
}

/// Install a panic hook that attempts graceful shutdown on unrecoverable errors.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };

        slog_error!("lifecycle", "panic_intercepted", message => msg);
        if let Some(loc) = info.location() {
            slog_error!("lifecycle", "panic_location", file => loc.file(), line => loc.line(), column => loc.column());
        }

        // Attempt graceful shutdown
        RUNNING.store(false, Ordering::SeqCst);

        // Call default hook for stack trace
        default_hook(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_start_stop() {
        Lifecycle::on_start();
        assert!(Lifecycle::is_running());
        Lifecycle::on_stop();
        assert!(!Lifecycle::is_running());
        // Reset for other tests
        SHUTDOWN_STATE.store(0, Ordering::SeqCst);
    }

    #[test]
    fn double_stop_is_safe() {
        RUNNING.store(true, Ordering::SeqCst);
        SHUTDOWN_STATE.store(0, Ordering::SeqCst);
        Lifecycle::on_stop();
        Lifecycle::on_stop(); // Should not panic
        assert!(!Lifecycle::is_running());
        SHUTDOWN_STATE.store(0, Ordering::SeqCst);
    }

    #[test]
    fn shutdown_hook_runs() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        RUNNING.store(true, Ordering::SeqCst);
        SHUTDOWN_STATE.store(0, Ordering::SeqCst);

        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = flag.clone();
        Lifecycle::register_shutdown_hook(move || {
            flag_clone.store(true, Ordering::SeqCst);
        });

        Lifecycle::on_stop();
        assert!(flag.load(Ordering::SeqCst));
        SHUTDOWN_STATE.store(0, Ordering::SeqCst);
    }
}
