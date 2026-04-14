// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::{slog_error, slog_warn};
use std::sync::atomic::{AtomicUsize, Ordering};

static ACTIVE_TASKS: AtomicUsize = AtomicUsize::new(0);

/// Drop guard that decrements ACTIVE_TASKS even if the task panics
struct TaskGuard;

impl Drop for TaskGuard {
    fn drop(&mut self) {
        ACTIVE_TASKS.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct AsyncRuntime;

impl AsyncRuntime {
    /// Spawn a background task on a new OS thread
    pub fn spawn<F: FnOnce() + Send + 'static>(task: F) {
        ACTIVE_TASKS.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let _guard = TaskGuard;
            task();
        });
    }

    /// Spawn a named background task for debugging
    pub fn spawn_named<F: FnOnce() + Send + 'static>(name: &str, task: F) {
        let thread_name = name.to_string();
        ACTIVE_TASKS.fetch_add(1, Ordering::SeqCst);
        match std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let _guard = TaskGuard;
                task();
            }) {
            Ok(_) => {}
            Err(e) => {
                slog_error!("runtime", "spawn_named_thread_failed", error => &e.to_string());
                ACTIVE_TASKS.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    /// Block the current thread until all spawned tasks complete (with timeout)
    pub fn block_on() {
        let timeout = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();

        while ACTIVE_TASKS.load(Ordering::SeqCst) > 0 {
            if start.elapsed() > timeout {
                slog_warn!("runtime", "async_runtime_timeout", active_tasks => &ACTIVE_TASKS.load(Ordering::SeqCst).to_string());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Block with a custom timeout in seconds
    pub fn block_on_timeout(timeout_secs: u64) {
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let start = std::time::Instant::now();

        while ACTIVE_TASKS.load(Ordering::SeqCst) > 0 {
            if start.elapsed() > timeout {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Get the number of currently active tasks
    pub fn active_count() -> usize {
        ACTIVE_TASKS.load(Ordering::SeqCst)
    }
}
