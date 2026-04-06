// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::sync::atomic::{AtomicUsize, Ordering};

static ACTIVE_TASKS: AtomicUsize = AtomicUsize::new(0);

pub struct AsyncRuntime;

impl AsyncRuntime {
    /// Spawn a background task on a new OS thread
    pub fn spawn<F: FnOnce() + Send + 'static>(task: F) {
        ACTIVE_TASKS.fetch_add(1, Ordering::Relaxed);
        std::thread::spawn(move || {
            task();
            ACTIVE_TASKS.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// Spawn a named background task for debugging
    pub fn spawn_named<F: FnOnce() + Send + 'static>(name: &str, task: F) {
        let thread_name = name.to_string();
        ACTIVE_TASKS.fetch_add(1, Ordering::Relaxed);
        match std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                task();
                ACTIVE_TASKS.fetch_sub(1, Ordering::Relaxed);
            }) {
            Ok(_) => {},
            Err(e) => {
                eprintln!("[AsyncRuntime] Failed to spawn named thread: {}", e);
                ACTIVE_TASKS.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Block the current thread until all spawned tasks complete (with timeout)
    pub fn block_on() {
        let timeout = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();

        while ACTIVE_TASKS.load(Ordering::Relaxed) > 0 {
            if start.elapsed() > timeout {
                eprintln!("[AsyncRuntime] Timeout: {} tasks still active after {:?}",
                    ACTIVE_TASKS.load(Ordering::Relaxed), timeout);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Block with a custom timeout in seconds
    pub fn block_on_timeout(timeout_secs: u64) {
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let start = std::time::Instant::now();

        while ACTIVE_TASKS.load(Ordering::Relaxed) > 0 {
            if start.elapsed() > timeout {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Get the number of currently active tasks
    pub fn active_count() -> usize {
        ACTIVE_TASKS.load(Ordering::Relaxed)
    }
}
