// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Runtime deadlock detection.
//!
//! Built only under the `deadlock-detect` feature. `parking_lot`'s detector
//! needs per-acquisition bookkeeping, so it stays out of a normal build.
//!
//! Why this exists: in August 2026 two testnet followers wedged with 78 of 84
//! threads parked on futexes at 0% CPU. They stayed that way until October. The
//! chain was fine — identical hashes on every node — but neither follower could
//! sync. The release profile sets `strip = "symbols"`, so attaching gdb to the
//! live process resolved libc frames and no Rust ones, and the lock could not
//! be named from a core dump either. A static read of every global lock in the
//! p2p layer found the ordering discipline there to be correct, which left the
//! search space as "every struct-field lock in the tree".
//!
//! The answer is to make the node report it. Enable the feature, reproduce the
//! wedge, and the log names the threads in the cycle and where each one is
//! blocked.

/// How often to look for a cycle. Deadlocks are permanent, so polling slowly
/// is enough and keeps the cost negligible.
#[cfg(feature = "deadlock-detect")]
const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawn the detector thread. Call once during startup; calling it again would
/// only add a second poller, so it is a no-op to guard against that.
#[cfg(feature = "deadlock-detect")]
pub fn spawn() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::slog_warn!("diag", "deadlock_detector_enabled",
        interval_secs => CHECK_INTERVAL.as_secs(),
        note => "diagnostic build: lock bookkeeping is active, do not run this as a release node");

    std::thread::Builder::new()
        .name("deadlock-watch".to_string())
        .spawn(|| loop {
            std::thread::sleep(CHECK_INTERVAL);
            let cycles = parking_lot::deadlock::check_deadlock();
            if cycles.is_empty() {
                continue;
            }
            // A cycle is permanent: report every one, every time, so the
            // operator sees it in whatever log window they happen to have.
            crate::slog_error!("diag", "DEADLOCK_DETECTED",
                cycles => cycles.len());
            for (i, threads) in cycles.iter().enumerate() {
                for t in threads {
                    crate::slog_error!("diag", "deadlock_thread",
                        cycle => i,
                        thread_id => &format!("{:?}", t.thread_id()),
                        backtrace => &format!("{:?}", t.backtrace()));
                }
            }
        })
        .ok();
}

/// No-op in a normal build, so callers need no `cfg`.
#[cfg(not(feature = "deadlock-detect"))]
pub fn spawn() {}

#[cfg(all(test, feature = "deadlock-detect"))]
mod tests {
    /// Local reproduction: build a real lock-order inversion and confirm the
    /// detector names it. Without this the detector is an untested claim — the
    /// whole point is that it must work the one time a node wedges.
    ///
    /// The two worker threads deadlock permanently and are deliberately never
    /// joined; they hold only these two mutexes, and the test process exits
    /// normally around them.
    /// Negative control. A detector that always fires is worthless, so prove
    /// it stays silent while locks are merely contended rather than cyclic.
    /// Runs before the inversion test leaks its two stuck threads, since a
    /// reported cycle would otherwise make this assertion meaningless.
    #[test]
    fn detector_stays_silent_under_ordinary_contention() {
        use parking_lot::Mutex;
        use std::sync::Arc;

        let m = Arc::new(Mutex::new(0u64));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = Arc::clone(&m);
            handles.push(std::thread::spawn(move || {
                for _ in 0..2_000 {
                    *m.lock() += 1;
                }
            }));
        }
        for h in handles {
            h.join().expect("contended workers must finish, not wedge");
        }
        assert_eq!(*m.lock(), 16_000);
        assert!(
            parking_lot::deadlock::check_deadlock().is_empty(),
            "contention is not a deadlock — a detector that fires here is useless"
        );
    }

    #[test]
    fn detector_reports_a_real_lock_order_inversion() {
        use parking_lot::Mutex;
        use std::sync::Arc;
        use std::time::Duration;

        let a = Arc::new(Mutex::new(0u8));
        let b = Arc::new(Mutex::new(0u8));

        // A then B.
        let (a1, b1) = (Arc::clone(&a), Arc::clone(&b));
        std::thread::spawn(move || {
            let _g = a1.lock();
            std::thread::sleep(Duration::from_millis(300));
            let _h = b1.lock();
        });

        // B then A — the inversion.
        let (a2, b2) = (Arc::clone(&a), Arc::clone(&b));
        std::thread::spawn(move || {
            let _g = b2.lock();
            std::thread::sleep(Duration::from_millis(300));
            let _h = a2.lock();
        });

        // Both are blocked well before this elapses.
        std::thread::sleep(Duration::from_secs(2));

        let cycles = parking_lot::deadlock::check_deadlock();
        assert!(
            !cycles.is_empty(),
            "the detector must report the cycle it was built to find"
        );
        let threads_in_cycle: usize = cycles.iter().map(|c| c.len()).sum();
        assert!(
            threads_in_cycle >= 2,
            "a two-thread inversion must name both threads, got {}",
            threads_in_cycle
        );
    }
}
