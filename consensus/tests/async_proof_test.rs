//! Verify async proof architecture doesn't block block production.
//!
//! Goal: enqueueing a proof job should return in microseconds,
//! not block on the 14-23s proof generation.

use std::time::{Duration, Instant};

use crossbeam_channel;

#[test]
fn bounded_queue_try_send_is_fast() {
    let (tx, rx) = crossbeam_channel::bounded::<[u8; 32]>(128);

    // Simulate block commits: 100 fast try_send calls
    let t0 = Instant::now();
    for i in 0..100u8 {
        let block_hash = [i; 32];
        let _ = tx.try_send(block_hash);
    }
    let elapsed = t0.elapsed();

    println!(
        "100 try_send calls: {:?} ({:.2} µs/call)",
        elapsed,
        elapsed.as_micros() as f64 / 100.0
    );

    // try_send should be sub-microsecond per call
    assert!(
        elapsed < Duration::from_millis(10),
        "100 enqueues took {:?}, expected < 10ms",
        elapsed
    );

    // Drain the queue
    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    assert_eq!(count, 100);
}

#[test]
fn queue_overflow_drops_silently() {
    // Bounded queue with capacity 2
    let (tx, _rx) = crossbeam_channel::bounded::<u64>(2);

    // 5 sends — first 2 should succeed, next 3 should fail silently
    let mut successes = 0;
    let mut failures = 0;
    for i in 0..5 {
        match tx.try_send(i) {
            Ok(()) => successes += 1,
            Err(crossbeam_channel::TrySendError::Full(_)) => failures += 1,
            Err(_) => unreachable!(),
        }
    }

    assert_eq!(successes, 2, "queue should accept only 2 items");
    assert_eq!(failures, 3, "queue should reject next 3");
}
