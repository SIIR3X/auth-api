//! Tasks the service starts on behalf of a request (notifications, cache
//! invalidations), counted so that a shutdown waits for them to finish instead
//! of cutting them off with the process.

use std::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use tokio::sync::Notify;

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static FINISHED: Notify = Notify::const_new();

/// Run `future` in the background, counted until it completes or panics.
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
    metrics::gauge!("auth_background_tasks").increment(1.0);
    tokio::spawn(async move {
        let _done = Done;
        future.await;
    });
}

/// Tasks started and not finished yet.
pub fn in_flight() -> usize {
    IN_FLIGHT.load(Ordering::SeqCst)
}

/// Wait until every background task finished or `deadline` elapsed. Returns
/// how many were still running.
pub async fn drain(deadline: Duration) -> usize {
    let until = tokio::time::Instant::now() + deadline;
    loop {
        let finished = FINISHED.notified();
        tokio::pin!(finished);
        finished.as_mut().enable();

        let left = in_flight();
        if left == 0 {
            return 0;
        }
        if tokio::time::timeout_at(until, finished).await.is_err() {
            return in_flight();
        }
    }
}

/// Decrements the count when a task ends, panic included.
struct Done;

impl Drop for Done {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        metrics::gauge!("auth_background_tasks").decrement(1.0);
        FINISHED.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test: the count is process-wide.
    #[tokio::test(start_paused = true)]
    async fn a_drain_waits_for_running_tasks_up_to_its_deadline() {
        assert_eq!(
            drain(Duration::from_secs(1)).await,
            0,
            "nothing to wait for"
        );

        spawn(tokio::time::sleep(Duration::from_secs(2)));
        assert_eq!(in_flight(), 1);
        assert_eq!(drain(Duration::from_secs(5)).await, 0);

        spawn(tokio::time::sleep(Duration::from_secs(60)));
        assert_eq!(
            drain(Duration::from_secs(1)).await,
            1,
            "the deadline wins over a task that runs longer"
        );

        spawn(async { panic!("a failing notification") });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(in_flight(), 1, "a panicking task is not left counted");
    }
}
