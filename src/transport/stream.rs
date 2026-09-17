//! Connection lifecycle rules shared by the stream transports.
//!
//! TCP and the SOCKS5-proxied Tor and Nym transports each give a pooled
//! connection its own writer task and receive loop, and either loop can
//! outlive the pool entry it was created with. The rules for when such a loop
//! may touch the pool are written once here.

use std::collections::HashMap;
use std::time::Duration;

use portable_atomic::{AtomicU64, Ordering};
use tokio::task::JoinHandle;

/// Identity of one pooled stream connection.
///
/// The pool is keyed by address, and a newer connection can take an address
/// while an older connection's writer or receive loop is still running. The
/// id tells the two apart.
pub(crate) type ConnId = u64;

/// Source of connection ids. Process-wide rather than per transport, because
/// the accept loops that build connections are free functions with no
/// transport instance to hold a counter.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Hand out an id no other connection in this process has had.
pub(crate) fn next_conn_id() -> ConnId {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

/// A pooled stream connection that knows its own [`ConnId`].
pub(crate) trait PooledConn {
    /// The id this connection's writer and receive loop were given.
    fn conn_id(&self) -> ConnId;
}

/// Remove the entry at `key`, but only if it is connection `id`.
///
/// This is the only way a connection's own writer or receive loop removes a
/// pool entry. An entry with another id belongs to a newer connection under
/// the same key, and is left alone.
///
/// The key type is the pool's own: a transport that pools by peer address
/// passes a `TransportAddr`, and one that pools by four-tuple passes its own
/// key. The identity check is the same either way, and it stays necessary
/// after a key is made more specific, because a peer can still reconnect on
/// the same four-tuple.
pub(crate) fn remove_own<K, C>(pool: &mut HashMap<K, C>, key: &K, id: ConnId) -> Option<C>
where
    K: std::hash::Hash + Eq,
    C: PooledConn,
{
    if pool.get(key)?.conn_id() != id {
        return None;
    }
    pool.remove(key)
}

/// How long a deliberately closed connection's writer may keep writing the
/// frames already queued before it is stopped.
///
/// It bounds only how long the socket and the writer task outlive the close;
/// no caller waits on it. A peer that is still reading drains a full queue in
/// far less, and one that has not drained it by then has stopped reading.
pub(crate) const WRITER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Let a closed connection's writer finish the frames already queued, and stop
/// it if it is still running after `bound`.
///
/// The caller must already have dropped the connection's queue, so the writer
/// exits once it has written what was queued. The wait runs on its own task,
/// which ends as soon as the writer does; the returned handle is that task's.
pub(crate) fn drain_writer(send_task: JoinHandle<()>, bound: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut send_task = send_task;
        if tokio::time::timeout(bound, &mut send_task).await.is_err() {
            send_task.abort();
        }
    })
}

/// How long a filled send queue must stay full, with nothing sending, before a
/// test treats its writer as parked.
#[cfg(test)]
pub(crate) const PARK_SETTLE: Duration = Duration::from_millis(300);

/// How many settle intervals a test waits for its writer to stay parked.
#[cfg(test)]
pub(crate) const PARK_ROUNDS: usize = 10;

/// Fill a connection's send queue behind a peer that does not read, until the
/// writer is parked in `write_all`, and return how many frames were queued.
///
/// `offer` tries to queue one frame and says whether it was accepted;
/// `capacity` reads the queue's free slots, `None` if the connection is gone.
/// Every one of 8000 offers is made whatever the previous one returned, with a
/// yield between them so the writer runs. Then the queue must read full after
/// a settle interval with nothing sending. Free capacity only grows while
/// nothing sends, so a full reading means the writer took no frame for the
/// whole interval, which it can do only while blocked in `write_all`.
///
/// A queue that is not full is topped up and the interval repeated, because a
/// late ACK can free send-buffer space after the fill ends and let the writer
/// take a few frames before it parks again; FreeBSD delays that ACK on
/// loopback. A writer that never stays parked for a whole interval panics.
#[cfg(test)]
pub(crate) async fn park_writer(
    mut offer: impl AsyncFnMut() -> bool,
    mut capacity: impl AsyncFnMut() -> Option<usize>,
) -> usize {
    let mut queued = 0usize;
    let mut refused = 0usize;
    for _ in 0..8000 {
        if offer().await {
            queued += 1;
        } else {
            refused += 1;
        }
        tokio::task::yield_now().await;
    }
    let mut seen = Vec::with_capacity(PARK_ROUNDS);
    for _ in 0..PARK_ROUNDS {
        tokio::time::sleep(PARK_SETTLE).await;
        let free = capacity().await;
        seen.push(free);
        match free {
            Some(0) => {
                assert!(refused > 0, "setup never filled the queue: queued={queued}");
                return queued;
            }
            Some(n) => {
                for _ in 0..=n {
                    if !offer().await {
                        break;
                    }
                    queued += 1;
                }
            }
            None => break,
        }
    }
    panic!(
        "setup did not park the writer: queued={queued} refused={refused} \
         capacity after each settle={seen:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer still running when the bound expires is stopped, and the
    /// timer ends with it.
    ///
    /// The writer holds a oneshot sender and never finishes, so the sender is
    /// dropped only if the task is aborted.
    #[tokio::test]
    async fn drain_writer_aborts_a_writer_that_outlives_the_bound() {
        let (guard_tx, guard_rx) = tokio::sync::oneshot::channel::<()>();
        let writer = tokio::spawn(async move {
            let _guard = guard_tx;
            std::future::pending::<()>().await
        });

        let timer = drain_writer(writer, Duration::from_millis(50));
        assert!(
            matches!(
                tokio::time::timeout(Duration::from_secs(1), guard_rx).await,
                Ok(Err(_))
            ),
            "a writer still running at the bound was left running"
        );
        tokio::time::timeout(Duration::from_secs(1), timer)
            .await
            .expect("the drain timer outlived the writer it stopped")
            .unwrap();
    }

    /// The wait ends when the writer does, not when the bound expires.
    #[tokio::test]
    async fn drain_writer_ends_as_soon_as_the_writer_does() {
        let writer = tokio::spawn(async {});
        let timer = drain_writer(writer, Duration::from_secs(30));
        tokio::time::timeout(Duration::from_millis(100), timer)
            .await
            .expect("the drain timer kept running after the writer exited")
            .unwrap();
    }

    /// Depth of the modelled send queue in the `park_writer` tests.
    const MODEL_DEPTH: usize = 4;

    /// A queue a late ACK drained after the fill is topped up, and the helper
    /// returns at the first settle that finds it still full.
    ///
    /// The first capacity read drains 2 frames and later reads drain none, so
    /// the fill queues 4, the top-up queues 2 more, and the second read ends
    /// the wait.
    #[tokio::test(start_paused = true)]
    async fn park_writer_tops_up_a_queue_a_late_ack_drained_and_returns_once_it_stays_full() {
        let len = std::cell::Cell::new(0usize);
        let drain = std::cell::Cell::new(2usize);
        let calls = std::cell::Cell::new(0usize);
        let queued = park_writer(
            async || {
                let accept = len.get() < MODEL_DEPTH;
                if accept {
                    len.set(len.get() + 1);
                }
                accept
            },
            async || {
                calls.set(calls.get() + 1);
                len.set(len.get().saturating_sub(drain.take()));
                Some(MODEL_DEPTH - len.get())
            },
        )
        .await;
        assert_eq!(queued, 6, "fill of 4 plus a top-up of 2");
        assert_eq!(
            calls.get(),
            2,
            "the second settle should find the queue full"
        );
    }

    /// A writer that takes a frame in every settle interval never counts as
    /// parked.
    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "setup did not park the writer")]
    async fn park_writer_panics_when_the_writer_takes_a_frame_in_every_settle() {
        let len = std::cell::Cell::new(0usize);
        let drain = std::cell::Cell::new(1usize);
        park_writer(
            async || {
                let accept = len.get() < MODEL_DEPTH;
                if accept {
                    len.set(len.get() + 1);
                }
                accept
            },
            async || {
                len.set(len.get().saturating_sub(drain.get()));
                Some(MODEL_DEPTH - len.get())
            },
        )
        .await;
    }

    /// A connection that is gone by the settle check never counts as parked.
    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "setup did not park the writer")]
    async fn park_writer_panics_when_the_connection_is_gone() {
        let len = std::cell::Cell::new(0usize);
        park_writer(
            async || {
                let accept = len.get() < MODEL_DEPTH;
                if accept {
                    len.set(len.get() + 1);
                }
                accept
            },
            async || None,
        )
        .await;
    }
}
