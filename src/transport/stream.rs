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

use crate::transport::TransportAddr;

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

/// Remove the entry at `addr`, but only if it is connection `id`.
///
/// This is the only way a connection's own writer or receive loop removes a
/// pool entry. An entry with another id belongs to a newer connection at the
/// same address, and is left alone.
pub(crate) fn remove_own<C: PooledConn>(
    pool: &mut HashMap<TransportAddr, C>,
    addr: &TransportAddr,
    id: ConnId,
) -> Option<C> {
    if pool.get(addr)?.conn_id() != id {
        return None;
    }
    pool.remove(addr)
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
}
