//! Per-application stream channels (core.md §9.6): the daemon creates one
//! channel per registered application; the session task forwards received
//! stream data to the application's channel when the stream's protocol ID
//! matches. The echo application consumes its channel and writes echoes back
//! on the same stream IDs.
use tokio::sync::mpsc;

/// A stream frame forwarded between the session layer and an application:
/// the stream ID the data arrived on and the bytes.
pub type StreamData = (u64, Vec<u8>);

/// Sender side of a per-application stream channel; cloneable so several
/// session tasks can forward into the same application.
#[derive(Debug, Clone)]
pub struct AppTx {
    tx: mpsc::Sender<StreamData>,
}

/// Receiver side of a per-application stream channel.
#[derive(Debug)]
pub struct AppRx {
    rx: mpsc::Receiver<StreamData>,
}

impl AppTx {
    /// Queue a stream frame for the application; awaits when the bounded
    /// channel is full (backpressure toward the session layer).
    ///
    /// # Errors
    ///
    /// Returns a [`mpsc::error::SendError`] when the application's receiver
    /// has closed.
    pub async fn send_stream_frame(
        &self,
        stream_id: u64,
        data: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<StreamData>> {
        self.tx.send((stream_id, data)).await
    }

    /// Non-blocking send; used by tests to observe the bounded channel.
    ///
    /// # Errors
    ///
    /// Returns a [`mpsc::error::TrySendError`] when the channel is full or
    /// closed.
    pub fn try_send_stream_frame(
        &self,
        stream_id: u64,
        data: Vec<u8>,
    ) -> Result<(), mpsc::error::TrySendError<StreamData>> {
        self.tx.try_send((stream_id, data))
    }
}

impl AppRx {
    /// Receive the next stream frame; `None` when every sender has closed.
    pub async fn recv_stream_frame(&mut self) -> Option<StreamData> {
        self.rx.recv().await
    }

    /// Non-blocking receive; used by the daemon's session writer to drain
    /// application echoes without waiting on the link.
    ///
    /// # Errors
    ///
    /// Returns [`mpsc::error::TryRecvError::Empty`] when no frame is queued
    /// and [`mpsc::error::TryRecvError::Disconnected`] when every sender has
    /// closed.
    pub fn try_recv_stream_frame(&mut self) -> Result<StreamData, mpsc::error::TryRecvError> {
        self.rx.try_recv()
    }
}

/// Create a per-application channel pair with `buffer` slots.
#[must_use]
pub fn spawn_app_channel(buffer: usize) -> (AppTx, AppRx) {
    let (tx, rx) = mpsc::channel(buffer);
    (AppTx { tx }, AppRx { rx })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    #[test]
    fn stream_frame_round_trip() {
        let rt = runtime();
        let (tx, mut rx) = spawn_app_channel(4);
        rt.block_on(async {
            tx.send_stream_frame(3, b"ping".to_vec())
                .await
                .expect("send");
            let (stream_id, data) = rx.recv_stream_frame().await.expect("recv");
            assert_eq!(stream_id, 3);
            assert_eq!(data, b"ping");
        });
    }

    #[test]
    fn recv_blocks_when_empty() {
        let rt = runtime();
        let (tx, mut rx) = spawn_app_channel(4);
        rt.block_on(async {
            assert_eq!(
                rx.try_recv_stream_frame(),
                Err(mpsc::error::TryRecvError::Empty),
                "empty channel must not yield a frame"
            );
            tx.send_stream_frame(0, b"x".to_vec()).await.expect("send");
            assert!(rx.recv_stream_frame().await.is_some());
            assert_eq!(
                rx.try_recv_stream_frame(),
                Err(mpsc::error::TryRecvError::Empty)
            );
        });
    }

    #[test]
    fn bounded_channel_backpressures() {
        let (tx, rx) = spawn_app_channel(1);
        tx.try_send_stream_frame(0, b"first".to_vec())
            .expect("slot 1");
        assert!(
            tx.try_send_stream_frame(0, b"second".to_vec()).is_err(),
            "full channel must reject a second frame"
        );
        drop(rx);
        assert!(
            tx.try_send_stream_frame(0, b"third".to_vec()).is_err(),
            "closed channel must reject"
        );
    }

    #[test]
    fn recv_returns_none_after_close() {
        let rt = runtime();
        let (tx, mut rx) = spawn_app_channel(1);
        rt.block_on(async {
            drop(tx);
            assert!(rx.recv_stream_frame().await.is_none());
        });
    }
}
