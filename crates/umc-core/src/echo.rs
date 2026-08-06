//! The echo application (core.md §9.6): the daemon's reference application.
//! It consumes stream frames from its application channel and writes the
//! same bytes back on the same stream IDs, proving the session -> app ->
//! session path end to end.
use crate::app_io::{AppRx, AppTx};

/// Run the echo application: every stream frame received on `rx` is sent
/// back on `tx` with the same stream ID and bytes. Returns when `rx`
/// closes.
///
/// `tx` is the application's outbound channel, drained by the daemon's
/// session writer; the echo loop itself is pure plumbing and does not know
/// which session produced the frame (multi-session routing lands in Phase
/// 10+).
pub async fn echo_loop(rx: &mut AppRx, tx: &AppTx) {
    while let Some((stream_id, data)) = rx.recv_stream_frame().await {
        if tx.send_stream_frame(stream_id, data).await.is_err() {
            break;
        }
    }
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
    fn echo_loop_reflects_frames_on_same_stream() {
        let rt = runtime();
        let (in_tx, mut in_rx) = crate::app_io::spawn_app_channel(4);
        let (out_tx, mut out_rx) = crate::app_io::spawn_app_channel(4);
        rt.block_on(async {
            let loop_task = tokio::spawn(async move {
                echo_loop(&mut in_rx, &out_tx).await;
            });
            in_tx
                .send_stream_frame(7, b"hello echo".to_vec())
                .await
                .expect("send");
            let (stream_id, data) = out_rx.recv_stream_frame().await.expect("recv");
            assert_eq!(stream_id, 7, "echo must keep the stream ID");
            assert_eq!(data, b"hello echo");
            drop(in_tx);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                loop_task.is_finished(),
                "echo loop must exit once the inbound channel closes"
            );
        });
    }
}
