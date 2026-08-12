use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use umc_metrics::Registry;

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

const PUBLIC_METRIC_NAMES: &[&str] = &[
    "sessions_active",
    "sessions_total",
    "handshake_failures",
    "resumption_sessions",
    "revocation_state_stale",
    "packets_received",
    "retransmissions",
    "path_degraded_events",
    "relay_circuits_opened",
    "relay_circuits_closed",
    "bundles_admitted",
    "bundles_expired",
    "route_requests_received",
    "control_requests_nodeadmin",
    "control_requests_peerservice",
    "control_requests_bundle",
    "control_requests_relay",
    "control_requests_session",
    "control_requests_route",
    "control_requests_config",
    "control_requests_diagnostics",
    "control_requests_identity",
    "control_requests_carrier",
    "control_requests_app",
    "control_requests_other",
];

/// Start the opt-in metrics listener. The task owns the listener and exits
/// when the Tokio runtime is shut down.
pub fn spawn(
    metrics: Arc<Registry>,
    bind: String,
    bearer_token: Option<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&bind).await {
            Ok(listener) => listener,
            Err(error) => {
                log::error!("[metrics] listener {bind} failed: {error}");
                return;
            }
        };
        log::info!("[metrics] endpoint listening on {bind}");
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    log::warn!("[metrics] accept failed: {error}");
                    continue;
                }
            };
            let metrics = metrics.clone();
            let token = bearer_token.clone();
            tokio::spawn(async move {
                let _ = serve_connection(stream, metrics, token).await;
            });
        }
    })
}

async fn serve_connection(
    mut stream: TcpStream,
    metrics: Arc<Registry>,
    bearer_token: Option<String>,
) -> Result<(), std::io::Error> {
    let mut request = vec![0_u8; MAX_REQUEST_BYTES];
    let mut bytes = 0;
    loop {
        let read = tokio::time::timeout(REQUEST_TIMEOUT, stream.read(&mut request[bytes..]))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "metrics request timeout")
            })??;
        if read == 0 {
            break;
        }
        bytes += read;
        if request[..bytes].windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if bytes == request.len() {
            break;
        }
    }
    let request = &request[..bytes];
    let authorized = match bearer_token.as_deref() {
        None => true,
        Some(token) => request_has_bearer(request, token),
    };
    let request_line = request
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let mut parts = request_line.split(|byte| *byte == b' ');
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let (status, content_type, body) = if method == b"GET" && path == b"/metrics" && authorized {
        ("200 OK", "text/plain; version=0.0.4", render_prometheus(&metrics))
    } else if method == b"GET" && path == b"/metrics" {
        (
            "401 Unauthorized",
            "text/plain; charset=utf-8",
            "unauthorized\n".to_string(),
        )
    } else {
        ("404 Not Found", "text/plain; charset=utf-8", "not found\n".to_string())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        if status == "401 Unauthorized" {
            "WWW-Authenticate: Bearer\r\n"
        } else {
            ""
        },
        body.len()
    );
    tokio::time::timeout(REQUEST_TIMEOUT, stream.write_all(response.as_bytes()))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "metrics response timeout"))??;
    Ok(())
}

fn request_has_bearer(request: &[u8], token: &str) -> bool {
    request.split(|byte| *byte == b'\n').any(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            return false;
        };
        let (name, value) = line.split_at(separator);
        let value = &value[1..];
        if !name.eq_ignore_ascii_case(b"Authorization") {
            return false;
        }
        let value = value.strip_prefix(b" ").unwrap_or(value);
        let expected = format!("Bearer {token}");
        constant_time_equal(value, expected.as_bytes())
    })
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(left.get(index).copied().unwrap_or_default())
            ^ usize::from(right.get(index).copied().unwrap_or_default());
    }
    difference == 0
}

fn render_prometheus(metrics: &Registry) -> String {
    let values = metrics.snapshot();
    let mut body = String::new();
    for name in PUBLIC_METRIC_NAMES {
        if let Some((_, value)) = values.iter().find(|(candidate, _)| candidate == name) {
            body.push_str("umc_");
            body.push_str(name);
            body.push(' ');
            body.push_str(&value.to_string());
            body.push('\n');
        }
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use umc_metrics::Registry;

    #[test]
    fn render_prometheus_exposes_only_bounded_public_series() {
        let metrics = Arc::new(Registry::new());
        metrics.incr("sessions_active", 2);
        metrics.incr("peer_secret_127_0_0_1", 9);

        let body = render_prometheus(&metrics);

        assert!(body.contains("umc_sessions_active 2"));
        assert!(!body.contains("peer_secret_127_0_0_1"));
        assert!(!body.contains('{'));
    }

    #[test]
    fn bearer_auth_is_case_insensitive_for_header_name_but_not_value() {
        let request = b"GET /metrics HTTP/1.1\r\naUtHoRiZaTiOn: Bearer secret\r\n\r\n";
        assert!(request_has_bearer(request, "secret"));
        assert!(!request_has_bearer(request, "secret2"));
    }

    #[test]
    fn constant_time_equal_checks_length_and_bytes() {
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"abd"));
        assert!(!constant_time_equal(b"abc", b"abcd"));
    }

    #[tokio::test]
    async fn http_endpoint_requires_bearer_for_remote_configuration() {
        let metrics = Arc::new(Registry::new());
        metrics.incr("sessions_total", 4);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection(stream, metrics, Some("secret".to_string())).await
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"umc_sessions_total 4\n"));
        task.await.unwrap().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let metrics = Arc::new(Registry::new());
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection(stream, metrics, Some("secret".to_string())).await
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
        assert!(response.windows(b"WWW-Authenticate: Bearer".len()).any(
            |window| window == b"WWW-Authenticate: Bearer"
        ));
        task.await.unwrap().unwrap();
    }
}
