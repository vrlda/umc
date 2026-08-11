//! umc CLI (core.md §44): control and diagnostics client.
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use prost::Message;
use umc_control::proto::umc::api::v1 as api;
use umc_sdk::config::ConfigClient;
use umc_sdk::daemon::DaemonClient;
use umc_sdk::status::StatusClient;

#[cfg(unix)]
const DEFAULT_SOCKET: &str = "~/.local/run/umc.sock";
#[cfg(windows)]
const DEFAULT_SOCKET: &str = r"\\.\pipe\umc";
#[cfg(not(any(unix, windows)))]
const DEFAULT_SOCKET: &str = "~/.local/run/umc.sock";
const CLIENT_NAME: &str = "umc-cli";

/// The default node data directory, mirroring `umcd`'s `NodeConfig` default
/// (bins/umcd/src/config.rs).
const DEFAULT_DATA_DIR: &str = "~/.local/share/umc";

/// The default config `umc init` writes (mirroring `umcd --init`, core.md
/// §19): the documented keys with conservative defaults. Written only when
/// no config file exists; the daemon's `NodeConfig::load` accepts it as-is.
#[cfg(unix)]
const DEFAULT_CONFIG_JSON: &str = r#"{
  "data_dir": "~/.local/share/umc",
  "control_socket": "~/.local/run/umc.sock",
  "profile": "standard",
  "carriers": ["ump.tcp/1", "ump.udp/1"],
  "mesh": false,
  "keystore": null,
  "public_relay": false,
  "telemetry_enabled": false,
  "development_token": null
}
"#;

#[cfg(windows)]
const DEFAULT_CONFIG_JSON: &str = r#"{
  "data_dir": "~/.local/share/umc",
  "control_socket": "\\\\.\\pipe\\umc",
  "profile": "standard",
  "carriers": ["ump.tcp/1", "ump.udp/1"],
  "mesh": false,
  "keystore": null,
  "public_relay": false,
  "telemetry_enabled": false,
  "development_token": null
}
"#;

#[cfg(not(any(unix, windows)))]
const DEFAULT_CONFIG_JSON: &str = r#"{
  "data_dir": "~/.local/share/umc",
  "control_socket": "~/.local/run/umc.sock",
  "profile": "standard",
  "carriers": ["ump.tcp/1", "ump.udp/1"],
  "mesh": false,
  "keystore": null,
  "public_relay": false,
  "telemetry_enabled": false,
  "development_token": null
}
"#;

#[derive(Parser)]
#[command(name = "umc", about = "Universal Mesh Core control client")]
struct Cli {
    /// Control socket path.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Node status.
    Status,
    /// Node configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Recent daemon events, newest first.
    Events,
    /// List identities.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Run diagnostics over the control socket.
    Doctor,
    /// Initialize the node data dir, keystore dir, and default config file.
    Init {
        /// Config file to write; defaults to `<data_dir>/node.json`.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// List live sessions.
    Sessions {
        #[command(subcommand)]
        action: SessionsAction,
    },
    /// List learned routes.
    Routes {
        #[command(subcommand)]
        action: RoutesAction,
    },
    /// List known peers.
    Peers {
        #[command(subcommand)]
        action: PeersAction,
    },
    /// Invitation lifecycle.
    Invite {
        #[command(subcommand)]
        action: InviteAction,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Print config entries.
    Get,
    /// Set config entries (key=value).
    Set { entries: Vec<String> },
}

#[derive(Debug, Subcommand)]
enum IdentityAction {
    List,
}

#[derive(Debug, Subcommand)]
enum SessionsAction {
    List,
}

#[derive(Debug, Subcommand)]
enum RoutesAction {
    List,
}

#[derive(Debug, Subcommand)]
enum PeersAction {
    List,
    /// Add an operator-supplied connection hint.
    Add {
        endpoint_id: String,
        carrier: String,
        address: String,
        #[arg(long)]
        expires_at_unix_ms: Option<i64>,
        #[arg(long)]
        do_not_reshare: bool,
    },
    /// Remove a peer and its persisted hints.
    Remove {
        endpoint_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum InviteAction {
    /// Create an invitation; returned values are hex for piping to import.
    Create {
        #[arg(long = "endpoint-id")]
        endpoint_ids: Vec<String>,
        #[arg(long)]
        expires_at_unix_ms: i64,
        #[arg(long, default_value_t = 1)]
        maximum_uses: u64,
    },
    /// Import an invitation document and secret encoded as hex.
    Import { document: String, secret: String },
    /// Revoke an invitation id encoded as hex.
    Revoke {
        invitation_id: String,
        #[arg(long, default_value = "cli revoke")]
        reason: String,
    },
}

async fn cmd_status(socket: &str) -> Result<Vec<String>, String> {
    let mut client = StatusClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("status: {e:?}"))?;
    let status = client
        .get_status()
        .await
        .map_err(|e| format!("status: {e:?}"))?;
    Ok(vec![
        "node reachable".to_string(),
        format!("uptime: {} ms", status.uptime_ms),
        format!("sessions: {}", status.active_sessions),
        format!("links: {}", status.active_links),
        format!("relay circuits: {}", status.active_relay_circuits),
        format!("started at: {} ms", status.started_at_unix_ms),
    ])
}

async fn cmd_config_get(socket: &str) -> Result<Vec<String>, String> {
    let mut client = ConfigClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("config: {e:?}"))?;
    let entries = client
        .get_config()
        .await
        .map_err(|e| format!("config: {e:?}"))?;
    let mut keys: Vec<&String> = entries.keys().collect();
    keys.sort();
    Ok(keys
        .into_iter()
        .map(|key| format!("{key}={}", entries[key]))
        .collect())
}

async fn cmd_config_set(socket: &str, entries: Vec<String>) -> Result<Vec<String>, String> {
    let mut map = HashMap::new();
    for entry in entries {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(format!(
                "config: invalid entry (expected key=value): {entry}"
            ));
        };
        map.insert(key.to_string(), value.to_string());
    }
    let mut client = ConfigClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("config: {e:?}"))?;
    match client.set_config(map).await {
        Ok(()) => Ok(vec!["config updated".to_string()]),
        Err(e) => Err(format!("config: {e:?}")),
    }
}

async fn cmd_events(socket: &str) -> Result<Vec<String>, String> {
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("events: {e:?}"))?;
    let (code, payload) = daemon
        .request_raw("NodeAdmin", "GetEvents", Vec::new())
        .await
        .map_err(|e| format!("events: {e:?}"))?;
    if code != api::StatusCode::Ok as i32 {
        return Err(format!("events: status {code}"));
    }
    let response = api::GetEventsResponse::decode(payload.as_slice())
        .map_err(|e| format!("events: decode failed: {e}"))?;
    if response.events.is_empty() {
        return Ok(vec!["no recent events".to_string()]);
    }
    Ok(response
        .events
        .into_iter()
        .map(|event| format!("{} {} {}", event.at_ms, event.kind, event.detail))
        .collect())
}

async fn cmd_identity(socket: &str) -> Result<Vec<String>, String> {
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("identity: {e:?}"))?;
    match daemon
        .request_raw("IdentityService", "ListIdentities", Vec::new())
        .await
    {
        Ok((code, _)) if code == api::StatusCode::Ok as i32 => {
            Ok(vec!["identity list (Phase 2 minimal)".to_string()])
        }
        Ok((code, _)) => Err(format!("identity: status {code}")),
        Err(e) => Err(format!("identity: {e:?}")),
    }
}

/// `DiagnosticsService.RunDoctor` over the control socket (core.md §43):
/// one line per check.
async fn cmd_doctor(socket: &str) -> Result<Vec<String>, String> {
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("doctor: {e:?}"))?;
    let (code, payload) = daemon
        .request_raw("DiagnosticsService", "RunDoctor", Vec::new())
        .await
        .map_err(|e| format!("doctor: {e:?}"))?;
    if code != api::StatusCode::Ok as i32 {
        return Err(format!("doctor: status {code}"));
    }
    let response = api::RunDoctorResponse::decode(payload.as_slice())
        .map_err(|e| format!("doctor: decode failed: {e}"))?;
    if response.results.is_empty() {
        return Ok(vec!["doctor: no checks reported".to_string()]);
    }
    Ok(response
        .results
        .into_iter()
        .map(|result| {
            let severity = api::DiagnosticSeverity::try_from(result.severity).map_or_else(
                |_| result.severity.to_string(),
                |s| s.as_str_name().to_string(),
            );
            format!("{}: {severity} {}", result.check_id, result.detail)
        })
        .collect())
}

/// `SessionService.ListSessions`: one line per live session. The peer
/// endpoint id is redacted (privacy.md §37).
async fn cmd_sessions_list(socket: &str) -> Result<Vec<String>, String> {
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("sessions: {e:?}"))?;
    let (code, payload) = daemon
        .request_raw("SessionService", "ListSessions", Vec::new())
        .await
        .map_err(|e| format!("sessions: {e:?}"))?;
    if code != api::StatusCode::Ok as i32 {
        return Err(format!("sessions: status {code}"));
    }
    let response = api::ListSessionsResponse::decode(payload.as_slice())
        .map_err(|e| format!("sessions: decode failed: {e}"))?;
    if response.sessions.is_empty() {
        return Ok(vec!["no sessions".to_string()]);
    }
    Ok(response
        .sessions
        .into_iter()
        .map(|session| {
            let id = session
                .session_handle
                .as_ref()
                .map_or_else(|| "?".to_string(), |handle| hex_id(&handle.value));
            format!(
                "session id={id} peer={} carrier={} established={}",
                redact_id(&session.remote_endpoint_id),
                session.protocol_id,
                session.created_at_unix_ms
            )
        })
        .collect())
}

/// `RouteService.ListRoutes`: one line per learned route.
async fn cmd_routes_list(socket: &str) -> Result<Vec<String>, String> {
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("routes: {e:?}"))?;
    let (code, payload) = daemon
        .request_raw("RouteService", "ListRoutes", Vec::new())
        .await
        .map_err(|e| format!("routes: {e:?}"))?;
    if code != api::StatusCode::Ok as i32 {
        return Err(format!("routes: status {code}"));
    }
    let response = api::ListRoutesResponse::decode(payload.as_slice())
        .map_err(|e| format!("routes: decode failed: {e}"))?;
    if response.routes.is_empty() {
        return Ok(vec!["no routes".to_string()]);
    }
    Ok(response
        .routes
        .into_iter()
        .map(|route| {
            let scope = api::RouteScope::try_from(route.scope)
                .map_or_else(|_| route.scope.to_string(), |s| s.as_str_name().to_string());
            format!(
                "route dest={} scope={} next={} state={} expires={}",
                redact_id(&route.destination_hint_hash),
                scope,
                route.carrier_class,
                route.state,
                route.expires_at_unix_ms
            )
        })
        .collect())
}

/// `PeerService.ListPeers`: one line per known peer.
async fn cmd_peers_list(socket: &str) -> Result<Vec<String>, String> {
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("peers: {e:?}"))?;
    let (code, payload) = daemon
        .request_raw("PeerService", "ListPeers", Vec::new())
        .await
        .map_err(|e| format!("peers: {e:?}"))?;
    if code != api::StatusCode::Ok as i32 {
        return Err(format!("peers: status {code}"));
    }
    let response = api::ListPeersResponse::decode(payload.as_slice())
        .map_err(|e| format!("peers: decode failed: {e}"))?;
    if response.peers.is_empty() {
        return Ok(vec!["no peers".to_string()]);
    }
    Ok(response
        .peers
        .into_iter()
        .map(|peer| {
            let trust = api::TrustState::try_from(peer.trust_state).map_or_else(
                |_| peer.trust_state.to_string(),
                |s| s.as_str_name().to_string(),
            );
            format!(
                "peer={} label={} trust={} last_seen={}",
                redact_id(&peer.endpoint_id),
                peer.label,
                trust,
                peer.last_seen_unix_ms
            )
        })
        .collect())
}

async fn cmd_peers_add(
    socket: &str,
    endpoint_id: String,
    carrier: String,
    address: String,
    expires_at_unix_ms: Option<i64>,
    do_not_reshare: bool,
) -> Result<Vec<String>, String> {
    let endpoint_id = decode_hex(&endpoint_id)?;
    let expires_at_unix_ms = expires_at_unix_ms.unwrap_or_else(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
            });
        now.saturating_add(24 * 60 * 60 * 1_000)
    });
    let request = api::AddPeerHintRequest {
        endpoint_id,
        hint: Some(api::PeerHint {
            carrier_type_id: carrier,
            connection_hint: address.into_bytes(),
            expires_at_unix_ms,
            source: "cli".into(),
            do_not_reshare,
        }),
    };
    let mut payload = Vec::new();
    Message::encode(&request, &mut payload).map_err(|e| format!("peers add: encode: {e}"))?;
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("peers add: {e:?}"))?;
    let (code, response_payload) = daemon
        .request_raw("PeerService", "AddPeerHint", payload)
        .await
        .map_err(|e| format!("peers add: {e:?}"))?;
    if code != api::StatusCode::Ok as i32 {
        return Err(format!("peers add: status {code}"));
    }
    let response = api::AddPeerHintResponse::decode(response_payload.as_slice())
        .map_err(|e| format!("peers add: decode: {e}"))?;
    Ok(vec![format!(
        "peer added: {}",
        response
            .peer
            .map_or_else(|| "unknown".into(), |peer| hex_id(&peer.endpoint_id))
    )])
}

async fn cmd_peers_remove(socket: &str, endpoint_id: String) -> Result<Vec<String>, String> {
    let request = api::RemovePeerRequest {
        endpoint_id: decode_hex(&endpoint_id)?,
        expected_revision: None,
    };
    let mut payload = Vec::new();
    Message::encode(&request, &mut payload).map_err(|e| format!("peers remove: encode: {e}"))?;
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("peers remove: {e:?}"))?;
    let (code, _) = daemon
        .request_raw("PeerService", "RemovePeer", payload)
        .await
        .map_err(|e| format!("peers remove: {e:?}"))?;
    if code != api::StatusCode::Ok as i32 {
        return Err(format!("peers remove: status {code}"));
    }
    Ok(vec!["peer removed".into()])
}

async fn cmd_invite_create(
    socket: &str,
    endpoint_ids: Vec<String>,
    expires_at_unix_ms: i64,
    maximum_uses: u64,
) -> Result<Vec<String>, String> {
    let endpoint_ids = endpoint_ids
        .into_iter()
        .map(|id| decode_hex(&id))
        .collect::<Result<Vec<_>, _>>()?;
    let request = api::CreateInvitationRequest {
        identity_handle: None,
        scope: Some(api::InvitationScope {
            endpoint_ids,
            protocol_ids: Vec::new(),
            allow_relay: false,
            allow_discovery: true,
            maximum_uses,
            expires_at_unix_ms,
        }),
    };
    let mut payload = Vec::new();
    Message::encode(&request, &mut payload).map_err(|e| format!("invite create: encode: {e}"))?;
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("invite create: {e:?}"))?;
    let (code, response_payload) = daemon
        .request_raw("PeerService", "CreateInvitation", payload)
        .await
        .map_err(|e| format!("invite create: {e:?}"))?;
    if code != api::StatusCode::Ok as i32 {
        return Err(format!("invite create: status {code}"));
    }
    let response = api::CreateInvitationResponse::decode(response_payload.as_slice())
        .map_err(|e| format!("invite create: decode: {e}"))?;
    Ok(vec![
        format!("invitation_id={}", hex_id(&response.invitation_id)),
        format!("invitation_secret={}", hex_id(&response.invitation_secret)),
        format!(
            "invitation_document={}",
            hex_id(&response.invitation_document)
        ),
    ])
}

async fn cmd_invite_import(
    socket: &str,
    document: String,
    secret: String,
) -> Result<Vec<String>, String> {
    let request = api::ImportInvitationRequest {
        invitation_document: decode_hex(&document)?,
        invitation_secret: decode_hex(&secret)?,
    };
    let mut payload = Vec::new();
    Message::encode(&request, &mut payload).map_err(|e| format!("invite import: encode: {e}"))?;
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("invite import: {e:?}"))?;
    let (code, response_payload) = daemon
        .request_raw("PeerService", "ImportInvitation", payload)
        .await
        .map_err(|e| format!("invite import: {e:?}"))?;
    if code != api::StatusCode::Ok as i32 {
        return Err(format!("invite import: status {code}"));
    }
    let response = api::ImportInvitationResponse::decode(response_payload.as_slice())
        .map_err(|e| format!("invite import: decode: {e}"))?;
    Ok(vec![format!(
        "invitation imported: {}",
        hex_id(&response.invitation_id)
    )])
}

async fn cmd_invite_revoke(
    socket: &str,
    invitation_id: String,
    reason: String,
) -> Result<Vec<String>, String> {
    let request = api::RevokeInvitationRequest {
        invitation_id: decode_hex(&invitation_id)?,
        reason,
    };
    let mut payload = Vec::new();
    Message::encode(&request, &mut payload).map_err(|e| format!("invite revoke: encode: {e}"))?;
    let mut daemon = DaemonClient::connect(socket, CLIENT_NAME)
        .await
        .map_err(|e| format!("invite revoke: {e:?}"))?;
    let (code, _) = daemon
        .request_raw("PeerService", "RevokeInvitation", payload)
        .await
        .map_err(|e| format!("invite revoke: {e:?}"))?;
    if code != api::StatusCode::Ok as i32 {
        return Err(format!("invite revoke: status {code}"));
    }
    Ok(vec!["invitation revoked".into()])
}

/// `umc init`: local node initialization mirroring `umcd --init` file
/// creation (core.md §19) — data dir, keystore dir, and the default config
/// file written only when absent. The node identity is generated by the
/// daemon at its first start.
fn cmd_init(config_path: Option<PathBuf>, data_dir: &Path) -> Result<Vec<String>, String> {
    let keystore_dir = data_dir.join("keystore");
    std::fs::create_dir_all(data_dir).map_err(|e| format!("init: data dir: {e}"))?;
    std::fs::create_dir_all(&keystore_dir).map_err(|e| format!("init: keystore dir: {e}"))?;
    let config_file = config_path.unwrap_or_else(|| data_dir.join("node.json"));
    let existed = config_file.exists();
    if !existed {
        std::fs::write(&config_file, DEFAULT_CONFIG_JSON)
            .map_err(|e| format!("init: config write: {e}"))?;
    }
    Ok(vec![
        format!("data directory: {}", data_dir.display()),
        format!("keystore directory: {}", keystore_dir.display()),
        format!(
            "config file: {} ({})",
            config_file.display(),
            if existed {
                "exists, not overwritten"
            } else {
                "written"
            }
        ),
        "node identity is generated at the first daemon start (or `umcd --init`)".to_string(),
    ])
}

/// The default node data directory with `~` expanded.
fn default_data_dir() -> PathBuf {
    expand_home(Path::new(DEFAULT_DATA_DIR))
}

fn expand_home(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = std::env::var("HOME")
            .ok()
            .or_else(|| std::env::var("USERPROFILE").ok())
        {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

/// Redacted endpoint id, mirroring the daemon's log redaction (privacy.md
/// §37): the last four bytes as hex.
fn redact_id(id: &[u8]) -> String {
    let tail = &id[id.len().saturating_sub(4)..];
    let mut out = String::with_capacity(tail.len() * 2 + 1);
    out.push('…');
    for byte in tail {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Full hex of a short operator-facing id (session handles, route hashes).
fn hex_id(id: &[u8]) -> String {
    let mut out = String::with_capacity(id.len() * 2);
    for byte in id {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() % 2 != 0 {
        return Err("hex value must have an even number of characters".into());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0]).ok_or_else(|| format!("invalid hex byte {pair:?}"))?;
        let low = hex_digit(pair[1]).ok_or_else(|| format!("invalid hex byte {pair:?}"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

async fn run(cli: Cli) -> Vec<String> {
    let result = match cli.command {
        Command::Status => cmd_status(&cli.socket).await,
        Command::Config {
            action: ConfigAction::Get,
        } => cmd_config_get(&cli.socket).await,
        Command::Config {
            action: ConfigAction::Set { entries },
        } => cmd_config_set(&cli.socket, entries).await,
        Command::Events => cmd_events(&cli.socket).await,
        Command::Identity {
            action: IdentityAction::List,
        } => cmd_identity(&cli.socket).await,
        Command::Doctor => cmd_doctor(&cli.socket).await,
        Command::Init { config } => cmd_init(config, &default_data_dir()),
        Command::Sessions {
            action: SessionsAction::List,
        } => cmd_sessions_list(&cli.socket).await,
        Command::Routes {
            action: RoutesAction::List,
        } => cmd_routes_list(&cli.socket).await,
        Command::Peers {
            action: PeersAction::List,
        } => cmd_peers_list(&cli.socket).await,
        Command::Peers {
            action:
                PeersAction::Add {
                    endpoint_id,
                    carrier,
                    address,
                    expires_at_unix_ms,
                    do_not_reshare,
                },
        } => {
            cmd_peers_add(
                &cli.socket,
                endpoint_id,
                carrier,
                address,
                expires_at_unix_ms,
                do_not_reshare,
            )
            .await
        }
        Command::Peers {
            action: PeersAction::Remove { endpoint_id },
        } => cmd_peers_remove(&cli.socket, endpoint_id).await,
        Command::Invite {
            action:
                InviteAction::Create {
                    endpoint_ids,
                    expires_at_unix_ms,
                    maximum_uses,
                },
        } => cmd_invite_create(&cli.socket, endpoint_ids, expires_at_unix_ms, maximum_uses).await,
        Command::Invite {
            action: InviteAction::Import { document, secret },
        } => cmd_invite_import(&cli.socket, document, secret).await,
        Command::Invite {
            action:
                InviteAction::Revoke {
                    invitation_id,
                    reason,
                },
        } => cmd_invite_revoke(&cli.socket, invitation_id, reason).await,
    };
    match result {
        Ok(lines) => lines,
        Err(message) => vec![message],
    }
}

fn main() {
    let mut cli = Cli::parse();
    cli.socket = expand_home(Path::new(&cli.socket))
        .to_string_lossy()
        .into_owned();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("runtime");
    for line in runtime.block_on(run(cli)) {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::process::{Child, Command as StdCommand, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(unix)]
    use std::time::Duration;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args.iter().copied()).expect("cli parses")
    }

    #[test]
    fn parses_every_subcommand() {
        assert!(matches!(parse(&["umc", "status"]).command, Command::Status));
        assert!(matches!(
            parse(&["umc", "config", "get"]).command,
            Command::Config {
                action: ConfigAction::Get
            }
        ));
        assert!(matches!(
            parse(&["umc", "config", "set", "mesh=true"]).command,
            Command::Config {
                action: ConfigAction::Set { .. }
            }
        ));
        assert!(matches!(parse(&["umc", "events"]).command, Command::Events));
        assert!(matches!(
            parse(&["umc", "identity", "list"]).command,
            Command::Identity {
                action: IdentityAction::List
            }
        ));
        assert!(matches!(parse(&["umc", "doctor"]).command, Command::Doctor));
        assert!(matches!(
            parse(&["umc", "init"]).command,
            Command::Init { config: None }
        ));
        assert!(matches!(
            parse(&["umc", "sessions", "list"]).command,
            Command::Sessions {
                action: SessionsAction::List
            }
        ));
        assert!(matches!(
            parse(&["umc", "routes", "list"]).command,
            Command::Routes {
                action: RoutesAction::List
            }
        ));
        assert!(matches!(
            parse(&["umc", "peers", "list"]).command,
            Command::Peers {
                action: PeersAction::List
            }
        ));
        assert!(matches!(
            parse(&["umc", "invite", "create", "--expires-at-unix-ms", "123"]).command,
            Command::Invite {
                action: InviteAction::Create { .. }
            }
        ));
        assert!(matches!(
            parse(&["umc", "peers", "add", "00", "ump.tcp/1", "127.0.0.1:1"]).command,
            Command::Peers {
                action: PeersAction::Add { .. }
            }
        ));
    }

    #[test]
    fn default_socket_matches_daemon_config() {
        let cli = parse(&["umc", "status"]);
        #[cfg(unix)]
        assert_eq!(cli.socket, "~/.local/run/umc.sock");
        #[cfg(windows)]
        assert_eq!(cli.socket, r"\\.\pipe\umc");
        #[cfg(not(any(unix, windows)))]
        assert_eq!(cli.socket, "~/.local/run/umc.sock");
    }

    #[test]
    fn init_accepts_a_config_path() {
        let cli = parse(&["umc", "init", "--config", "/tmp/umc-node.json"]);
        match cli.command {
            Command::Init { config } => {
                assert_eq!(config, Some(PathBuf::from("/tmp/umc-node.json")));
            }
            other => panic!("expected Init, got {other:?}"),
        }
    }

    #[test]
    fn init_creates_dirs_and_writes_the_default_config_only_once() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "umc-init-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let config = dir.join("node.json");
        let lines = cmd_init(Some(config.clone()), &dir).expect("init");
        assert!(
            lines.iter().any(|l| l.contains("data directory")),
            "init prints the data directory: {lines:?}"
        );
        assert!(dir.join("keystore").is_dir(), "keystore dir created");
        assert!(config.is_file(), "default config written");
        let written = std::fs::read_to_string(&config).expect("read config");
        assert!(
            written.contains("telemetry_enabled"),
            "defaults mirror umcd: {written}"
        );

        // A second pass leaves an existing config untouched.
        std::fs::write(&config, "custom").expect("overwrite");
        cmd_init(Some(config.clone()), &dir).expect("second init");
        assert_eq!(
            std::fs::read_to_string(&config).expect("read config"),
            "custom",
            "existing config is not overwritten"
        );
    }

    #[cfg(unix)]
    fn fresh_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "umc-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        dir
    }

    /// Locate (and if necessary build) the umcd binary, mirroring the
    /// phase12 harness: a stale daemon silently tests the wrong code.
    #[cfg(unix)]
    fn umcd_binary() -> PathBuf {
        let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let bin = here
            .join("../../target/debug")
            .join(format!("umcd{}", std::env::consts::EXE_SUFFIX));
        let src_newer =
            std::fs::read_dir(here.join("../../bins/umcd/src")).map_or(true, |entries| {
                entries.filter_map(Result::ok).any(|e| {
                    e.path()
                        .metadata()
                        .and_then(|m| m.modified())
                        .ok()
                        .zip(bin.metadata().and_then(|m| m.modified()).ok())
                        .is_some_and(|(src, bin)| src > bin)
                })
            });
        if !bin.exists() || src_newer {
            let status = StdCommand::new(env!("CARGO"))
                .args(["build", "-p", "umcd"])
                .current_dir(here.join("../.."))
                .status()
                .expect("run cargo build -p umcd");
            assert!(status.success(), "cargo build -p umcd failed");
        }
        assert!(bin.exists(), "umcd binary missing at {}", bin.display());
        bin
    }

    /// A running daemon; kills the child on drop.
    #[cfg(unix)]
    struct Daemon {
        child: Child,
        _dir: PathBuf,
    }

    #[cfg(unix)]
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Spawn a daemon with no carriers bound (the control socket is all the
    /// smoke test needs).
    #[cfg(unix)]
    fn spawn_daemon(dir: &Path) -> Daemon {
        let config = format!(
            r#"{{"data_dir": "{}", "control_socket": "{}", "carriers": [], "profile": "standard", "mesh": false, "public_relay": false, "telemetry_enabled": false, "development_token": null}}"#,
            dir.join("data").display(),
            dir.join("umc.sock").display()
        );
        let config_path = dir.join("node.json");
        std::fs::write(&config_path, config).expect("write config");
        let log = std::fs::File::create(dir.join("umcd.log")).expect("log file");
        let child = StdCommand::new(umcd_binary())
            .args(["--config", config_path.to_str().expect("config path")])
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn umcd");
        Daemon {
            child,
            _dir: dir.to_path_buf(),
        }
    }

    #[cfg(unix)]
    fn wait_for_socket(socket: &Path) {
        for _ in 0..200 {
            if socket.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "daemon control socket never appeared at {}",
            socket.display()
        );
    }

    #[cfg(unix)]
    fn run_cli(socket: &str, command: Command) -> Vec<String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("runtime");
        runtime.block_on(run(Cli {
            socket: socket.to_string(),
            command,
        }))
    }

    /// The new subcommands round-trip against a live daemon: doctor runs
    /// the daemon-side checks, and the list commands hit their service
    /// handlers over the control socket.
    #[cfg(unix)]
    #[test]
    fn new_subcommands_round_trip_against_a_live_daemon() {
        let dir = fresh_dir("smoke");
        let _daemon = spawn_daemon(&dir);
        let socket_path = dir.join("umc.sock");
        wait_for_socket(&socket_path);
        let socket = socket_path.to_str().expect("socket path").to_string();

        let lines = run_cli(&socket, Command::Doctor);
        assert!(
            lines.iter().any(|l| l.starts_with("database:")),
            "doctor reports the database check: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("clock:")),
            "doctor reports the clock check: {lines:?}"
        );

        let lines = run_cli(
            &socket,
            Command::Sessions {
                action: SessionsAction::List,
            },
        );
        assert_eq!(lines, vec!["no sessions"]);

        let lines = run_cli(
            &socket,
            Command::Routes {
                action: RoutesAction::List,
            },
        );
        assert_eq!(lines, vec!["no routes"]);

        let lines = run_cli(
            &socket,
            Command::Peers {
                action: PeersAction::List,
            },
        );
        assert_eq!(lines, vec!["no peers"]);

        let lines = run_cli(&socket, Command::Status);
        assert!(
            lines.iter().any(|l| l == "node reachable"),
            "status still works: {lines:?}"
        );
    }
}
