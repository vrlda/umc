//! umc CLI (core.md §44): control and diagnostics client.
use clap::{Parser, Subcommand};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use umc_control::framing::{frame_envelope, EnvelopeDecoder};
use umc_control::proto::umc::api::v1 as api;

const DEFAULT_SOCKET: &str = "/tmp/umc.sock";

#[derive(Parser)]
#[command(name = "umc", about = "Universal Mesh Core control client")]
struct Cli {
    /// Control socket path.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Node status.
    Status,
    /// List identities.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Run local diagnostics.
    Doctor,
}

#[derive(Subcommand)]
enum IdentityAction {
    List,
}

async fn call(socket: &str, service: &str, method: &str) -> Result<api::Envelope, String> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let hello = api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence: 1,
        body: Some(api::envelope::Body::ClientHello(api::ClientHello {
            supported_versions: vec![api::ApiVersion { major: 1, minor: 0 }],
            client_name: "umc-cli".to_string(),
            ..Default::default()
        })),
    };
    let mut out = Vec::new();
    Message::encode(&hello, &mut out).map_err(|e| e.to_string())?;
    let mut framed = Vec::new();
    frame_envelope(&mut framed, &out, 4 * 1024 * 1024).map_err(|e| format!("{e:?}"))?;
    stream
        .write_all(&framed)
        .await
        .map_err(|e| format!("write: {e}"))?;

    let request = api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence: 2,
        body: Some(api::envelope::Body::Request(api::Request {
            request_id: 1,
            service: service.to_string(),
            method: method.to_string(),
            ..Default::default()
        })),
    };
    let mut out = Vec::new();
    Message::encode(&request, &mut out).map_err(|e| e.to_string())?;
    let mut framed = Vec::new();
    frame_envelope(&mut framed, &out, 4 * 1024 * 1024).map_err(|e| format!("{e:?}"))?;
    stream
        .write_all(&framed)
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut decoder = EnvelopeDecoder::new(4 * 1024 * 1024);
    let mut buf = [0u8; 8 * 1024];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        for envelope in decoder.feed(&buf[..n]).map_err(|e| format!("{e:?}"))? {
            let msg = api::Envelope::decode(envelope.as_slice()).map_err(|e| e.to_string())?;
            if matches!(msg.body, Some(api::envelope::Body::Response(_))) {
                return Ok(msg);
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        match cli.command {
            Command::Status => match call(&cli.socket, "NodeAdmin", "GetStatus").await {
                Ok(_) => println!("node reachable"),
                Err(e) => println!("status: {e}"),
            },
            Command::Identity {
                action: IdentityAction::List,
            } => match call(&cli.socket, "IdentityService", "ListIdentities").await {
                Ok(_) => println!("identity list (Phase 2 minimal)"),
                Err(e) => println!("identity: {e}"),
            },
            Command::Doctor => {
                println!("doctor: run `umcd --doctor` output locally (Phase 2 minimal)");
            }
        }
    });
}
