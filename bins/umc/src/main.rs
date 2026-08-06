//! umc CLI (core.md §44): control and diagnostics client.
use std::collections::HashMap;

use clap::{Parser, Subcommand};
use prost::Message;
use umc_control::proto::umc::api::v1 as api;
use umc_sdk::client::ClientError;
use umc_sdk::config::ConfigClient;
use umc_sdk::daemon::DaemonClient;
use umc_sdk::status::StatusClient;

const DEFAULT_SOCKET: &str = "/tmp/umc.sock";
const CLIENT_NAME: &str = "umc-cli";

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
    /// Run local diagnostics.
    Doctor,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print config entries.
    Get,
    /// Set config entries (key=value); unimplemented until Phase 12.
    Set { entries: Vec<String> },
}

#[derive(Subcommand)]
enum IdentityAction {
    List,
}

fn print_error(prefix: &str, error: &ClientError) {
    println!("{prefix}: {error:?}");
}

async fn cmd_status(socket: &str) {
    let mut client = match StatusClient::connect(socket, CLIENT_NAME).await {
        Ok(client) => client,
        Err(e) => {
            print_error("status", &e);
            return;
        }
    };
    match client.get_status().await {
        Ok(status) => {
            println!("node reachable");
            println!("uptime: {} ms", status.uptime_ms);
            println!("sessions: {}", status.active_sessions);
            println!("links: {}", status.active_links);
            println!("relay circuits: {}", status.active_relay_circuits);
            println!("started at: {} ms", status.started_at_unix_ms);
        }
        Err(e) => print_error("status", &e),
    }
}

async fn cmd_config_get(socket: &str) {
    let mut client = match ConfigClient::connect(socket, CLIENT_NAME).await {
        Ok(client) => client,
        Err(e) => {
            print_error("config", &e);
            return;
        }
    };
    match client.get_config().await {
        Ok(entries) => {
            let mut keys: Vec<&String> = entries.keys().collect();
            keys.sort();
            for key in keys {
                println!("{key}={}", entries[key]);
            }
        }
        Err(e) => print_error("config", &e),
    }
}

async fn cmd_config_set(socket: &str, entries: Vec<String>) {
    let mut map = HashMap::new();
    for entry in entries {
        let Some((key, value)) = entry.split_once('=') else {
            println!("config: invalid entry (expected key=value): {entry}");
            return;
        };
        map.insert(key.to_string(), value.to_string());
    }
    let mut client = match ConfigClient::connect(socket, CLIENT_NAME).await {
        Ok(client) => client,
        Err(e) => {
            print_error("config", &e);
            return;
        }
    };
    match client.set_config(map) {
        Ok(()) => println!("config updated"),
        Err(e) => print_error("config", &e),
    }
}

async fn cmd_events(socket: &str) {
    let mut daemon = match DaemonClient::connect(socket, CLIENT_NAME).await {
        Ok(daemon) => daemon,
        Err(e) => {
            print_error("events", &e);
            return;
        }
    };
    match daemon
        .request_raw("NodeAdmin", "GetEvents", Vec::new())
        .await
    {
        Ok((code, payload)) if code == api::StatusCode::Ok as i32 => {
            match api::GetEventsResponse::decode(payload.as_slice()) {
                Ok(response) => {
                    if response.events.is_empty() {
                        println!("no recent events");
                        return;
                    }
                    for event in response.events {
                        println!("{} {} {}", event.at_ms, event.kind, event.detail);
                    }
                }
                Err(e) => println!("events: decode failed: {e}"),
            }
        }
        Ok((code, _)) => println!("events: status {code}"),
        Err(e) => print_error("events", &e),
    }
}

async fn cmd_identity(socket: &str) {
    let mut daemon = match DaemonClient::connect(socket, CLIENT_NAME).await {
        Ok(daemon) => daemon,
        Err(e) => {
            print_error("identity", &e);
            return;
        }
    };
    match daemon
        .request_raw("IdentityService", "ListIdentities", Vec::new())
        .await
    {
        Ok((code, _)) if code == api::StatusCode::Ok as i32 => {
            println!("identity list (Phase 2 minimal)");
        }
        Ok((code, _)) => println!("identity: status {code}"),
        Err(e) => print_error("identity", &e),
    }
}

async fn run(cli: Cli) {
    match cli.command {
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
        Command::Doctor => {
            println!("doctor: run `umcd --doctor` output locally (Phase 2 minimal)");
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("runtime");
    runtime.block_on(run(cli));
}
