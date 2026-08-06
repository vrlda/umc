mod carriers;
mod config;
mod doctor;
mod runtime_adapters;
mod server;
mod state;

use clap::Parser;
use config::NodeConfig;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "umcd", about = "Universal Mesh Core daemon")]
struct Args {
    /// Path to the node configuration file.
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    /// Run an initialization pass and exit (core.md §19).
    #[arg(long)]
    init: bool,
    /// Override the control socket path (layering: CLI beats config file).
    #[arg(long)]
    socket: Option<String>,
    /// Run diagnostics and exit.
    #[arg(long)]
    doctor: bool,
}

fn main() {
    let args = Args::parse();
    let mut config = NodeConfig::load(args.config.as_ref()).expect("valid config");
    if let Some(socket) = args.socket {
        config.control_socket = socket.into();
    }
    if args.init {
        init_node(&config, args.config.as_ref());
        return;
    }
    if args.doctor {
        let report = doctor::run_doctor(&config);
        for check in report.checks {
            println!(
                "{}: {} ({})",
                if check.passed { "[ok]" } else { "[FAIL]" },
                check.name,
                check.detail
            );
        }
        return;
    }
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(run(config));
}

/// Main startup sequence (core.md §18): state -> carriers -> control socket
/// -> shutdown.
async fn run(config: NodeConfig) {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let mut state = state::RuntimeState::new(config, shutdown_tx).expect("runtime state");
    println!(
        "data directory: {}",
        state.config.resolved_data_dir().display()
    );
    println!("started at: {}ms", state.started_at.0);
    println!("node endpoint: {:02x?}", state.node_identity.endpoint_id());
    println!(
        "mesh mode: {}",
        if state.mesh.enable_lan_discovery {
            "local"
        } else {
            "endpoint"
        }
    );

    carriers::wire_carriers(&mut state);
    println!("carrier listeners: {} bound", state.listeners.len());
    let state = Arc::new(state);

    let server_state = state.clone();
    let server_task = tokio::spawn(server::run(server_state));

    // Graceful shutdown: SIGINT sets the flag and releases the channel.
    let shutdown_flag = state.shutdown_requested.clone();
    let shutdown_tx = state.shutdown_channel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("shutdown: signal received");
        shutdown_flag.store(true, Ordering::Relaxed);
        let _ = shutdown_tx.send(()).await;
    });

    let _ = shutdown_rx.recv().await;
    println!("shutdown: complete");
    // Wait for the control socket to finish closing before exiting.
    let _ = server_task.await;
}

fn init_node(config: &NodeConfig, config_path: Option<&PathBuf>) {
    let data_dir = config.resolved_data_dir();
    std::fs::create_dir_all(data_dir.join("objects")).expect("create data dir");
    let keystore_dir = config.resolved_keystore_dir();
    std::fs::create_dir_all(&keystore_dir).expect("create keystore dir");
    let config_file = config_path
        .cloned()
        .unwrap_or_else(|| data_dir.join("node.json"));
    let json = serde_json::to_string_pretty(config).expect("serialize config");
    std::fs::write(&config_file, json).expect("write config");
    println!("node data directory: {}", data_dir.display());
    println!("keystore directory: {}", keystore_dir.display());
    println!("config file: {}", config_file.display());
    println!("public relay: disabled (default)");
    println!("telemetry: disabled (default)");
}
