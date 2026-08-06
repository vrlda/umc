mod config;
mod doctor;
mod server;

use clap::Parser;
use config::NodeConfig;

#[derive(Parser)]
#[command(name = "umcd", about = "Universal Mesh Core daemon")]
struct Args {
    /// Path to the node configuration file.
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    /// Run an initialization pass and exit (core.md §19).
    #[arg(long)]
    init: bool,
    /// Run diagnostics and exit.
    #[arg(long)]
    doctor: bool,
}

fn main() {
    let args = Args::parse();
    let config = NodeConfig::load(args.config.as_ref()).expect("valid config");
    if args.init {
        init_node(&config);
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
    rt.block_on(server::run(config));
}

fn init_node(config: &NodeConfig) {
    let data_dir = config.resolved_data_dir();
    std::fs::create_dir_all(data_dir.join("objects")).expect("create data dir");
    std::fs::create_dir_all(data_dir.join("keystore")).expect("create keystore dir");
    println!("node data directory: {}", data_dir.display());
    println!("public relay: disabled (default)");
    println!("telemetry: disabled (default)");
}
