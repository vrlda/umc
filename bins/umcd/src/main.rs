#[cfg(unix)]
include!("unix_main.rs");

/// The daemon's Unix-domain control socket and filesystem permission model
/// are intentionally authoritative for v0.1. Windows named-pipe transport is
/// deferred, but the package remains compileable on Tier-1 CI.
#[cfg(not(unix))]
fn main() {
    eprintln!(
        "umcd runtime is unavailable on this platform; Windows named-pipe support is deferred"
    );
}
