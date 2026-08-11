#[cfg(any(unix, windows))]
include!("unix_main.rs");

/// Unsupported targets remain compileable, but do not claim a daemon runtime
/// until a local control transport is available.
#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("umcd runtime is unavailable on this platform; no control transport is available");
}
