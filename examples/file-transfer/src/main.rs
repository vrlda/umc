use std::env;
use std::fs;
use std::path::PathBuf;

use umc_file_transfer::transfer_bytes;

#[tokio::main]
async fn main() {
    let mut args = env::args_os().skip(1);
    let source_path = args.next().map(PathBuf::from);
    let destination_path = args.next().map(PathBuf::from);
    if args.next().is_some() || destination_path.is_none() && source_path.is_some() {
        eprintln!("usage: umc-file-transfer [SOURCE DESTINATION]");
        std::process::exit(2);
    }

    let source = source_path.as_ref().map_or_else(
        || {
            (0..(1024 * 1024))
                .map(|index| u8::try_from(index % 251).expect("bounded pattern"))
                .collect()
        },
        |path| fs::read(path).expect("read source file"),
    );
    let report = transfer_bytes(&source).await.expect("transfer file");
    if let Some(destination) = destination_path {
        fs::write(destination, &report.received).expect("write destination file");
    }
    println!(
        "transferred {} bytes; BLAKE2s-256 {:02x?}",
        report.bytes, report.digest
    );
}
