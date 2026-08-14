use std::io::{self, BufRead, Write};

use umc_chat::CHAT_PROTOCOL;
use umc_sdk::{Client, Policy};

#[tokio::main]
async fn main() {
    println!("UMC terminal chat ({CHAT_PROTOCOL})");
    println!("This local demo loops messages through the embedded UMC backend.");
    println!("Type a message and press Enter; type /quit to exit.");

    let mut client = Client::embedded();
    let endpoint = client.load_endpoint("default").await.expect("endpoint");
    let application = client
        .register_application(
            "terminal-chat",
            [0x44; 16],
            &[endpoint.endpoint_id()],
            &[CHAT_PROTOCOL],
        )
        .await
        .expect("register application");
    let listener = client
        .listen(
            &application,
            endpoint.endpoint_id(),
            CHAT_PROTOCOL,
            &Policy::default(),
        )
        .await
        .expect("listen");
    let pending_session = client
        .connect_session(
            &application,
            b"embedded-chat-peer",
            CHAT_PROTOCOL,
            &Policy::default(),
        )
        .await
        .expect("connect session");
    let session = client
        .accept_session(&application, &pending_session)
        .await
        .expect("accept session");
    let pending_stream = client
        .open_stream(&application, &session, false)
        .await
        .expect("open stream");
    let stream = client
        .accept_stream(&application, &pending_stream)
        .await
        .expect("accept stream");

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = line.expect("read stdin");
        if line == "/quit" {
            break;
        }
        let bytes = line.as_bytes();
        client
            .write_stream(&stream, bytes, false)
            .await
            .expect("write chat message");
        let (reply, eof) = client
            .read_stream(&stream, bytes.len(), false)
            .await
            .expect("read chat reply");
        if eof {
            break;
        }
        writeln!(stdout, "peer: {}", String::from_utf8_lossy(&reply)).expect("write stdout");
        stdout.flush().expect("flush stdout");
    }
    client
        .close_stream_send(&stream)
        .await
        .expect("close stream");
    client
        .close_listener(&listener)
        .await
        .expect("close listener");
    client
        .unregister_application(&application, true)
        .await
        .expect("unregister application");
}
