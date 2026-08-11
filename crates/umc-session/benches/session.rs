use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use umc_session::session::{Role, Session, SessionConfig};
use umc_types::runtime::{Clock, Instant};

#[derive(Debug, Clone, Copy)]
struct BenchClock;

impl Clock for BenchClock {
    fn now(&self) -> Instant {
        Instant(0)
    }
}

fn config(role: Role, local: [u8; 32], remote: [u8; 32]) -> SessionConfig {
    SessionConfig {
        role,
        dcid: vec![0x42; 8],
        local_traffic_secret: local,
        remote_traffic_secret: remote,
        initial_max_data: 4 * 1024 * 1024,
        initial_max_stream_data: 256 * 1024,
        max_ack_delay_ms: 25,
    }
}

fn bench_session(c: &mut Criterion) {
    let clock = BenchClock;
    let mut sender =
        Session::new(config(Role::Client, [1u8; 32], [2u8; 32]), &clock).expect("sender session");
    let packet = sender
        .build_outbound(&clock, Instant(0), &[0x04])
        .expect("outbound packet")
        .expect("packet is available");

    c.bench_function("session_build_outbound_ping", |b| {
        b.iter_batched(
            || {
                Session::new(config(Role::Client, [1u8; 32], [2u8; 32]), &clock)
                    .expect("sender session")
            },
            |mut session| {
                session
                    .build_outbound(&clock, Instant(0), black_box(&[0x04]))
                    .expect("outbound packet");
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("session_on_inbound_ping", |b| {
        b.iter_batched(
            || {
                Session::new(config(Role::Server, [2u8; 32], [1u8; 32]), &clock)
                    .expect("receiver session")
            },
            |mut session| {
                session
                    .on_inbound(Instant(0), black_box(&packet))
                    .expect("inbound packet");
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(session_benches, bench_session);
criterion_main!(session_benches);
