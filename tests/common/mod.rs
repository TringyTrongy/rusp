//! Helpers shared by the integration tests.
//!
//! Everything here drives the real library the way the binary does: a real
//! relay, a real SPAKE2 handshake, real files on disk. Nothing is stubbed.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusp::code::TransferCode;
use rusp::config::{ConflictPolicy, RelayConfig};
use rusp::net::server::{Relay, RelaySettings};
use rusp::net::{NetOptions, SenderRendezvous};
use rusp::protocol::channel::Channel;
use rusp::protocol::Role;
use rusp::transfer::progress::{Counters, Silent};
use rusp::transfer::{self, ReceiveOptions};
use rusp::Result;
use tokio_util::sync::CancellationToken;

/// A relay running on loopback for the duration of a test.
pub struct TestRelay {
    pub address: String,
    cancel: CancellationToken,
}

impl TestRelay {
    /// Start a relay on an ephemeral loopback port.
    pub async fn start() -> TestRelay {
        Self::start_with(RelaySettings::default()).await
    }

    /// Start a relay with specific settings; the listen address is replaced
    /// with an ephemeral loopback port.
    pub async fn start_with(settings: RelaySettings) -> TestRelay {
        let relay = Relay::bind(RelaySettings {
            listen: "127.0.0.1:0".into(),
            ..settings
        })
        .await
        .expect("relay should bind");
        let address = relay.local_addr().expect("relay address").to_string();
        let cancel = CancellationToken::new();
        tokio::spawn(relay.run(cancel.clone()));
        TestRelay { address, cancel }
    }

    /// Network options pointing at this relay, with LAN discovery off so
    /// tests never depend on the machine's network.
    pub fn options(&self) -> NetOptions {
        NetOptions {
            relay: Some(RelayConfig::new(&self.address, None)),
            lan: false,
            discovery_port: 0,
            connect_timeout: Duration::from_secs(10),
            rendezvous_timeout: Duration::from_secs(20),
        }
    }

    /// Options with a token, for authentication tests.
    pub fn options_with_token(&self, token: &str) -> NetOptions {
        NetOptions {
            relay: Some(RelayConfig::new(&self.address, Some(token.to_owned()))),
            ..self.options()
        }
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// A code that is valid and unique per test.
pub fn code(room: &str) -> TransferCode {
    TransferCode::parse(&format!("{room}-cotton-harbor-tiger-pencil")).expect("valid code")
}

/// Receive options writing into `dir`.
pub fn receive_options(dir: &Path, on_conflict: ConflictPolicy) -> ReceiveOptions {
    ReceiveOptions {
        output_dir: dir.to_path_buf(),
        on_conflict,
    }
}

/// What a completed round trip produced.
#[derive(Debug)]
pub struct RoundTrip {
    pub sent: transfer::SendReport,
    pub received: transfer::ReceiveReport,
    pub sender_bytes: u64,
    pub receiver_bytes: u64,
}

/// Run one full transfer over a relay and return both sides' reports.
///
/// Both peers run concurrently, as separate tasks over separate sockets, so
/// this exercises the same code path the binary does.
pub async fn round_trip(
    relay: &TestRelay,
    room: &str,
    sources: &[PathBuf],
    destination: &Path,
    on_conflict: ConflictPolicy,
) -> Result<RoundTrip> {
    round_trip_with(
        relay,
        room,
        sources,
        destination,
        on_conflict,
        rusp::files::ScanOptions::default(),
    )
    .await
}

/// As [`round_trip`], with control over how the sender walks its input.
pub async fn round_trip_with(
    relay: &TestRelay,
    room: &str,
    sources: &[PathBuf],
    destination: &Path,
    on_conflict: ConflictPolicy,
    scan_options: rusp::files::ScanOptions,
) -> Result<RoundTrip> {
    let code = code(room);
    let scan = rusp::files::scan(sources, scan_options)?;
    let options = relay.options();
    let cancel = CancellationToken::new();

    let sender = {
        let code = code.clone();
        let options = options.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let counters = Counters::default();
            let mut rendezvous = SenderRendezvous::open(options, code.room().clone()).await?;
            let connection = rendezvous.accept(&cancel).await?;
            let (read, write) = connection.into_split();
            let mut channel = Channel::establish(read, write, Role::Sender, &code).await?;
            let report = transfer::send(&mut channel, &scan, &counters, &cancel).await?;
            let _ = channel.shutdown().await;
            Ok::<_, rusp::Error>((report, counters.snapshot().0))
        })
    };

    let receiver = {
        let destination = destination.to_path_buf();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let counters = Counters::default();
            let connection = rusp::net::dial(&options, code.room(), &cancel).await?;
            let (read, write) = connection.into_split();
            let mut channel = Channel::establish(read, write, Role::Receiver, &code).await?;
            let pending =
                transfer::begin(&mut channel, receive_options(&destination, on_conflict)).await?;
            let report = pending.accept(&counters, &cancel).await?;
            Ok::<_, rusp::Error>((report, counters.snapshot().0))
        })
    };

    let (sender, receiver) = tokio::join!(sender, receiver);
    let (sent, sender_bytes) = sender.expect("sender task should not panic")?;
    let (received, receiver_bytes) = receiver.expect("receiver task should not panic")?;

    Ok(RoundTrip {
        sent,
        received,
        sender_bytes,
        receiver_bytes,
    })
}

/// Run a transfer where the receiver declines the offer.
pub async fn decline(
    relay: &TestRelay,
    room: &str,
    sources: &[PathBuf],
    destination: &Path,
) -> (Result<transfer::SendReport>, Result<()>) {
    let code = code(room);
    let scan = rusp::files::scan(sources, Default::default()).expect("scan");
    let options = relay.options();
    let cancel = CancellationToken::new();

    let sender = {
        let code = code.clone();
        let options = options.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut rendezvous = SenderRendezvous::open(options, code.room().clone()).await?;
            let connection = rendezvous.accept(&cancel).await?;
            let (read, write) = connection.into_split();
            let mut channel = Channel::establish(read, write, Role::Sender, &code).await?;
            transfer::send(&mut channel, &scan, &Silent, &cancel).await
        })
    };

    let receiver = {
        let destination = destination.to_path_buf();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let connection = rusp::net::dial(&options, code.room(), &cancel).await?;
            let (read, write) = connection.into_split();
            let mut channel = Channel::establish(read, write, Role::Receiver, &code).await?;
            let pending = transfer::begin(
                &mut channel,
                receive_options(&destination, ConflictPolicy::Rename),
            )
            .await?;
            pending.decline(Some("no thanks".into())).await
        })
    };

    let (sender, receiver) = tokio::join!(sender, receiver);
    (
        sender.expect("sender task"),
        receiver.expect("receiver task"),
    )
}

/// Every path under `root`, relative and `/`-separated, sorted.
pub fn tree(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root).sort_by_file_name() {
        let entry = entry.expect("walk the destination");
        if entry.depth() == 0 {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        out.push(if entry.file_type().is_dir() {
            format!("{relative}/")
        } else {
            relative
        });
    }
    out.sort();
    out
}

/// Write a file, creating parent directories.
pub fn write(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, contents).expect("write file");
}

/// Deterministic pseudo-random bytes, so a failure is reproducible.
pub fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            // xorshift64*: not cryptography, just repeatable filler.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u8
        })
        .collect()
}
