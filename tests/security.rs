//! Security properties, exercised against a real handshake and a real relay.
//!
//! Each test states an attack and asserts that it fails in the intended way.

mod common;

use std::time::Duration;

use common::{code, receive_options, write, TestRelay};
use rusp::code::TransferCode;
use rusp::config::ConflictPolicy;
use rusp::error::{CryptoError, Error, NetworkError, ProtocolError, TransferError};
use rusp::files::ScanOptions;
use rusp::net::server::RelaySettings;
use rusp::net::{self, SenderRendezvous};
use rusp::protocol::channel::Channel;
use rusp::protocol::message::{ControlMessage, Entry, Offer};
use rusp::protocol::Role;
use rusp::transfer::progress::Silent;
use rusp::transfer::{self};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

/// Bring two peers together over the relay and hand back their raw sockets.
async fn paired_sockets(
    relay: &TestRelay,
    room: &str,
) -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let options = relay.options();
    let code = code(room);
    let room_id = code.room().clone();
    let cancel = CancellationToken::new();

    let sender = {
        let options = options.clone();
        let room_id = room_id.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut rendezvous = SenderRendezvous::open(options, room_id).await.unwrap();
            rendezvous.accept(&cancel).await.unwrap()
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let receiver = net::dial(&options, &room_id, &cancel).await.unwrap();
    let sender = sender.await.unwrap();

    // `Connection` hides its socket on purpose; the raw halves are enough for
    // the byte-level tests below.
    let (sr, sw) = sender.into_split();
    let (rr, rw) = receiver.into_split();
    (
        sr.reunite(sw).expect("sender halves"),
        rr.reunite(rw).expect("receiver halves"),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mistyped_code_fails_and_gives_the_attacker_nothing() {
    let relay = TestRelay::start().await;
    let options = relay.options();
    let sender_code = code("typo");
    let receiver_code =
        TransferCode::parse("typo-cotton-harbor-tiger-museum").expect("valid but wrong");
    let cancel = CancellationToken::new();

    let sender = {
        let options = options.clone();
        let code = sender_code.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut rendezvous = SenderRendezvous::open(options, code.room().clone()).await?;
            let connection = rendezvous.accept(&cancel).await?;
            let (read, write) = connection.into_split();
            Channel::establish(read, write, Role::Sender, &code)
                .await
                .map(|_| ())
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    let connection = net::dial(&options, receiver_code.room(), &cancel)
        .await
        .unwrap();
    let (read, write) = connection.into_split();
    let receiver = Channel::establish(read, write, Role::Receiver, &receiver_code).await;

    for result in [sender.await.unwrap(), receiver.map(|_| ())] {
        let err = result.expect_err("a wrong code must not produce a session");
        assert!(
            matches!(err, Error::Crypto(CryptoError::KeyMismatch)),
            "{err}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_recognisable_ever_reaches_the_wire() {
    // Stand in for a hostile relay or a passive eavesdropper: run a real
    // transfer through a tap that records every byte, then go looking for the
    // things that must never be in it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let code = code("spy1");
    let payload: Vec<u8> = b"SUPER-SECRET-PAYLOAD-0123456789".repeat(64);

    let source = dir();
    write(&source.path().join("secret.txt"), &payload);
    let destination = dir();
    let scan =
        rusp::files::scan(&[source.path().join("secret.txt")], ScanOptions::default()).unwrap();

    let tap = tokio::spawn(async move {
        let (sender, _) = listener.accept().await.unwrap();
        let (receiver, _) = listener.accept().await.unwrap();
        let (mut sender_read, mut sender_write) = sender.into_split();
        let (mut receiver_read, mut receiver_write) = receiver.into_split();

        let forward = tokio::spawn(async move {
            let mut transcript = Vec::new();
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = sender_read.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                transcript.extend_from_slice(&buf[..n]);
                if receiver_write.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            transcript
        });
        let backward = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = receiver_read.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if sender_write.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        let transcript = forward.await.unwrap();
        backward.abort();
        transcript
    });

    let cancel = CancellationToken::new();
    let sender_code = code.clone();
    let sender_cancel = cancel.clone();

    // Connect in a fixed order so the tap knows which socket is which: the
    // first connection it accepts is the sender's.
    let sender_stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let receiver_stream = tokio::net::TcpStream::connect(address).await.unwrap();

    let sender = tokio::spawn(async move {
        let (read, write) = sender_stream.into_split();
        let mut channel = Channel::establish(read, write, Role::Sender, &sender_code)
            .await
            .unwrap();
        transfer::send(&mut channel, &scan, &Silent, &sender_cancel)
            .await
            .unwrap();
        let _ = channel.shutdown().await;
    });

    let (read, write) = receiver_stream.into_split();
    let mut channel = Channel::establish(read, write, Role::Receiver, &code)
        .await
        .unwrap();
    let pending = transfer::begin(
        &mut channel,
        receive_options(destination.path(), ConflictPolicy::Rename),
    )
    .await
    .unwrap();
    pending.accept(&Silent, &cancel).await.unwrap();
    sender.await.unwrap();
    drop(channel);

    let transcript = tap.await.unwrap();
    assert!(
        transcript.len() > payload.len(),
        "the transfer should have produced traffic"
    );
    assert!(
        !contains(&transcript, &payload[..64]),
        "file contents must never appear in the clear"
    );
    assert!(
        !contains(&transcript, code.secret().as_bytes()),
        "the code must never appear on the wire"
    );
    for word in code.secret().split('-') {
        assert!(
            !contains(&transcript, word.as_bytes()),
            "`{word}` must not appear on the wire"
        );
    }
    assert!(
        !contains(&transcript, b"secret.txt"),
        "file names must not appear in the clear either"
    );
    assert_eq!(
        std::fs::read(destination.path().join("secret.txt")).unwrap(),
        payload,
        "and the transfer really did work"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A writer that flips one bit of the next write it sees.
///
/// `Channel` is generic over its writer, so a test can drop a saboteur in
/// between it and the socket without the protocol code knowing.
struct FlipOnce<W> {
    inner: W,
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for FlipOnce<W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::sync::atomic::Ordering;
        if self.armed.swap(false, Ordering::SeqCst) && !buf.is_empty() {
            let mut altered = buf.to_vec();
            let last = altered.len() - 1;
            altered[last] ^= 0x01;
            return std::pin::Pin::new(&mut self.inner).poll_write(cx, &altered);
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_single_flipped_bit_ends_the_session() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let relay = TestRelay::start().await;
    let (sender, receiver) = paired_sockets(&relay, "flip").await;
    let code = code("flip");
    let armed = Arc::new(AtomicBool::new(false));

    let sender_code = code.clone();
    let sender_armed = Arc::clone(&armed);
    let ready = Arc::new(tokio::sync::Notify::new());
    let sender_ready = Arc::clone(&ready);
    let sender = tokio::spawn(async move {
        let (read, write) = sender.into_split();
        let write = FlipOnce {
            inner: write,
            armed: sender_armed,
        };
        let mut channel = Channel::establish(read, write, Role::Sender, &sender_code)
            .await
            .unwrap();
        // Wait until the saboteur is armed, so the corruption lands on a
        // record frame rather than somewhere in the handshake.
        sender_ready.notified().await;
        channel
            .send_control(&ControlMessage::Keepalive)
            .await
            .unwrap();
    });

    let (read, write) = receiver.into_split();
    let mut channel = Channel::establish(read, write, Role::Receiver, &code)
        .await
        .unwrap();
    armed.store(true, Ordering::SeqCst);
    ready.notify_one();

    let err = channel
        .recv()
        .await
        .expect_err("a corrupted frame must not be accepted");
    assert!(matches!(err, Error::Crypto(CryptoError::Decrypt)), "{err}");
    let _ = sender.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sender_offering_a_traversing_path_is_refused() {
    let relay = TestRelay::start().await;
    let destination = dir();
    let code = code("trav");
    let options = relay.options();
    let cancel = CancellationToken::new();

    // A hostile sender that builds its own manifest instead of scanning.
    let hostile = {
        let options = options.clone();
        let code = code.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut rendezvous = SenderRendezvous::open(options, code.room().clone()).await?;
            let connection = rendezvous.accept(&cancel).await?;
            let (read, write) = connection.into_split();
            let mut channel = Channel::establish(read, write, Role::Sender, &code).await?;

            channel
                .send_control(&ControlMessage::Capabilities(
                    rusp::protocol::local_capabilities(),
                ))
                .await?;
            let _ = channel.recv_control().await?;
            channel
                .send_control(&ControlMessage::Offer(Offer {
                    entries: vec![Entry::file("../../escaped.txt", 5)],
                    total_bytes: 5,
                    name_hint: None,
                }))
                .await?;
            channel.recv_control().await
        })
    };

    tokio::time::sleep(Duration::from_millis(50)).await;
    let connection = net::dial(&options, code.room(), &cancel).await.unwrap();
    let (read, write) = connection.into_split();
    let mut channel = Channel::establish(read, write, Role::Receiver, &code)
        .await
        .unwrap();

    let err = transfer::begin(
        &mut channel,
        receive_options(destination.path(), ConflictPolicy::Overwrite),
    )
    .await
    .expect_err("a traversing path must be refused");
    assert!(
        matches!(err, Error::Transfer(TransferError::UnsafePath(_))),
        "{err}"
    );

    // The sender is told why, rather than just losing the connection.
    let reply = hostile.await.unwrap().expect("the sender gets an answer");
    assert!(
        matches!(reply, ControlMessage::Failure { .. }),
        "{}",
        reply.name()
    );

    // And nothing was written anywhere.
    let escaped = destination.path().parent().unwrap().join("escaped.txt");
    assert!(!escaped.exists());
    assert!(!destination.path().join("escaped.txt").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sender_that_lies_about_a_file_size_is_cut_off() {
    let relay = TestRelay::start().await;
    let destination = dir();
    let code = code("size");
    let options = relay.options();
    let cancel = CancellationToken::new();

    let hostile = {
        let options = options.clone();
        let code = code.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut rendezvous = SenderRendezvous::open(options, code.room().clone()).await?;
            let connection = rendezvous.accept(&cancel).await?;
            let (read, write) = connection.into_split();
            let mut channel = Channel::establish(read, write, Role::Sender, &code).await?;

            channel
                .send_control(&ControlMessage::Capabilities(
                    rusp::protocol::local_capabilities(),
                ))
                .await?;
            let _ = channel.recv_control().await?;
            // Declare one byte...
            channel
                .send_control(&ControlMessage::Offer(Offer {
                    entries: vec![Entry::file("small.bin", 1)],
                    total_bytes: 1,
                    name_hint: None,
                }))
                .await?;
            let _accept = channel.recv_control().await?;
            channel
                .send_control(&ControlMessage::FileStart { index: 0 })
                .await?;

            // ...then try to write a great deal more than that.
            let mut buf = rusp::protocol::FrameBuf::with_capacity(200_000);
            for round in 0..64u64 {
                let space = channel.stage_data(&mut buf, round * 65_536, 65_536);
                space.fill(0x41);
                channel.finish_data(&mut buf, 65_536);
                if channel.send_frame(&mut buf).await.is_err() {
                    break;
                }
            }
            channel.flush().await
        })
    };

    tokio::time::sleep(Duration::from_millis(50)).await;
    let connection = net::dial(&options, code.room(), &cancel).await.unwrap();
    let (read, write) = connection.into_split();
    let mut channel = Channel::establish(read, write, Role::Receiver, &code)
        .await
        .unwrap();
    let pending = transfer::begin(
        &mut channel,
        receive_options(destination.path(), ConflictPolicy::Overwrite),
    )
    .await
    .unwrap();

    let err = pending
        .accept(&Silent, &cancel)
        .await
        .expect_err("a sender exceeding its declared size must be stopped");
    assert!(
        matches!(err, Error::Transfer(TransferError::SizeMismatch { .. })),
        "{err}"
    );

    // Release the socket before waiting for the sender. It is still trying to
    // push megabytes at a receiver that has stopped reading, and until this
    // end closes, those writes simply block: the relay cannot drain into a
    // full receive buffer. Linux happens to have enough buffer to swallow the
    // whole flood, which is why this only ever deadlocked on macOS and
    // Windows. Dropping the channel makes the writes fail, which is what ends
    // the sender.
    drop(channel);
    let _ = tokio::time::timeout(Duration::from_secs(10), hostile).await;
    let written: u64 = walkdir::WalkDir::new(destination.path())
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum();
    assert!(
        written < 1_000_000,
        "{written} bytes were written for a file declared as one byte"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_token_keeps_strangers_out() {
    let relay = TestRelay::start_with(RelaySettings {
        token: Some(Zeroizing::new("shared-secret".into())),
        ..RelaySettings::default()
    })
    .await;
    let cancel = CancellationToken::new();
    let room = code("tokn").room().clone();

    let err = net::dial(&relay.options(), &room, &cancel)
        .await
        .expect_err("no token should be refused");
    assert!(
        matches!(err, Error::Network(NetworkError::RelayRejected(_))),
        "{err}"
    );

    let err = net::dial(&relay.options_with_token("wrong"), &room, &cancel)
        .await
        .expect_err("a wrong token should be refused");
    assert!(
        matches!(err, Error::Network(NetworkError::RelayRejected(_))),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_third_party_cannot_take_over_a_room_in_progress() {
    let relay = TestRelay::start().await;
    let (_sender, _receiver) = paired_sockets(&relay, "busy").await;
    let cancel = CancellationToken::new();

    let err = net::dial(&relay.options(), code("busy").room(), &cancel)
        .await
        .expect_err("the room is taken");
    assert!(
        matches!(err, Error::Network(NetworkError::RoomBusy(_))),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_rusp_client_gets_a_clear_answer_not_a_hang() {
    let relay = TestRelay::start().await;
    let mut stream = tokio::net::TcpStream::connect(&relay.address)
        .await
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();

    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    assert!(read.is_ok(), "the relay should hang up rather than stall");
    assert!(buf.is_empty(), "and should not answer: {buf:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_receivers_cannot_pair_with_each_other() {
    let relay = TestRelay::start().await;
    let (a, b) = paired_sockets(&relay, "role").await;
    let code = code("role");

    let peer_code = code.clone();
    let first = tokio::spawn(async move {
        let (read, write) = a.into_split();
        Channel::establish(read, write, Role::Receiver, &peer_code)
            .await
            .map(|_| ())
    });
    let (read, write) = b.into_split();
    let second = Channel::establish(read, write, Role::Receiver, &code).await;

    let err = second.expect_err("two receivers must not pair");
    assert!(err.to_string().contains("also a receiver"), "{err}");
    let _ = first.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_leaves_no_half_written_file() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    // Big enough that cancellation lands mid-file.
    write(
        &source.path().join("big.bin"),
        &common::pseudo_random(8 << 20, 3),
    );

    let code = code("cncl");
    let options = relay.options();
    let cancel = CancellationToken::new();
    let scan = rusp::files::scan(&[source.path().join("big.bin")], ScanOptions::default()).unwrap();

    let sender = {
        let options = options.clone();
        let code = code.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut rendezvous = SenderRendezvous::open(options, code.room().clone()).await?;
            let connection = rendezvous.accept(&cancel).await?;
            let (read, write) = connection.into_split();
            let mut channel = Channel::establish(read, write, Role::Sender, &code).await?;
            transfer::send(&mut channel, &scan, &Silent, &cancel)
                .await
                .map(|_| ())
        })
    };

    tokio::time::sleep(Duration::from_millis(50)).await;
    let connection = net::dial(&options, code.room(), &cancel).await.unwrap();
    let (read, write) = connection.into_split();
    let mut channel = Channel::establish(read, write, Role::Receiver, &code)
        .await
        .unwrap();
    let pending = transfer::begin(
        &mut channel,
        receive_options(destination.path(), ConflictPolicy::Rename),
    )
    .await
    .unwrap();

    // Pull the plug part-way through.
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        trigger.cancel();
    });

    let result = pending.accept(&Silent, &cancel).await;
    let _ = sender.await;

    assert!(
        result.is_err(),
        "a cancelled transfer must not report success"
    );
    assert!(
        !destination.path().join("big.bin").exists(),
        "no finished-looking file may be left behind"
    );
    let leftovers = common::tree(destination.path());
    assert!(
        leftovers.iter().all(|p| !p.ends_with("rusp-part")),
        "part files must be cleaned up: {leftovers:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_frame_larger_than_the_limit_is_refused_before_it_is_allocated() {
    let relay = TestRelay::start().await;
    let (sender, receiver) = paired_sockets(&relay, "hugh").await;
    let code = code("hugh");

    // Announce a four-gigabyte frame right after the magic.
    let attacker = tokio::spawn(async move {
        let mut sender = sender;
        sender.write_all(b"RUSP").await.unwrap();
        sender.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let _ = sender.flush().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let (read, write) = receiver.into_split();
    let err = Channel::establish(read, write, Role::Receiver, &code)
        .await
        .expect_err("an oversized frame must be refused");
    assert!(
        matches!(err, Error::Protocol(ProtocolError::FrameTooLarge { .. })),
        "{err}"
    );
    let _ = attacker.await;
}

/// A hostile peer can declare an enormous array in a few bytes. Decoding must
/// not trust that number: a five-byte lie must not turn into a multi-gigabyte
/// allocation.
fn control_frame_claiming_a_huge_array(variant: &str, field: &str) -> Vec<u8> {
    use rusp::protocol::message::kind;
    let mut v = vec![kind::CONTROL];
    v.push(0x81); // fixmap, one pair: the externally tagged enum variant
    v.push(0xa0 | variant.len() as u8);
    v.extend_from_slice(variant.as_bytes());
    v.push(0x81); // fixmap, one pair: the field
    v.push(0xa0 | field.len() as u8);
    v.extend_from_slice(field.as_bytes());
    v.push(0xdd); // array32 header...
    v.extend_from_slice(&u32::MAX.to_be_bytes()); // ...claiming four billion items
    v
}

#[test]
fn a_declared_but_absent_array_is_refused_without_allocating() {
    for (variant, field) in [("Offer", "entries"), ("Accept", "wanted")] {
        let payload = control_frame_claiming_a_huge_array(variant, field);
        assert!(
            payload.len() < 32,
            "the whole attack is {} bytes",
            payload.len()
        );
        let err = rusp::protocol::message::decode_incoming(&payload)
            .expect_err("a four-billion-item claim backed by nothing must be refused");
        assert!(
            matches!(err, Error::Protocol(ProtocolError::Malformed(_))),
            "{variant}/{field}: {err}"
        );
    }
}
