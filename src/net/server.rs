//! The relay server behind `rusp relay`.
//!
//! Two clients name the same room; the relay puts them together and then
//! copies bytes. It never holds a key, never sees a code, and cannot decrypt
//! anything it forwards.
//!
//! # Refusing rather than evicting
//!
//! When a room already has two occupants, or the relay is at its room limit, a
//! new client is **refused**. It would be easy instead to evict the oldest
//! waiting room to make space — but then anyone who can reach the relay could
//! knock other people's transfers over just by opening rooms. Refusing keeps a
//! stranger from affecting a transfer that is already under way.
//!
//! # Limits
//!
//! * a semaphore caps how many connections may be mid-handshake at once,
//! * a handshake that stalls is dropped after [`HANDSHAKE_TIMEOUT`],
//! * a room with only one occupant expires after the configured timeout,
//! * a waiting client that hangs up frees its room immediately,
//! * room names must be valid [`RoomId`]s, and tokens are length-limited
//!   before they are compared.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex, Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::code::RoomId;
use crate::error::{Error, NetworkError, Result};
use crate::net::relay::{self, Join, RefusalReason, RelayReply, MAX_TOKEN_LEN, RELAY_MAX_FRAME};
use crate::protocol::frame::{FrameBuf, FrameReader, FrameWriter};

/// How long a client has to complete the relay handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum number of connections allowed to be mid-handshake at once.
pub const MAX_PENDING_HANDSHAKES: usize = 256;

fn server_name() -> String {
    format!("rusp-relay/{}", crate::VERSION)
}

/// Relay server settings.
#[derive(Debug, Clone)]
pub struct RelaySettings {
    /// Address to listen on.
    pub listen: String,
    /// Token every client must present, if any.
    pub token: Option<Zeroizing<String>>,
    /// Maximum number of rooms held at once.
    pub max_rooms: usize,
    /// How long a room with only one occupant is kept.
    pub room_timeout: Duration,
}

impl Default for RelaySettings {
    fn default() -> Self {
        RelaySettings {
            listen: format!("0.0.0.0:{}", crate::config::DEFAULT_RELAY_PORT),
            token: None,
            max_rooms: 1024,
            room_timeout: Duration::from_secs(600),
        }
    }
}

/// Counters a relay operator can look at.
#[derive(Debug, Default)]
pub struct RelayMetrics {
    /// Connections accepted.
    pub accepted: AtomicU64,
    /// Pairs successfully joined.
    pub paired: AtomicU64,
    /// Clients turned away.
    pub refused: AtomicU64,
}

impl RelayMetrics {
    /// Read the counters.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.accepted.load(Ordering::Relaxed),
            self.paired.load(Ordering::Relaxed),
            self.refused.load(Ordering::Relaxed),
        )
    }
}

/// What is going on in a room.
enum Room {
    /// One peer is waiting; sending it a stream hands over its partner.
    Waiting(oneshot::Sender<TcpStream>),
    /// Two peers are paired and bytes are flowing.
    Paired,
}

struct Shared {
    rooms: Mutex<HashMap<String, Room>>,
    max_rooms: usize,
    room_timeout: Duration,
    token: Option<Zeroizing<String>>,
    metrics: Arc<RelayMetrics>,
}

/// A bound relay, ready to serve.
pub struct Relay {
    listener: TcpListener,
    shared: Arc<Shared>,
    permits: Arc<Semaphore>,
}

impl Relay {
    /// Bind the relay's listening socket.
    pub async fn bind(settings: RelaySettings) -> Result<Self> {
        let listener = TcpListener::bind(&settings.listen)
            .await
            .map_err(|source| {
                Error::Network(NetworkError::Bind {
                    addr: settings.listen.clone(),
                    source,
                })
            })?;
        Ok(Relay {
            listener,
            shared: Arc::new(Shared {
                rooms: Mutex::new(HashMap::new()),
                max_rooms: settings.max_rooms.max(1),
                room_timeout: settings.room_timeout,
                token: settings.token,
                metrics: Arc::new(RelayMetrics::default()),
            }),
            permits: Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES)),
        })
    }

    /// The address the relay is actually listening on.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|e| Error::io("read relay address", e))
    }

    /// Shared counters, readable while the relay runs.
    pub fn metrics(&self) -> Arc<RelayMetrics> {
        Arc::clone(&self.shared.metrics)
    }

    /// Serve until cancelled.
    pub async fn run(self, cancel: CancellationToken) -> Result<()> {
        loop {
            let accepted = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                result = self.listener.accept() => result,
            };

            let (stream, _peer) = match accepted {
                Ok(pair) => pair,
                // A failed accept — fd exhaustion, or a client vanishing
                // between SYN and accept — must not take the relay down.
                Err(_) => continue,
            };
            let _ = stream.set_nodelay(true);
            self.shared.metrics.accepted.fetch_add(1, Ordering::Relaxed);

            let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
                // At the handshake limit: drop rather than queue unbounded work.
                self.shared.metrics.refused.fetch_add(1, Ordering::Relaxed);
                continue;
            };

            let shared = Arc::clone(&self.shared);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = serve_client(stream, shared, cancel).await;
            });
        }
    }
}

type Reader = FrameReader<ReadHalf<TcpStream>>;
type Writer = FrameWriter<WriteHalf<TcpStream>>;

async fn serve_client(
    stream: TcpStream,
    shared: Arc<Shared>,
    cancel: CancellationToken,
) -> Result<()> {
    let (read, write) = tokio::io::split(stream);
    let mut reader = FrameReader::new(read, RELAY_MAX_FRAME);
    let mut writer = FrameWriter::new(write, RELAY_MAX_FRAME);
    let mut buf = FrameBuf::with_capacity(RELAY_MAX_FRAME);
    let mut payload = Vec::new();

    // Everything up to registration is on a clock, so a client cannot hold a
    // handshake slot open by simply not talking.
    let join: Join = match tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        relay::read_magic(&mut reader).await?;
        reader.read_frame_required(&mut payload).await?;
        relay::decode::<Join>(&payload)
    })
    .await
    {
        Ok(Ok(join)) => join,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(NetworkError::Timeout(HANDSHAKE_TIMEOUT).into()),
    };

    if let Some(expected) = &shared.token {
        let presented = join.token.as_deref().unwrap_or_default();
        if presented.len() > MAX_TOKEN_LEN || !token_matches(expected, presented) {
            return refuse(
                &shared,
                &mut writer,
                &mut buf,
                RefusalReason::Unauthorised,
                String::new(),
            )
            .await;
        }
    }

    let room = match RoomId::new(join.room) {
        Ok(room) => room,
        Err(e) => {
            return refuse(
                &shared,
                &mut writer,
                &mut buf,
                RefusalReason::BadRoom,
                e.to_string(),
            )
            .await
        }
    };

    // --- claim or join the room ------------------------------------------
    let (ready_tx, ready_rx) = oneshot::channel();
    let partner = {
        let mut rooms = shared.rooms.lock().await;
        let at_capacity = rooms.len() >= shared.max_rooms;
        match rooms.entry(room.as_str().to_owned()) {
            Entry::Occupied(mut occupied) => match occupied.get() {
                Room::Paired => {
                    drop(rooms);
                    return refuse(
                        &shared,
                        &mut writer,
                        &mut buf,
                        RefusalReason::RoomBusy,
                        String::new(),
                    )
                    .await;
                }
                Room::Waiting(_) => {
                    let Room::Waiting(waiting) = occupied.insert(Room::Paired) else {
                        unreachable!("just matched Waiting")
                    };
                    Some(waiting)
                }
            },
            Entry::Vacant(vacant) => {
                if at_capacity {
                    drop(rooms);
                    return refuse(
                        &shared,
                        &mut writer,
                        &mut buf,
                        RefusalReason::Overloaded,
                        String::new(),
                    )
                    .await;
                }
                vacant.insert(Room::Waiting(ready_tx));
                None
            }
        }
    };

    match partner {
        // We are the second peer: tell our client, then hand our socket to the
        // task that is already waiting. It does the copying.
        Some(waiting) => {
            relay::encode(&RelayReply::Paired, &mut buf)?;
            writer.write_buf(&mut buf).await?;
            writer.flush().await?;
            let stream = reader.into_inner().unsplit(writer.into_inner());
            if waiting.send(stream).is_err() {
                // The waiting peer gave up in the moment between our lookup
                // and the hand-off; leave the room clean for the next pair.
                shared.rooms.lock().await.remove(room.as_str());
            }
            Ok(())
        }
        // We are the first peer: wait to be claimed.
        None => {
            let result =
                wait_for_partner(&shared, &room, reader, writer, &mut buf, ready_rx, cancel).await;
            shared.rooms.lock().await.remove(room.as_str());
            result
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_partner(
    shared: &Arc<Shared>,
    room: &RoomId,
    mut reader: Reader,
    mut writer: Writer,
    buf: &mut FrameBuf,
    ready_rx: oneshot::Receiver<TcpStream>,
    cancel: CancellationToken,
) -> Result<()> {
    relay::encode(
        &RelayReply::Welcome {
            server: server_name(),
        },
        buf,
    )?;
    writer.write_buf(buf).await?;
    writer.flush().await?;

    let mut scratch = Vec::new();
    let partner = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(()),
        // A waiting client is not supposed to say anything. If a read
        // completes at all it has either hung up or is misbehaving, and
        // either way its room should be freed now rather than at timeout.
        _ = reader.read_frame(&mut scratch) => return Ok(()),
        claimed = tokio::time::timeout(shared.room_timeout, ready_rx) => match claimed {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => return Ok(()),
            Err(_) => return Err(NetworkError::Timeout(shared.room_timeout).into()),
        },
    };

    relay::encode(&RelayReply::Paired, buf)?;
    writer.write_buf(buf).await?;
    writer.flush().await?;

    shared.metrics.paired.fetch_add(1, Ordering::Relaxed);

    let mut ours = reader.into_inner().unsplit(writer.into_inner());
    let mut theirs = partner;
    // From here the relay is a pipe. It has no idea what it is carrying, and
    // could not read it if it tried.
    let copy = tokio::io::copy_bidirectional(&mut ours, &mut theirs);
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(()),
        result = copy => {
            result.map(|_| ()).map_err(|e| Error::io(format!("relay room {room}"), e))
        }
    }
}

/// Compare tokens without leaking how far they matched.
///
/// BLAKE3's `Hash` equality is constant time, so hashing both sides gives a
/// comparison that does not depend on the contents or the shared prefix.
fn token_matches(expected: &str, presented: &str) -> bool {
    blake3::hash(expected.as_bytes()) == blake3::hash(presented.as_bytes())
}

async fn refuse(
    shared: &Arc<Shared>,
    writer: &mut Writer,
    buf: &mut FrameBuf,
    reason: RefusalReason,
    detail: String,
) -> Result<()> {
    shared.metrics.refused.fetch_add(1, Ordering::Relaxed);
    relay::encode(&RelayReply::Refused { reason, detail }, buf)?;
    writer.write_buf(buf).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn start(settings: RelaySettings) -> (String, CancellationToken, Arc<RelayMetrics>) {
        let settings = RelaySettings {
            listen: "127.0.0.1:0".into(),
            ..settings
        };
        let relay = Relay::bind(settings).await.unwrap();
        let addr = relay.local_addr().unwrap().to_string();
        let metrics = relay.metrics();
        let cancel = CancellationToken::new();
        tokio::spawn(relay.run(cancel.clone()));
        (addr, cancel, metrics)
    }

    fn room(s: &str) -> RoomId {
        RoomId::new(s).unwrap()
    }

    fn config(addr: &str, token: Option<&str>) -> RelayConfig {
        RelayConfig::new(addr, token.map(str::to_owned))
    }

    async fn join(
        addr: &str,
        token: Option<&str>,
        room_id: &RoomId,
        cancel: &CancellationToken,
    ) -> Result<TcpStream> {
        relay::rendezvous(
            &config(addr, token),
            room_id,
            Duration::from_secs(5),
            cancel,
        )
        .await
    }

    #[tokio::test]
    async fn two_peers_are_paired_and_bytes_flow_both_ways() {
        let (addr, cancel, metrics) = start(RelaySettings::default()).await;
        let r = room("k7m2");

        let a_cancel = cancel.clone();
        let a_addr = addr.clone();
        let a_room = r.clone();
        let a = tokio::spawn(async move { join(&a_addr, None, &a_room, &a_cancel).await });

        // Give the first peer a moment to register the room.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut b = join(&addr, None, &r, &cancel).await.unwrap();
        let mut a = a.await.unwrap().unwrap();

        a.write_all(b"hello from a").await.unwrap();
        a.flush().await.unwrap();
        let mut got = [0u8; 12];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello from a");

        b.write_all(b"and back").await.unwrap();
        b.flush().await.unwrap();
        let mut got = [0u8; 8];
        a.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"and back");

        assert_eq!(metrics.snapshot().1, 1, "one pair");
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_third_peer_is_refused_rather_than_evicting_anyone() {
        let (addr, cancel, _) = start(RelaySettings::default()).await;
        let r = room("k7m2");

        let a_cancel = cancel.clone();
        let a_addr = addr.clone();
        let a_room = r.clone();
        let a = tokio::spawn(async move { join(&a_addr, None, &a_room, &a_cancel).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut b = join(&addr, None, &r, &cancel).await.unwrap();
        let mut a = a.await.unwrap().unwrap();

        let err = join(&addr, None, &r, &cancel).await.unwrap_err();
        assert!(
            matches!(err, Error::Network(NetworkError::RoomBusy(_))),
            "{err}"
        );
        assert!(err.hint().is_some());

        // The established pair is untouched.
        a.write_all(b"still here").await.unwrap();
        a.flush().await.unwrap();
        let mut got = [0u8; 10];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"still here");
        cancel.cancel();
    }

    #[tokio::test]
    async fn different_rooms_do_not_meet() {
        let (addr, cancel, _) = start(RelaySettings {
            room_timeout: Duration::from_millis(300),
            ..RelaySettings::default()
        })
        .await;

        let a_cancel = cancel.clone();
        let a_addr = addr.clone();
        let a = tokio::spawn(async move { join(&a_addr, None, &room("aaaa"), &a_cancel).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let b_cancel = cancel.clone();
        let b_addr = addr.clone();
        let b = tokio::spawn(async move { join(&b_addr, None, &room("bbbb"), &b_cancel).await });

        for task in [a, b] {
            let err = task.await.unwrap().unwrap_err();
            assert!(
                matches!(err, Error::Protocol(_) | Error::Network(_)),
                "{err}"
            );
        }
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_token_is_required_when_configured() {
        let (addr, cancel, metrics) = start(RelaySettings {
            token: Some(Zeroizing::new("hunter2".into())),
            ..RelaySettings::default()
        })
        .await;
        let r = room("k7m2");

        for wrong in [None, Some(""), Some("hunter3"), Some("hunter2 ")] {
            let err = join(&addr, wrong, &r, &cancel).await.unwrap_err();
            assert!(
                matches!(err, Error::Network(NetworkError::RelayRejected(_))),
                "{wrong:?}: {err}"
            );
        }
        assert!(metrics.snapshot().2 >= 4);

        // The right token gets in.
        let a_cancel = cancel.clone();
        let a_addr = addr.clone();
        let a_room = r.clone();
        let a =
            tokio::spawn(async move { join(&a_addr, Some("hunter2"), &a_room, &a_cancel).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(join(&addr, Some("hunter2"), &r, &cancel).await.is_ok());
        assert!(a.await.unwrap().is_ok());
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_room_limit_refuses_new_rooms() {
        let (addr, cancel, _) = start(RelaySettings {
            max_rooms: 1,
            room_timeout: Duration::from_secs(5),
            ..RelaySettings::default()
        })
        .await;

        let a_cancel = cancel.clone();
        let a_addr = addr.clone();
        let _a = tokio::spawn(async move { join(&a_addr, None, &room("aaaa"), &a_cancel).await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let err = join(&addr, None, &room("bbbb"), &cancel).await.unwrap_err();
        assert!(
            matches!(err, Error::Network(NetworkError::RelayRejected(_))),
            "{err}"
        );
        assert!(err.to_string().contains("capacity"), "{err}");
        cancel.cancel();
    }

    #[tokio::test]
    async fn an_invalid_room_name_is_refused() {
        let (addr, cancel, _) = start(RelaySettings::default()).await;
        let mut stream = TcpStream::connect(&addr).await.unwrap();
        stream.write_all(&relay::RELAY_MAGIC).await.unwrap();

        let mut buf = FrameBuf::with_capacity(256);
        relay::encode(
            &Join {
                room: "NOT A ROOM".into(),
                token: None,
            },
            &mut buf,
        )
        .unwrap();
        let frame = buf.finish(RELAY_MAX_FRAME).unwrap().to_vec();
        stream.write_all(&frame).await.unwrap();

        let (read, _write) = stream.into_split();
        let mut reader = FrameReader::new(read, RELAY_MAX_FRAME);
        let mut payload = Vec::new();
        reader.read_frame_required(&mut payload).await.unwrap();
        assert!(matches!(
            relay::decode::<RelayReply>(&payload).unwrap(),
            RelayReply::Refused {
                reason: RefusalReason::BadRoom,
                ..
            }
        ));
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_non_relay_client_is_dropped() {
        let (addr, cancel, _) = start(RelaySettings::default()).await;
        let mut stream = TcpStream::connect(&addr).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        // The relay closes the connection without answering.
        let mut sink = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut sink)).await;
        assert!(read.is_ok(), "relay should hang up on a non-relay client");
        assert!(sink.is_empty(), "relay should not answer: {sink:?}");
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_waiting_room_expires() {
        let (addr, cancel, _) = start(RelaySettings {
            room_timeout: Duration::from_millis(200),
            ..RelaySettings::default()
        })
        .await;
        let err = join(&addr, None, &room("k7m2"), &cancel).await.unwrap_err();
        assert!(
            matches!(err, Error::Protocol(_) | Error::Network(_)),
            "{err}"
        );

        // ...and the room is free again afterwards.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let r = room("k7m2");
        let a_cancel = cancel.clone();
        let a_addr = addr.clone();
        let a_room = r.clone();
        let a = tokio::spawn(async move { join(&a_addr, None, &a_room, &a_cancel).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(join(&addr, None, &r, &cancel).await.is_ok());
        assert!(a.await.unwrap().is_ok());
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_waiting_client_hanging_up_frees_the_room_at_once() {
        let (addr, cancel, _) = start(RelaySettings {
            // Long enough that only the hang-up path can free the room in time.
            room_timeout: Duration::from_secs(30),
            ..RelaySettings::default()
        })
        .await;
        let r = room("k7m2");

        let first = join(&addr, None, &r, &cancel);
        let first = tokio::time::timeout(Duration::from_millis(300), first).await;
        assert!(first.is_err(), "should still be waiting");
        drop(first);

        // The abandoned room must not block a fresh pair.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let a_cancel = cancel.clone();
        let a_addr = addr.clone();
        let a_room = r.clone();
        let a = tokio::spawn(async move { join(&a_addr, None, &a_room, &a_cancel).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(join(&addr, None, &r, &cancel).await.is_ok());
        assert!(a.await.unwrap().is_ok());
        cancel.cancel();
    }

    #[tokio::test]
    async fn cancelling_a_join_returns_promptly() {
        let (addr, cancel, _) = start(RelaySettings::default()).await;
        let join_cancel = CancellationToken::new();
        let c = join_cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            c.cancel();
        });
        let err = join(&addr, None, &room("k7m2"), &join_cancel)
            .await
            .unwrap_err();
        assert!(err.is_cancelled(), "{err}");
        cancel.cancel();
    }

    #[tokio::test]
    async fn an_unreachable_relay_reports_the_address() {
        let cancel = CancellationToken::new();
        // Port 1 on loopback is not listening on any sane machine.
        let err = relay::rendezvous(
            &config("127.0.0.1:1", None),
            &room("k7m2"),
            Duration::from_secs(2),
            &cancel,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("127.0.0.1:1"), "{err}");
    }

    #[test]
    fn token_comparison_accepts_only_the_exact_token() {
        assert!(token_matches("hunter2", "hunter2"));
        assert!(!token_matches("hunter2", "hunter3"));
        assert!(!token_matches("hunter2", "hunter"));
        assert!(!token_matches("hunter2", "hunter22"));
        assert!(!token_matches("hunter2", ""));
        assert!(token_matches("", ""));
    }
}
