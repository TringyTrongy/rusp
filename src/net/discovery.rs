//! Finding a peer on the local network.
//!
//! The receiver multicasts a short query naming the room it is looking for.
//! A sender holding that room answers, by unicast, with the TCP port it is
//! listening on. The receiver then connects directly — no relay, no
//! configuration, and the bytes never leave the network segment.
//!
//! Queries also go to the IPv4 broadcast address, because plenty of networks
//! forward broadcast but filter multicast.
//!
//! # What this exposes
//!
//! A discovery datagram contains the room identifier and nothing else. The
//! room is the public half of a transfer code (see [`crate::code`]); the
//! secret words never appear on the wire here or anywhere else. Somebody
//! watching the local network learns that a transfer is happening and which
//! room it uses, exactly as a relay operator would.
//!
//! An active attacker on the same network can answer a query with their own
//! address and take the sender's place. They cannot read the transfer — they
//! do not have the code, and the handshake fails — but they can stop it from
//! happening. That is a denial of service, and it is no worse than what
//! anybody who can forge ARP on the same segment can already do.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::code::RoomId;
use crate::config::DISCOVERY_MULTICAST_V4;
use crate::error::{Error, IoContext, NetworkError, Result};

/// Prefix on every discovery datagram, so unrelated traffic on the port is
/// discarded before it reaches a parser.
pub const DISCOVERY_MAGIC: [u8; 6] = *b"RUSPDS";

/// Largest discovery datagram accepted. Real ones are well under a hundred
/// bytes; anything larger is not ours.
pub const MAX_DATAGRAM: usize = 512;

/// How often the receiver repeats its query while waiting.
const QUERY_INTERVAL: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum DiscoveryMessage {
    /// "Is anybody offering this room?"
    Query { room: String },
    /// "Yes, connect to me on this TCP port."
    Offer { room: String, port: u16 },
}

fn encode(msg: &DiscoveryMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&DISCOVERY_MAGIC);
    // Discovery messages are built from a validated room and a port, so
    // encoding them cannot fail.
    out.extend_from_slice(&rmp_serde::to_vec_named(msg).unwrap_or_default());
    out
}

fn decode(datagram: &[u8]) -> Option<DiscoveryMessage> {
    let body = datagram.strip_prefix(&DISCOVERY_MAGIC[..])?;
    rmp_serde::from_slice(body).ok()
}

/// Bind the shared discovery port for listening.
///
/// `SO_REUSEADDR` (and `SO_REUSEPORT` where it exists) lets several senders on
/// one machine listen on the same port, which is what makes two concurrent
/// `rusp send` invocations work.
fn bind_listener(port: u16) -> Result<UdpSocket> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    let bind_err = |e: std::io::Error| {
        Error::Network(NetworkError::Bind {
            addr: format!("udp {addr}"),
            source: e,
        })
    };

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(bind_err)?;
    socket.set_reuse_address(true).map_err(bind_err)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true).map_err(bind_err)?;
    socket.set_nonblocking(true).map_err(bind_err)?;
    socket.bind(&addr.into()).map_err(bind_err)?;

    // A filtered or absent multicast route is not fatal: broadcast queries
    // still reach us.
    let _ = socket.join_multicast_v4(&DISCOVERY_MULTICAST_V4, &Ipv4Addr::UNSPECIFIED);

    UdpSocket::from_std(socket.into()).map_err(bind_err)
}

/// Answer discovery queries for `room` with `tcp_port`, until cancelled.
///
/// Returns only on cancellation or an unrecoverable socket error. Intended to
/// be spawned alongside the sender's TCP listener.
pub async fn serve(
    discovery_port: u16,
    room: RoomId,
    tcp_port: u16,
    cancel: CancellationToken,
) -> Result<()> {
    let socket = bind_listener(discovery_port)?;
    let reply = encode(&DiscoveryMessage::Offer {
        room: room.as_str().to_owned(),
        port: tcp_port,
    });
    let mut datagram = vec![0u8; MAX_DATAGRAM];

    loop {
        let received = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            result = socket.recv_from(&mut datagram) => result,
        };

        let (len, from) = match received {
            Ok(pair) => pair,
            // A datagram that could not be received says nothing about the
            // next one; a peer resetting an ICMP port-unreachable should not
            // take the responder down.
            Err(_) => continue,
        };

        if let Some(DiscoveryMessage::Query { room: wanted }) = decode(&datagram[..len]) {
            if wanted == room.as_str() {
                let _ = socket.send_to(&reply, from).await;
            }
        }
    }
}

/// Look for a peer offering `room` on the local network.
///
/// Returns the address to connect to, or [`NetworkError::Timeout`] if nobody
/// answered within `patience`.
pub async fn find(
    discovery_port: u16,
    room: &RoomId,
    patience: Duration,
    cancel: &CancellationToken,
) -> Result<SocketAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|e| {
            Error::Network(NetworkError::Bind {
                addr: "udp 0.0.0.0:0".into(),
                source: e,
            })
        })?;
    // Link-local scope: discovery is for machines on the same segment.
    let _ = socket.set_multicast_ttl_v4(1);
    let _ = socket.set_broadcast(true);

    let query = encode(&DiscoveryMessage::Query {
        room: room.as_str().to_owned(),
    });
    // Networks disagree about which of these they carry: some filter
    // multicast, some filter broadcast, and a macOS machine may refuse both
    // when it has no usable route. The loopback address covers the remaining
    // case of two Rusp processes on one machine, which is both a real way to
    // use this and what makes the tests deterministic everywhere.
    let targets: [SocketAddr; 3] = [
        SocketAddrV4::new(DISCOVERY_MULTICAST_V4, discovery_port).into(),
        SocketAddrV4::new(Ipv4Addr::BROADCAST, discovery_port).into(),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, discovery_port).into(),
    ];

    let mut datagram = vec![0u8; MAX_DATAGRAM];
    let deadline = tokio::time::Instant::now() + patience;

    loop {
        // Cancellation is checked before any network work: a platform that
        // refuses to send must still report the cancellation rather than a
        // timeout.
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }

        let mut sent = false;
        for target in targets {
            if socket.send_to(&query, target).await.is_ok() {
                sent = true;
            }
        }
        if !sent {
            return Err(NetworkError::Timeout(patience).into());
        }

        let window =
            QUERY_INTERVAL.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        let listen_until = tokio::time::Instant::now() + window;

        loop {
            let remaining = listen_until.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let received = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(Error::Cancelled),
                result = tokio::time::timeout(remaining, socket.recv_from(&mut datagram)) => result,
            };

            let Ok(Ok((len, from))) = received else {
                break;
            };
            if let Some(DiscoveryMessage::Offer {
                room: offered,
                port,
            }) = decode(&datagram[..len])
            {
                if offered == room.as_str() && port != 0 {
                    return Ok(SocketAddr::new(from.ip(), port));
                }
            }
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(NetworkError::Timeout(patience).into());
        }
    }
}

/// Bind a TCP listener on an ephemeral port for direct connections.
pub async fn bind_direct_listener() -> Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .path_ctx("listen on", "0.0.0.0:0")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room(s: &str) -> RoomId {
        RoomId::new(s).unwrap()
    }

    #[test]
    fn messages_round_trip_through_a_datagram() {
        for msg in [
            DiscoveryMessage::Query {
                room: "k7m2".into(),
            },
            DiscoveryMessage::Offer {
                room: "k7m2".into(),
                port: 40_000,
            },
        ] {
            let bytes = encode(&msg);
            assert!(bytes.starts_with(&DISCOVERY_MAGIC));
            assert!(bytes.len() < MAX_DATAGRAM);
            assert_eq!(decode(&bytes), Some(msg));
        }
    }

    #[test]
    fn foreign_traffic_on_the_port_is_ignored() {
        // Anything without our magic, and anything with the magic but a body
        // that is not one of our messages, must decode to None rather than
        // panic or misparse.
        assert_eq!(decode(b""), None);
        assert_eq!(decode(b"not ours at all"), None);
        assert_eq!(decode(&DISCOVERY_MAGIC), None);
        assert_eq!(decode(b"RUSPDS\xc1\xc1\xc1"), None);
        let mut truncated = encode(&DiscoveryMessage::Query { room: "k".into() });
        for cut in 0..truncated.len() {
            let _ = decode(&truncated[..cut]);
        }
        truncated.push(0xFF);
        let _ = decode(&truncated);
    }

    #[tokio::test]
    async fn a_receiver_finds_a_sender() {
        // Port 0 is not usable for the shared listener, so pick a high port
        // and accept that a busy CI machine might already hold it.
        let port = 39_871;
        let Ok(_probe) = bind_listener(port) else {
            eprintln!("discovery port unavailable; skipping");
            return;
        };
        drop(_probe);

        let cancel = CancellationToken::new();
        let responder = tokio::spawn(serve(port, room("k7m2"), 45_678, cancel.clone()));

        let found = find(port, &room("k7m2"), Duration::from_secs(3), &cancel)
            .await
            .expect("should find the sender");
        assert_eq!(found.port(), 45_678);

        cancel.cancel();
        responder.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_different_room_is_not_answered() {
        let port = 39_872;
        let Ok(_probe) = bind_listener(port) else {
            eprintln!("discovery port unavailable; skipping");
            return;
        };
        drop(_probe);

        let cancel = CancellationToken::new();
        let responder = tokio::spawn(serve(port, room("aaaa"), 45_678, cancel.clone()));

        let err = find(port, &room("bbbb"), Duration::from_millis(600), &cancel)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Network(NetworkError::Timeout(_))),
            "{err}"
        );

        cancel.cancel();
        responder.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn searching_stops_when_cancelled() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = find(39_873, &room("k7m2"), Duration::from_secs(30), &cancel)
            .await
            .unwrap_err();
        assert!(err.is_cancelled(), "{err}");
    }

    #[tokio::test]
    async fn the_direct_listener_gets_a_real_port() {
        let listener = bind_direct_listener().await.unwrap();
        assert_ne!(listener.local_addr().unwrap().port(), 0);
    }
}
