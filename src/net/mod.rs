//! Getting two peers connected.
//!
//! This layer's only job is to produce a byte stream between sender and
//! receiver. It knows nothing about the protocol that will run over it.
//!
//! # Paths, in the order they are tried
//!
//! 1. **Local network.** The receiver multicasts a query for the room; a
//!    sender on the same segment answers with its port and the receiver
//!    connects straight to it. No relay, no configuration, and the data never
//!    leaves the network.
//! 2. **Relay.** Both sides connect out to a relay and meet in a room. This
//!    works from behind almost any NAT or firewall, because both ends make
//!    outbound connections.
//!
//! The **receiver chooses** which path to use; the sender waits on both at
//! once and takes whichever the receiver actually used. Having one side decide
//! is what keeps the two from picking different paths.
//!
//! # What is not here yet
//!
//! There is no UDP or QUIC hole punching, so two peers behind separate NATs
//! need a relay. That is a real limitation and it is listed in the README's
//! roadmap rather than papered over. When it arrives it becomes another
//! variant of [`Route`] and another arm in the races below — nothing above
//! this module has to change.

pub mod discovery;
pub mod relay;
pub mod server;

use std::fmt;
use std::future::pending;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::code::RoomId;
use crate::config::{Config, RelayConfig};
use crate::error::{Error, IoContext, NetworkError, Result};

/// How long the receiver looks on the local network before falling back to a
/// relay. Short, because a relay is waiting and a local peer answers in
/// milliseconds when it is there at all.
pub const LAN_PATIENCE_WITH_RELAY: Duration = Duration::from_millis(1500);

/// How a connection was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Direct TCP to a peer found on the local network.
    Lan,
    /// Through a relay.
    Relay,
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Route::Lan => "local network",
            Route::Relay => "relay",
        })
    }
}

/// A byte stream to the peer, plus how we got it.
#[derive(Debug)]
pub struct Connection {
    stream: TcpStream,
    route: Route,
    peer: SocketAddr,
}

impl Connection {
    fn new(stream: TcpStream, route: Route) -> Result<Self> {
        // Every frame is written with a single `write_all`, so waiting for
        // more data to coalesce only adds latency.
        let _ = stream.set_nodelay(true);
        let peer = stream.peer_addr().ctx("read peer address")?;
        Ok(Connection {
            stream,
            route,
            peer,
        })
    }

    /// Which path this connection took.
    pub fn route(&self) -> Route {
        self.route
    }

    /// The far end of the socket. For a relayed connection this is the relay,
    /// not the peer.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// One line describing the connection, for `--verbose`.
    pub fn describe(&self) -> String {
        match self.route {
            Route::Lan => format!("connected directly to {} on the local network", self.peer),
            Route::Relay => format!("connected through the relay at {}", self.peer),
        }
    }

    /// Split into halves for the protocol layer.
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        self.stream.into_split()
    }
}

/// Everything the networking layer needs to know.
#[derive(Debug, Clone)]
pub struct NetOptions {
    /// Relay to use, if one is configured.
    pub relay: Option<RelayConfig>,
    /// Whether to use local-network discovery.
    pub lan: bool,
    /// UDP port discovery runs on.
    pub discovery_port: u16,
    /// Limit on a single connection attempt.
    pub connect_timeout: Duration,
    /// Limit on the whole wait for a peer.
    pub rendezvous_timeout: Duration,
}

impl NetOptions {
    /// Build options from resolved configuration.
    pub fn from_config(config: &Config) -> Self {
        NetOptions {
            relay: config.relay.clone(),
            lan: config.lan_discovery,
            discovery_port: config.discovery_port,
            connect_timeout: config.connect_timeout,
            rendezvous_timeout: config.rendezvous_timeout,
        }
    }

    /// True when no path to a peer is available at all.
    pub fn is_unroutable(&self) -> bool {
        !self.lan && self.relay.is_none()
    }

    /// How long to spend looking on the local network before giving up on it.
    fn lan_patience(&self) -> Duration {
        match self.relay {
            // With a relay waiting, do not stall the transfer looking locally.
            Some(_) => LAN_PATIENCE_WITH_RELAY.min(self.rendezvous_timeout),
            // Without one, the local network is the only hope, so wait it out.
            None => self.rendezvous_timeout,
        }
    }
}

/// The sender's half of the rendezvous: listen locally and wait at the relay,
/// and take whichever the receiver uses.
#[derive(Debug)]
pub struct SenderRendezvous {
    options: NetOptions,
    room: RoomId,
    listener: Option<tokio::net::TcpListener>,
    /// Cancels the discovery responder when this rendezvous is dropped.
    discovery: CancellationToken,
    /// Remembered so a relay problem can be reported even when the local
    /// network was also being tried.
    relay_error: Option<Error>,
}

impl Drop for SenderRendezvous {
    fn drop(&mut self) {
        self.discovery.cancel();
    }
}

impl SenderRendezvous {
    /// Start listening. Call this before showing the user their code, so a
    /// receiver that reacts instantly still finds somebody home.
    pub async fn open(options: NetOptions, room: RoomId) -> Result<Self> {
        if options.is_unroutable() {
            return Err(NetworkError::NoRoute.into());
        }

        let discovery = CancellationToken::new();
        let listener = if options.lan {
            let listener = discovery::bind_direct_listener().await?;
            let port = listener.local_addr().ctx("read listener address")?.port();
            tokio::spawn(discovery::serve(
                options.discovery_port,
                room.clone(),
                port,
                discovery.clone(),
            ));
            Some(listener)
        } else {
            None
        };

        Ok(SenderRendezvous {
            options,
            room,
            listener,
            discovery,
            relay_error: None,
        })
    }

    /// The TCP port local peers are told to connect to, if any.
    pub fn lan_port(&self) -> Option<u16> {
        self.listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
    }

    /// Wait for a peer to arrive by either path.
    ///
    /// May be called again after a connection turns out not to be a real peer;
    /// each call re-registers with the relay.
    pub async fn accept(&mut self, cancel: &CancellationToken) -> Result<Connection> {
        let deadline = self.options.rendezvous_timeout;
        match tokio::time::timeout(deadline, self.accept_inner(cancel)).await {
            Ok(result) => result,
            Err(_) => Err(self
                .relay_error
                .take()
                .unwrap_or_else(|| NetworkError::Timeout(deadline).into())),
        }
    }

    async fn accept_inner(&mut self, cancel: &CancellationToken) -> Result<Connection> {
        loop {
            let listener = self.listener.as_ref();
            let lan = async {
                match listener {
                    Some(listener) => listener.accept().await.ctx("accept a local connection"),
                    None => pending().await,
                }
            };
            let via_relay = async {
                match &self.options.relay {
                    Some(relay) => Some(
                        relay::rendezvous(relay, &self.room, self.options.connect_timeout, cancel)
                            .await,
                    ),
                    None => pending().await,
                }
            };

            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(Error::Cancelled),
                accepted = lan => {
                    let (stream, _) = accepted?;
                    return Connection::new(stream, Route::Lan);
                }
                relayed = via_relay => match relayed {
                    Some(Ok(stream)) => return Connection::new(stream, Route::Relay),
                    Some(Err(e)) if e.is_cancelled() => return Err(e),
                    Some(Err(e)) => {
                        // With no local network to fall back on, a relay
                        // failure is the whole story.
                        if self.listener.is_none() {
                            return Err(e);
                        }
                        // Otherwise keep listening locally, but remember why
                        // the relay did not work so the timeout can say so.
                        self.relay_error.get_or_insert(e);
                        self.options.relay = None;
                    }
                    None => unreachable!("the relay arm only completes when a relay is configured"),
                },
            }
        }
    }
}

/// The receiver's half: pick a path and connect.
pub async fn dial(
    options: &NetOptions,
    room: &RoomId,
    cancel: &CancellationToken,
) -> Result<Connection> {
    if options.is_unroutable() {
        return Err(NetworkError::NoRoute.into());
    }

    let mut lan_error = None;
    if options.lan {
        match discovery::find(options.discovery_port, room, options.lan_patience(), cancel).await {
            Ok(addr) => {
                let attempt =
                    tokio::time::timeout(options.connect_timeout, TcpStream::connect(addr)).await;
                match attempt {
                    Ok(Ok(stream)) => return Connection::new(stream, Route::Lan),
                    // Somebody answered but we could not reach them. Fall
                    // through to the relay rather than giving up.
                    Ok(Err(source)) => {
                        lan_error = Some(Error::path("connect to", addr.to_string(), source))
                    }
                    Err(_) => {
                        lan_error = Some(NetworkError::Timeout(options.connect_timeout).into())
                    }
                }
            }
            Err(e) if e.is_cancelled() => return Err(e),
            Err(e) => lan_error = Some(e),
        }
    }

    match &options.relay {
        Some(relay) => {
            let stream = relay::rendezvous(relay, room, options.connect_timeout, cancel).await?;
            Connection::new(stream, Route::Relay)
        }
        // Local discovery was the only option and it did not find anybody.
        None => Err(lan_error.unwrap_or_else(|| NetworkError::NoRoute.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::server::{Relay, RelaySettings};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn room(s: &str) -> RoomId {
        RoomId::new(s).unwrap()
    }

    fn relay_only(addr: &str) -> NetOptions {
        NetOptions {
            relay: Some(RelayConfig::new(addr, None)),
            lan: false,
            discovery_port: 0,
            connect_timeout: Duration::from_secs(5),
            rendezvous_timeout: Duration::from_secs(10),
        }
    }

    async fn start_relay() -> (String, CancellationToken) {
        let relay = Relay::bind(RelaySettings {
            listen: "127.0.0.1:0".into(),
            ..RelaySettings::default()
        })
        .await
        .unwrap();
        let addr = relay.local_addr().unwrap().to_string();
        let cancel = CancellationToken::new();
        tokio::spawn(relay.run(cancel.clone()));
        (addr, cancel)
    }

    #[tokio::test]
    async fn no_lan_and_no_relay_is_a_clear_error() {
        let options = NetOptions {
            relay: None,
            lan: false,
            discovery_port: 9111,
            connect_timeout: Duration::from_secs(1),
            rendezvous_timeout: Duration::from_secs(1),
        };
        assert!(options.is_unroutable());

        let cancel = CancellationToken::new();
        let err = dial(&options, &room("k7m2"), &cancel).await.unwrap_err();
        assert!(matches!(err, Error::Network(NetworkError::NoRoute)));
        assert!(err.hint().unwrap().contains("rusp relay"));

        let err = SenderRendezvous::open(options, room("k7m2"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Network(NetworkError::NoRoute)));
    }

    #[tokio::test]
    async fn sender_and_receiver_meet_through_a_relay() {
        let (addr, relay_cancel) = start_relay().await;
        let options = relay_only(&addr);
        let r = room("k7m2");

        let mut rendezvous = SenderRendezvous::open(options.clone(), r.clone())
            .await
            .unwrap();
        assert_eq!(rendezvous.lan_port(), None, "lan is off");

        let cancel = CancellationToken::new();
        let sender_cancel = cancel.clone();
        let sender = tokio::spawn(async move {
            let conn = rendezvous.accept(&sender_cancel).await.unwrap();
            assert_eq!(conn.route(), Route::Relay);
            assert!(conn.describe().contains("relay"));
            let (_read, mut write) = conn.into_split();
            write.write_all(b"payload").await.unwrap();
            write.flush().await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(80)).await;
        let conn = dial(&options, &r, &cancel).await.unwrap();
        assert_eq!(conn.route(), Route::Relay);
        let (mut read, _write) = conn.into_split();
        let mut got = [0u8; 7];
        read.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"payload");

        sender.await.unwrap();
        relay_cancel.cancel();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sender_and_receiver_meet_on_the_local_network() {
        let port = 39_881;
        // Skip rather than fail if the shared discovery port is unavailable.
        let Ok(probe) = tokio::net::UdpSocket::bind(("0.0.0.0", port)).await else {
            eprintln!("discovery port busy; skipping");
            return;
        };
        drop(probe);

        let options = NetOptions {
            relay: None,
            lan: true,
            discovery_port: port,
            connect_timeout: Duration::from_secs(5),
            rendezvous_timeout: Duration::from_secs(5),
        };
        let r = room("k7m2");

        let mut rendezvous = SenderRendezvous::open(options.clone(), r.clone())
            .await
            .unwrap();
        assert!(rendezvous.lan_port().is_some());

        let cancel = CancellationToken::new();
        let sender_cancel = cancel.clone();
        let sender = tokio::spawn(async move {
            let conn = rendezvous.accept(&sender_cancel).await.unwrap();
            assert_eq!(conn.route(), Route::Lan);
            let (_read, mut write) = conn.into_split();
            write.write_all(b"local").await.unwrap();
            write.flush().await.unwrap();
        });

        let conn = tokio::time::timeout(Duration::from_secs(20), dial(&options, &r, &cancel))
            .await
            .expect("local discovery must not hang")
            .unwrap();
        assert_eq!(conn.route(), Route::Lan);
        let (mut read, _write) = conn.into_split();
        let mut got = [0u8; 5];
        read.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"local");
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn a_receiver_with_nobody_to_talk_to_times_out() {
        let options = NetOptions {
            relay: None,
            lan: true,
            discovery_port: 39_882,
            connect_timeout: Duration::from_millis(300),
            rendezvous_timeout: Duration::from_millis(400),
        };
        let cancel = CancellationToken::new();
        let err = dial(&options, &room("zzzz"), &cancel).await.unwrap_err();
        assert!(
            matches!(err, Error::Network(NetworkError::Timeout(_))),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_sender_waiting_alone_times_out() {
        let (addr, relay_cancel) = start_relay().await;
        let options = NetOptions {
            rendezvous_timeout: Duration::from_millis(400),
            ..relay_only(&addr)
        };
        let mut rendezvous = SenderRendezvous::open(options, room("k7m2")).await.unwrap();
        let cancel = CancellationToken::new();
        let err = rendezvous.accept(&cancel).await.unwrap_err();
        assert!(
            matches!(err, Error::Network(NetworkError::Timeout(_))),
            "{err}"
        );
        relay_cancel.cancel();
    }

    #[tokio::test]
    async fn an_unreachable_relay_is_reported_not_swallowed() {
        let options = relay_only("127.0.0.1:1");
        let cancel = CancellationToken::new();

        let err = dial(&options, &room("k7m2"), &cancel).await.unwrap_err();
        assert!(err.to_string().contains("127.0.0.1:1"), "{err}");

        let mut rendezvous = SenderRendezvous::open(options, room("k7m2")).await.unwrap();
        let err = rendezvous.accept(&cancel).await.unwrap_err();
        assert!(err.to_string().contains("127.0.0.1:1"), "{err}");
    }

    #[tokio::test]
    async fn cancelling_stops_both_sides_promptly() {
        let (addr, relay_cancel) = start_relay().await;
        let options = NetOptions {
            rendezvous_timeout: Duration::from_secs(30),
            ..relay_only(&addr)
        };
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            c.cancel();
        });

        let mut rendezvous = SenderRendezvous::open(options, room("k7m2")).await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(5), rendezvous.accept(&cancel))
            .await
            .expect("should not hit the outer timeout")
            .unwrap_err();
        assert!(err.is_cancelled(), "{err}");
        relay_cancel.cancel();
    }

    #[test]
    fn lan_patience_depends_on_whether_a_relay_is_waiting() {
        let with_relay = NetOptions {
            relay: Some(RelayConfig::new("h", None)),
            lan: true,
            discovery_port: 1,
            connect_timeout: Duration::from_secs(1),
            rendezvous_timeout: Duration::from_secs(300),
        };
        assert_eq!(with_relay.lan_patience(), LAN_PATIENCE_WITH_RELAY);

        let lan_only = NetOptions {
            relay: None,
            ..with_relay
        };
        assert_eq!(lan_only.lan_patience(), Duration::from_secs(300));
    }
}
