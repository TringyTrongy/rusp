//! The relay rendezvous protocol, client side.
//!
//! A relay is a meeting point for two peers that cannot reach each other
//! directly. Both connect to it and name the same room; the relay pairs them
//! and then copies bytes between the two sockets without looking at them.
//!
//! # What a relay learns
//!
//! The room identifier, the two IP addresses, the timing, and the number of
//! bytes moved. It never sees the code's secret words, so it cannot derive the
//! session key, and every byte it forwards is already sealed. A relay is
//! untrusted infrastructure: running one lets you disrupt transfers, not read
//! them.
//!
//! # Wire format
//!
//! ```text
//! client -> relay   "RUSPRLY1"   then one framed Join   { room, token? }
//! relay  -> client  one framed Welcome | Refused
//! relay  -> client  one framed Paired                   (when the peer arrives)
//! ...               raw bytes in both directions
//! ```
//!
//! The framing is the same length-prefixed encoding the peer protocol uses,
//! with a small frame limit — a relay never needs to carry a large message.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::code::RoomId;
use crate::config::RelayConfig;
use crate::error::{Error, NetworkError, ProtocolError, Result};
use crate::protocol::frame::{FrameBuf, FrameReader, FrameWriter};

/// Opening bytes of a relay connection.
pub const RELAY_MAGIC: [u8; 8] = *b"RUSPRLY1";

/// Frame limit on the relay control channel.
pub const RELAY_MAX_FRAME: usize = 4096;

/// Longest token a relay will read, to bound work before authentication.
pub const MAX_TOKEN_LEN: usize = 256;

/// A client asking to be put in a room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Join {
    /// The room to join. Only ever the public half of a transfer code.
    pub room: String,
    /// Shared token, when the relay is private.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// What the relay says back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayReply {
    /// Registered, now waiting for the other side.
    Welcome {
        /// Free-form relay identification, for diagnostics.
        #[serde(default)]
        server: String,
    },
    /// The other side has arrived; everything after this frame is raw bytes.
    Paired,
    /// The relay will not serve this request.
    Refused {
        /// Machine-readable reason.
        reason: RefusalReason,
        /// Human-readable detail.
        #[serde(default)]
        detail: String,
    },
}

/// Why a relay refused a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalReason {
    /// Missing or wrong token.
    Unauthorised,
    /// Two peers are already using that room.
    RoomBusy,
    /// The relay is at capacity.
    Overloaded,
    /// The room name was not acceptable.
    BadRoom,
}

impl RefusalReason {
    fn describe(self) -> &'static str {
        match self {
            RefusalReason::Unauthorised => "this relay requires a token",
            RefusalReason::RoomBusy => "that room is already in use",
            RefusalReason::Overloaded => "the relay is at capacity",
            RefusalReason::BadRoom => "the relay rejected the room name",
        }
    }
}

/// Encode a relay message into a frame buffer.
pub(crate) fn encode<T: Serialize>(value: &T, buf: &mut FrameBuf) -> Result<()> {
    buf.clear();
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|e| ProtocolError::Malformed(format!("could not encode relay message: {e}")))?;
    buf.push_slice(&bytes);
    Ok(())
}

/// Decode a relay message from a frame payload.
pub(crate) fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|e| {
        ProtocolError::Malformed(format!("could not decode relay message: {e}")).into()
    })
}

/// Connect to a relay, join `room`, and wait until the peer arrives.
///
/// Returns the paired socket, over which the peer protocol then runs. The
/// caller is responsible for bounding the total wait; `cancel` interrupts it.
pub async fn rendezvous(
    relay: &RelayConfig,
    room: &RoomId,
    connect_timeout: Duration,
    cancel: &CancellationToken,
) -> Result<TcpStream> {
    let connect = tokio::time::timeout(connect_timeout, TcpStream::connect(&relay.address));
    let stream = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(Error::Cancelled),
        result = connect => match result {
            Ok(Ok(stream)) => stream,
            Ok(Err(source)) => {
                return Err(NetworkError::RelayConnect {
                    addr: relay.address.clone(),
                    source,
                }
                .into())
            }
            Err(_) => return Err(NetworkError::Timeout(connect_timeout).into()),
        },
    };
    // Control frames are tiny and latency matters more than packing.
    let _ = stream.set_nodelay(true);

    let (read, write) = stream.into_split();
    let mut reader = FrameReader::new(read, RELAY_MAX_FRAME);
    let mut writer = FrameWriter::new(write, RELAY_MAX_FRAME);
    let mut buf = FrameBuf::with_capacity(RELAY_MAX_FRAME);

    write_magic(&mut writer).await?;
    encode(
        &Join {
            room: room.as_str().to_owned(),
            token: relay.token.as_ref().map(|t| t.to_string()),
        },
        &mut buf,
    )?;
    writer.write_buf(&mut buf).await?;
    writer.flush().await?;

    let mut payload = Vec::new();
    match expect_reply(&mut reader, &mut payload, cancel).await? {
        RelayReply::Welcome { .. } => {}
        RelayReply::Paired => {
            // A relay is allowed to skip straight to pairing if the peer was
            // already waiting.
            return Ok(rejoin(reader, writer));
        }
        RelayReply::Refused { reason, detail } => return Err(refusal(reason, detail, room)),
    }

    match expect_reply(&mut reader, &mut payload, cancel).await? {
        RelayReply::Paired => Ok(rejoin(reader, writer)),
        RelayReply::Refused { reason, detail } => Err(refusal(reason, detail, room)),
        RelayReply::Welcome { .. } => Err(ProtocolError::Unexpected {
            got: "welcome",
            expected: "paired",
        }
        .into()),
    }
}

fn refusal(reason: RefusalReason, detail: String, room: &RoomId) -> Error {
    let message = if detail.is_empty() {
        reason.describe().to_owned()
    } else {
        format!("{}: {detail}", reason.describe())
    };
    match reason {
        RefusalReason::RoomBusy => NetworkError::RoomBusy(room.as_str().to_owned()).into(),
        _ => NetworkError::RelayRejected(message).into(),
    }
}

async fn expect_reply<R>(
    reader: &mut FrameReader<R>,
    payload: &mut Vec<u8>,
    cancel: &CancellationToken,
) -> Result<RelayReply>
where
    R: tokio::io::AsyncRead + Unpin,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(Error::Cancelled),
        result = reader.read_frame_required(payload) => {
            result?;
            decode(payload)
        }
    }
}

/// Put the two halves back together once the relay has stopped speaking.
fn rejoin(
    reader: FrameReader<tokio::net::tcp::OwnedReadHalf>,
    writer: FrameWriter<tokio::net::tcp::OwnedWriteHalf>,
) -> TcpStream {
    let read = reader.into_inner();
    let write = writer.into_inner();
    // The halves came from one stream a few statements ago, so reunite cannot
    // fail; if it somehow did there would be nothing sensible to do but panic,
    // which is why this is the only place the crate uses `expect` on a socket.
    read.reunite(write)
        .expect("relay socket halves come from the same stream")
}

pub(crate) async fn write_magic<W>(writer: &mut FrameWriter<W>) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use crate::error::IoContext;
    use tokio::io::AsyncWriteExt;
    writer
        .get_mut()
        .write_all(&RELAY_MAGIC)
        .await
        .ctx("greet the relay")
}

pub(crate) async fn read_magic<R>(reader: &mut FrameReader<R>) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut got = [0u8; RELAY_MAGIC.len()];
    match reader.get_mut().read_exact(&mut got).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::UnexpectedEof.into())
        }
        Err(e) => return Err(Error::io("read relay greeting", e)),
    }
    if got == RELAY_MAGIC {
        Ok(())
    } else {
        Err(ProtocolError::BadMagic.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_messages_round_trip() {
        let mut buf = FrameBuf::with_capacity(256);

        let join = Join {
            room: "k7m2".into(),
            token: Some("hunter2".into()),
        };
        encode(&join, &mut buf).unwrap();
        assert_eq!(decode::<Join>(buf.payload()).unwrap(), join);

        for reply in [
            RelayReply::Welcome {
                server: "rusp-relay/0.1.0".into(),
            },
            RelayReply::Paired,
            RelayReply::Refused {
                reason: RefusalReason::RoomBusy,
                detail: String::new(),
            },
        ] {
            encode(&reply, &mut buf).unwrap();
            assert_eq!(decode::<RelayReply>(buf.payload()).unwrap(), reply);
        }
    }

    #[test]
    fn a_join_without_a_token_omits_the_field() {
        let mut buf = FrameBuf::with_capacity(256);
        encode(
            &Join {
                room: "k7m2".into(),
                token: None,
            },
            &mut buf,
        )
        .unwrap();
        let decoded: Join = decode(buf.payload()).unwrap();
        assert_eq!(decoded.token, None);
    }

    #[test]
    fn garbage_does_not_decode() {
        assert!(decode::<RelayReply>(&[]).is_err());
        assert!(decode::<RelayReply>(&[0xC1, 0xC1]).is_err());
        assert!(decode::<Join>(b"not messagepack").is_err());
    }

    #[test]
    fn refusals_map_to_the_right_error() {
        let room = RoomId::new("k7m2").unwrap();
        let busy = refusal(RefusalReason::RoomBusy, String::new(), &room);
        assert!(matches!(busy, Error::Network(NetworkError::RoomBusy(_))));
        assert!(busy.hint().is_some());

        let unauth = refusal(RefusalReason::Unauthorised, "no token".into(), &room);
        assert!(matches!(
            unauth,
            Error::Network(NetworkError::RelayRejected(_))
        ));
        assert!(unauth.to_string().contains("no token"));
    }
}
