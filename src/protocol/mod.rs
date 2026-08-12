//! The Rusp wire protocol.
//!
//! # Sequence
//!
//! ```text
//! sender                                        receiver
//!   |  "RUSP" magic                                   |
//!   |------------------------------------------------>|
//!   |<------------------------------------------------|
//!   |  Hello { versions, role }                        |   in the clear
//!   |------------------------------------------------>|
//!   |<------------------------------------------------|
//!   |  SPAKE2 element                                  |
//!   |------------------------------------------------>|
//!   |<------------------------------------------------|
//!   |  key confirmation tag                            |   both sides verify
//!   |------------------------------------------------>|   or abort
//!   |<------------------------------------------------|
//!   |================ encrypted from here =============|
//!   |  Capabilities                                    |
//!   |------------------------------------------------>|
//!   |<------------------------------------------------|
//!   |  Offer { manifest }                              |
//!   |------------------------------------------------>|
//!   |<------------------------------------------------|  Accept / Decline
//!   |  FileStart, Data..., FileEnd { hash }            |
//!   |------------------------------------------------>|
//!   |  ... repeated per file, with no reply in between |
//!   |  Complete { files, bytes }                       |
//!   |------------------------------------------------>|
//!   |<------------------------------------------------|  Complete
//! ```
//!
//! # Versioning
//!
//! Each side announces the range of protocol versions it accepts. The session
//! runs at the highest version both understand; if the ranges do not overlap,
//! both sides stop with a message naming the versions involved rather than
//! failing somewhere deep in a decode.
//!
//! Within a version, control messages may gain optional fields — see
//! [`message`] for why the encoding allows that. A change that removes a
//! field, changes a meaning, or adds a mandatory message needs a new version.

pub mod channel;
pub mod frame;
pub mod message;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use frame::{FrameBuf, FrameReader, FrameWriter, DEFAULT_MAX_FRAME};
pub use message::{
    Accept, Capabilities, ControlMessage, Entry, EntryKind, FailureCode, Handshake, Hash32, Hello,
    Incoming, Offer, Role, Summary,
};

use crate::error::{Error, IoContext, ProtocolError, Result};

/// Bytes that open every Rusp peer connection, so a mismatched service is
/// rejected immediately instead of failing to parse a frame.
pub const MAGIC: [u8; 4] = *b"RUSP";

/// Oldest protocol version this build can speak.
pub const PROTOCOL_MIN: u16 = 1;

/// Newest protocol version this build can speak.
pub const PROTOCOL_MAX: u16 = 1;

/// Default file data chunk size.
///
/// Large enough that per-frame overhead (9 byte header, 16 byte tag, one
/// `write_all`) disappears against the payload, and small enough that a
/// handful of in-flight chunks is a few megabytes rather than a few hundred.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Smallest chunk size a peer may negotiate.
pub const MIN_CHUNK_SIZE: usize = 4 * 1024;

/// The implementation string sent in [`Hello`]. Diagnostics only.
pub fn agent_string() -> String {
    format!("rusp/{}", crate::VERSION)
}

/// This build's capabilities.
pub fn local_capabilities() -> Capabilities {
    Capabilities {
        max_frame: DEFAULT_MAX_FRAME as u32,
        chunk_size: DEFAULT_CHUNK_SIZE as u32,
        // No optional features are implemented yet. Compression, resume and
        // parallel streams will announce themselves here.
        features: Default::default(),
    }
}

/// The [`Hello`] this build sends.
pub fn local_hello(role: Role) -> Hello {
    Hello {
        min_version: PROTOCOL_MIN,
        max_version: PROTOCOL_MAX,
        role,
        agent: agent_string(),
    }
}

/// Pick the highest protocol version both sides accept.
pub fn negotiate_version(peer: &Hello) -> Result<u16> {
    if peer.min_version > peer.max_version {
        return Err(ProtocolError::Malformed(format!(
            "peer announced an impossible version range v{}-v{}",
            peer.min_version, peer.max_version
        ))
        .into());
    }
    let chosen = PROTOCOL_MAX.min(peer.max_version);
    if chosen < PROTOCOL_MIN || chosen < peer.min_version {
        return Err(ProtocolError::IncompatibleVersion {
            peer_min: peer.min_version,
            peer_max: peer.max_version,
            ours_min: PROTOCOL_MIN,
            ours_max: PROTOCOL_MAX,
        }
        .into());
    }
    Ok(chosen)
}

/// Check that the peer is the role we expected to meet.
pub fn check_role(peer: &Hello, expected: Role) -> Result<()> {
    if peer.role == expected {
        Ok(())
    } else {
        Err(ProtocolError::Malformed(format!(
            "expected to meet a {expected} but the other side is also a {}",
            peer.role
        ))
        .into())
    }
}

/// Write the connection magic.
pub async fn write_magic<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    w.write_all(&MAGIC).await.ctx("write protocol magic")
}

/// Read and verify the connection magic.
pub async fn read_magic<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let mut got = [0u8; MAGIC.len()];
    match r.read_exact(&mut got).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::UnexpectedEof.into())
        }
        Err(e) => return Err(Error::io("read protocol magic", e)),
    }
    if got == MAGIC {
        Ok(())
    } else {
        Err(ProtocolError::BadMagic.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(min: u16, max: u16) -> Hello {
        Hello {
            min_version: min,
            max_version: max,
            role: Role::Sender,
            agent: "test".into(),
        }
    }

    #[test]
    fn same_version_negotiates() {
        assert_eq!(negotiate_version(&local_hello(Role::Sender)).unwrap(), 1);
    }

    #[test]
    fn newer_peer_is_met_at_our_maximum() {
        assert_eq!(negotiate_version(&hello(1, 9)).unwrap(), PROTOCOL_MAX);
    }

    #[test]
    fn peer_that_dropped_support_for_our_versions_is_refused() {
        let err = negotiate_version(&hello(7, 9)).unwrap_err();
        assert!(matches!(
            err,
            Error::Protocol(ProtocolError::IncompatibleVersion {
                peer_min: 7,
                peer_max: 9,
                ..
            })
        ));
        // The message names all four numbers so a user can see who to upgrade.
        let text = err.to_string();
        assert!(text.contains("v7-v9"), "{text}");
        assert!(err.hint().is_some());
    }

    #[test]
    fn peer_too_old_is_refused() {
        // A peer that only speaks v0 shares nothing with us.
        let err = negotiate_version(&hello(0, 0)).unwrap_err();
        assert!(matches!(
            err,
            Error::Protocol(ProtocolError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn impossible_ranges_are_rejected() {
        assert!(matches!(
            negotiate_version(&hello(9, 1)).unwrap_err(),
            Error::Protocol(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn roles_must_be_opposite() {
        let sender = hello(1, 1);
        assert!(check_role(&sender, Role::Sender).is_ok());
        let err = check_role(&sender, Role::Receiver).unwrap_err();
        assert!(err.to_string().contains("also a sender"), "{err}");
    }

    #[test]
    fn capabilities_are_within_their_own_limits() {
        let caps = local_capabilities();
        assert!(caps.chunk_size as usize >= MIN_CHUNK_SIZE);
        assert!(caps.max_frame as usize >= frame::MIN_MAX_FRAME);
        // A chunk plus its header and AEAD tag has to fit in a frame.
        assert!(
            caps.chunk_size as usize + message::DATA_HEADER_LEN + 16 <= caps.max_frame as usize
        );
    }

    #[tokio::test]
    async fn magic_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(16);
        write_magic(&mut a).await.unwrap();
        read_magic(&mut b).await.unwrap();
    }

    #[tokio::test]
    async fn wrong_magic_is_reported_as_not_rusp() {
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_all(b"HTTP").await.unwrap();
        assert!(matches!(
            read_magic(&mut b).await.unwrap_err(),
            Error::Protocol(ProtocolError::BadMagic)
        ));
    }

    #[tokio::test]
    async fn closed_connection_before_magic_is_not_a_panic() {
        let (a, mut b) = tokio::io::duplex(16);
        drop(a);
        assert!(matches!(
            read_magic(&mut b).await.unwrap_err(),
            Error::Protocol(ProtocolError::UnexpectedEof)
        ));
    }
}
