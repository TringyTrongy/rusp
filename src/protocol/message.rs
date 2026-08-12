//! Protocol messages and their encoding.
//!
//! # Shape of a payload
//!
//! Every frame payload starts with a one-byte *kind*, so the reader knows what
//! it is holding before it parses anything:
//!
//! ```text
//! handshake, in the clear     session, inside the AEAD
//! 0x01 HELLO   msgpack        0x10 CONTROL  msgpack
//! 0x02 PAKE    raw bytes      0x11 DATA     u64 offset (LE) + raw bytes
//! 0x03 CONFIRM raw bytes
//! ```
//!
//! Control messages are MessagePack with **named** fields. That costs a few
//! bytes per control message — of which a transfer sends a handful — and buys
//! the ability to add optional fields later without a version bump. File data
//! never goes through serde at all; it is raw bytes behind a nine-byte header.
//!
//! # Extension points
//!
//! * [`Capabilities::features`] is a free-form set that peers intersect, so a
//!   future compression or resume feature needs no protocol version bump.
//! * [`EntryKind`] and [`FailureCode`] are integer codes rather
//!   than closed enums, so an older build meets an unknown value with a
//!   sensible fallback instead of a parse failure.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, Result};
use crate::protocol::frame::FrameBuf;

/// Payload kind bytes.
pub mod kind {
    /// Version and role announcement, in the clear.
    pub const HELLO: u8 = 0x01;
    /// A SPAKE2 group element, in the clear.
    pub const PAKE: u8 = 0x02;
    /// A key-confirmation tag, in the clear.
    pub const CONFIRM: u8 = 0x03;
    /// A control message, encrypted.
    pub const CONTROL: u8 = 0x10;
    /// A file data chunk, encrypted.
    pub const DATA: u8 = 0x11;
}

/// Bytes a data payload spends on its header: kind plus 64-bit offset.
pub const DATA_HEADER_LEN: usize = 1 + 8;

/// Refuse manifests with more entries than this. A directory tree larger than
/// this is almost certainly a mistake or an attack, and the limit keeps a
/// hostile offer from exhausting memory before we can look at it.
pub const MAX_ENTRIES: usize = 1_000_000;

/// Longest relative path accepted in a manifest entry.
pub const MAX_PATH_LEN: usize = 4096;

/// Which side of the transfer a peer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Offers files.
    Sender,
    /// Receives files.
    Receiver,
}

impl Role {
    /// The other side.
    pub fn peer(self) -> Role {
        match self {
            Role::Sender => Role::Receiver,
            Role::Receiver => Role::Sender,
        }
    }

    /// Stable label used in key-derivation and SPAKE2 identity strings.
    pub fn label(self) -> &'static str {
        match self {
            Role::Sender => "sender",
            Role::Receiver => "receiver",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A 32-byte digest, serialised as MessagePack binary rather than an array of
/// integers.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash32([u8; 32]);

impl Hash32 {
    /// Wrap raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash32(bytes)
    }

    /// The digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Full lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First eight hex characters, for human-readable output.
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", self.short())
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Hash32 {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Hash32;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("32 bytes of digest")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> std::result::Result<Hash32, E> {
                let bytes: [u8; 32] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &"32 bytes"))?;
                Ok(Hash32(bytes))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Hash32, A::Error> {
                let mut bytes = [0u8; 32];
                for (i, slot) in bytes.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"32 bytes"))?;
                }
                Ok(Hash32(bytes))
            }
        }

        deserializer.deserialize_bytes(Visitor)
    }
}

/// Version and role announcement. The only message sent before any key
/// material exists, so it carries the bare minimum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Lowest protocol version this peer accepts.
    pub min_version: u16,
    /// Highest protocol version this peer accepts.
    pub max_version: u16,
    /// Which side this peer is.
    pub role: Role,
    /// Free-form implementation string, for diagnostics only. Never trusted.
    #[serde(default)]
    pub agent: String,
}

/// What a peer can do. Exchanged inside the encrypted channel, so it is not
/// visible to a relay or an eavesdropper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Largest frame this peer is willing to receive, in bytes.
    pub max_frame: u32,
    /// Preferred data chunk size, in bytes.
    pub chunk_size: u32,
    /// Optional feature names. Unknown names are ignored, so this is the
    /// extension point for compression, resume, and multi-stream transfers.
    #[serde(default)]
    pub features: BTreeSet<String>,
}

impl Capabilities {
    /// Combine two peers' capabilities into the settings they both support.
    pub fn intersect(&self, peer: &Capabilities) -> Capabilities {
        Capabilities {
            max_frame: self.max_frame.min(peer.max_frame),
            chunk_size: self.chunk_size.min(peer.chunk_size),
            features: self
                .features
                .intersection(&peer.features)
                .cloned()
                .collect(),
        }
    }

    /// True when both peers named this feature.
    pub fn has(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }
}

/// What kind of thing a manifest entry is.
///
/// An integer rather than an enum so that a build which predates a new kind
/// can skip the entry instead of failing to parse the whole manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryKind(pub u8);

impl EntryKind {
    /// A regular file.
    pub const FILE: EntryKind = EntryKind(0);
    /// A directory, present so empty directories survive the transfer.
    pub const DIRECTORY: EntryKind = EntryKind(1);

    /// True for regular files.
    pub fn is_file(self) -> bool {
        self == EntryKind::FILE
    }

    /// True for directories.
    pub fn is_directory(self) -> bool {
        self == EntryKind::DIRECTORY
    }

    /// True for kinds this build does not understand.
    pub fn is_unknown(self) -> bool {
        !self.is_file() && !self.is_directory()
    }
}

/// One item in a transfer manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Path relative to the transfer root, always `/`-separated.
    ///
    /// The receiver never trusts this: it is re-validated against
    /// [`crate::files::safe_path`] before anything touches the disk.
    pub path: String,
    /// File or directory.
    pub kind: EntryKind,
    /// Size in bytes; zero for directories.
    #[serde(default)]
    pub size: u64,
    /// Unix permission bits. Only the executable bit is honoured, and only on
    /// Unix; everything else is ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Modification time as seconds since the Unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
}

impl Entry {
    /// A regular file entry.
    pub fn file(path: impl Into<String>, size: u64) -> Self {
        Entry {
            path: path.into(),
            kind: EntryKind::FILE,
            size,
            mode: None,
            mtime: None,
        }
    }

    /// A directory entry.
    pub fn directory(path: impl Into<String>) -> Self {
        Entry {
            path: path.into(),
            kind: EntryKind::DIRECTORY,
            size: 0,
            mode: None,
            mtime: None,
        }
    }
}

/// Everything the sender is proposing to send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// The manifest, in the order files will be sent.
    pub entries: Vec<Entry>,
    /// Sum of all file sizes, so the receiver can show progress and check
    /// free space before accepting.
    #[serde(default)]
    pub total_bytes: u64,
    /// Human-readable description of what is being sent, such as a folder
    /// name. Display only; never used to build a path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_hint: Option<String>,
}

/// The receiver's answer to an [`Offer`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accept {
    /// Indices into [`Offer::entries`] that the receiver wants, in ascending
    /// order. Anything omitted is not sent at all, which is how `--on-conflict
    /// skip` avoids moving bytes it would throw away.
    pub wanted: Vec<u32>,
}

/// Why a peer is giving up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FailureCode(pub u16);

impl FailureCode {
    /// An unexpected internal failure.
    pub const INTERNAL: FailureCode = FailureCode(1);
    /// A message did not make sense here.
    pub const BAD_MESSAGE: FailureCode = FailureCode(2);
    /// A file failed verification.
    pub const INTEGRITY: FailureCode = FailureCode(3);
    /// A filesystem operation failed.
    pub const IO: FailureCode = FailureCode(4);
    /// The peer refused for policy reasons, such as an unsafe path.
    pub const REFUSED: FailureCode = FailureCode(5);
    /// Something in the offer needs a newer build.
    pub const UNSUPPORTED: FailureCode = FailureCode(6);
}

impl fmt::Display for FailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            FailureCode::INTERNAL => f.write_str("internal error"),
            FailureCode::BAD_MESSAGE => f.write_str("bad message"),
            FailureCode::INTEGRITY => f.write_str("integrity failure"),
            FailureCode::IO => f.write_str("filesystem error"),
            FailureCode::REFUSED => f.write_str("refused"),
            FailureCode::UNSUPPORTED => f.write_str("unsupported"),
            FailureCode(other) => write!(f, "error {other}"),
        }
    }
}

/// Totals reported at the end of a transfer.
///
/// There is deliberately no per-file acknowledgement in the protocol. Waiting
/// for one would add a network round trip per file, which is what dominates a
/// transfer of several thousand small files. The receiver decides what it
/// wants up front in [`Accept`], verifies each file as it lands, and reports
/// the totals once at the end; anything that goes wrong in between is a
/// [`ControlMessage::Failure`], which ends the transfer immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Summary {
    /// Number of files written.
    pub files: u32,
    /// Number of file bytes transferred.
    pub bytes: u64,
    /// Number of files deliberately not written.
    #[serde(default)]
    pub skipped: u32,
}

/// A control message. Everything except file data is one of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// What this peer supports. Sender first, then receiver.
    Capabilities(Capabilities),
    /// The manifest of what is on offer.
    Offer(Offer),
    /// Which parts of the offer the receiver wants.
    Accept(Accept),
    /// The receiver does not want the transfer at all.
    Decline {
        /// Optional explanation, shown to the sender.
        reason: Option<String>,
    },
    /// The next data frames belong to this manifest entry.
    FileStart {
        /// Index into the offer's entries.
        index: u32,
    },
    /// That entry is complete; here is what it should hash to.
    FileEnd {
        /// Index into the offer's entries.
        index: u32,
        /// BLAKE3 hash of the file's contents.
        hash: Hash32,
        /// Number of bytes sent for it.
        size: u64,
    },
    /// Everything is done.
    Complete(Summary),
    /// The peer is stopping on purpose.
    Cancel {
        /// Optional explanation.
        reason: Option<String>,
    },
    /// The peer is stopping because something went wrong.
    Failure {
        /// Machine-readable code.
        code: FailureCode,
        /// Human-readable detail.
        message: String,
    },
    /// Sent during long pauses so an idle connection is not dropped.
    Keepalive,
}

impl ControlMessage {
    /// Short static name, used in protocol-desync errors and tracing.
    pub fn name(&self) -> &'static str {
        match self {
            ControlMessage::Capabilities(_) => "capabilities",
            ControlMessage::Offer(_) => "offer",
            ControlMessage::Accept(_) => "accept",
            ControlMessage::Decline { .. } => "decline",
            ControlMessage::FileStart { .. } => "file-start",
            ControlMessage::FileEnd { .. } => "file-end",
            ControlMessage::Complete(_) => "complete",
            ControlMessage::Cancel { .. } => "cancel",
            ControlMessage::Failure { .. } => "failure",
            ControlMessage::Keepalive => "keepalive",
        }
    }
}

/// A message read from the session, borrowing the reader's buffer so file data
/// never has to be copied out of it.
#[derive(Debug)]
pub enum Incoming<'a> {
    /// A control message.
    Control(ControlMessage),
    /// File bytes for the entry named by the most recent `FileStart`.
    Data {
        /// Byte offset of this chunk within the file.
        offset: u64,
        /// The chunk itself.
        bytes: &'a [u8],
    },
}

impl Incoming<'_> {
    /// Short static name for diagnostics.
    pub fn name(&self) -> &'static str {
        match self {
            Incoming::Control(msg) => msg.name(),
            Incoming::Data { .. } => "data",
        }
    }
}

/// A handshake message, exchanged before the secure channel exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handshake {
    /// Version and role announcement.
    Hello(Hello),
    /// A SPAKE2 group element.
    Pake(Vec<u8>),
    /// A key-confirmation tag.
    Confirm(Vec<u8>),
}

impl Handshake {
    /// Short static name for desync errors.
    pub fn name(&self) -> &'static str {
        match self {
            Handshake::Hello(_) => "hello",
            Handshake::Pake(_) => "pake",
            Handshake::Confirm(_) => "confirm",
        }
    }

    /// Serialise into `buf`, which is cleared first.
    pub fn encode(&self, buf: &mut FrameBuf) -> Result<()> {
        buf.clear();
        match self {
            Handshake::Hello(hello) => {
                buf.push_u8(kind::HELLO);
                buf.push_slice(&encode_msgpack(hello)?);
            }
            Handshake::Pake(bytes) => {
                buf.push_u8(kind::PAKE);
                buf.push_slice(bytes);
            }
            Handshake::Confirm(bytes) => {
                buf.push_u8(kind::CONFIRM);
                buf.push_slice(bytes);
            }
        }
        Ok(())
    }

    /// Parse a handshake payload.
    pub fn decode(payload: &[u8]) -> Result<Handshake> {
        let (&tag, body) = payload
            .split_first()
            .ok_or_else(|| ProtocolError::Malformed("empty handshake frame".into()))?;
        match tag {
            kind::HELLO => Ok(Handshake::Hello(decode_msgpack(body)?)),
            kind::PAKE => Ok(Handshake::Pake(body.to_vec())),
            kind::CONFIRM => Ok(Handshake::Confirm(body.to_vec())),
            other => Err(ProtocolError::Malformed(format!(
                "unexpected handshake frame kind 0x{other:02x}"
            ))
            .into()),
        }
    }
}

/// Encode a control message into `buf`, which is cleared first.
pub fn encode_control(msg: &ControlMessage, buf: &mut FrameBuf) -> Result<()> {
    buf.clear();
    buf.push_u8(kind::CONTROL);
    buf.push_slice(&encode_msgpack(msg)?);
    Ok(())
}

/// Start a data payload in `buf`, returning the space to fill with file bytes.
///
/// The caller writes `len` bytes into the returned slice — typically straight
/// from the file — and the frame is then ready to be encrypted in place.
pub fn start_data(buf: &mut FrameBuf, offset: u64, len: usize) -> &mut [u8] {
    buf.clear();
    buf.push_u8(kind::DATA);
    buf.push_slice(&offset.to_le_bytes());
    buf.claim(len)
}

/// Parse a decrypted session payload.
pub fn decode_incoming(payload: &[u8]) -> Result<Incoming<'_>> {
    let (&tag, body) = payload
        .split_first()
        .ok_or_else(|| ProtocolError::Malformed("empty session frame".into()))?;
    match tag {
        kind::CONTROL => Ok(Incoming::Control(decode_msgpack(body)?)),
        kind::DATA => {
            if body.len() < 8 {
                return Err(ProtocolError::Malformed("truncated data frame header".into()).into());
            }
            let (head, bytes) = body.split_at(8);
            let offset = u64::from_le_bytes(head.try_into().expect("split_at guarantees 8 bytes"));
            Ok(Incoming::Data { offset, bytes })
        }
        other => Err(ProtocolError::Malformed(format!(
            "unexpected session frame kind 0x{other:02x}"
        ))
        .into()),
    }
}

/// MessagePack with named struct fields, so optional fields can be added later.
fn encode_msgpack<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value)
        .map_err(|e| ProtocolError::Malformed(format!("could not encode message: {e}")).into())
}

fn decode_msgpack<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes)
        .map_err(|e| ProtocolError::Malformed(format!("could not decode message: {e}")).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::protocol::frame::DEFAULT_MAX_FRAME;

    fn sample_offer() -> Offer {
        Offer {
            entries: vec![
                Entry::directory("photos"),
                Entry::file("photos/café ☕.jpg", 1234),
                Entry {
                    mode: Some(0o755),
                    mtime: Some(1_700_000_000),
                    ..Entry::file("run.sh", 42)
                },
            ],
            total_bytes: 1276,
            name_hint: Some("photos".into()),
        }
    }

    fn round_trip(msg: &ControlMessage) -> ControlMessage {
        let mut buf = FrameBuf::with_capacity(64);
        encode_control(msg, &mut buf).unwrap();
        let payload = buf.payload().to_vec();
        assert_eq!(payload[0], kind::CONTROL);
        match decode_incoming(&payload).unwrap() {
            Incoming::Control(decoded) => decoded,
            other => panic!("expected control, got {}", other.name()),
        }
    }

    #[test]
    fn control_messages_round_trip() {
        let messages = vec![
            ControlMessage::Capabilities(Capabilities {
                max_frame: DEFAULT_MAX_FRAME as u32,
                chunk_size: 262_144,
                features: ["resume".to_string()].into_iter().collect(),
            }),
            ControlMessage::Offer(sample_offer()),
            ControlMessage::Accept(Accept {
                wanted: vec![0, 2, 5],
            }),
            ControlMessage::Decline {
                reason: Some("no space".into()),
            },
            ControlMessage::Decline { reason: None },
            ControlMessage::FileStart { index: 7 },
            ControlMessage::FileEnd {
                index: 7,
                hash: Hash32::from_bytes([9u8; 32]),
                size: 1 << 40,
            },
            ControlMessage::Complete(Summary {
                files: 3,
                bytes: 1276,
                skipped: 1,
            }),
            ControlMessage::Cancel { reason: None },
            ControlMessage::Failure {
                code: FailureCode::INTEGRITY,
                message: "hash mismatch".into(),
            },
            ControlMessage::Keepalive,
        ];
        for msg in messages {
            assert_eq!(round_trip(&msg), msg, "{}", msg.name());
        }
    }

    #[test]
    fn unicode_and_awkward_paths_survive() {
        for path in [
            "photos/café ☕.jpg",
            "with spaces/and'quotes\".txt",
            "日本語/ファイル.txt",
            "emoji-🚀.bin",
            &"a".repeat(255),
        ] {
            let msg = ControlMessage::Offer(Offer {
                entries: vec![Entry::file(path, 1)],
                total_bytes: 1,
                name_hint: None,
            });
            let ControlMessage::Offer(decoded) = round_trip(&msg) else {
                panic!("wrong variant")
            };
            assert_eq!(decoded.entries[0].path, path);
        }
    }

    #[test]
    fn hashes_are_encoded_as_binary_not_arrays() {
        let msg = ControlMessage::FileEnd {
            index: 0,
            hash: Hash32::from_bytes([0xAB; 32]),
            size: 0,
        };
        let mut buf = FrameBuf::with_capacity(64);
        encode_control(&msg, &mut buf).unwrap();
        // 32 bytes of digest plus a 2-byte msgpack bin8 header; an array of 32
        // integers above 0x7f would take at least 64 bytes.
        assert!(
            buf.payload_len() < 100,
            "digest encoding is bloated: {} bytes",
            buf.payload_len()
        );
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn hash_formatting() {
        let h = Hash32::from_bytes([0x01; 32]);
        assert_eq!(h.short(), "01010101");
        assert_eq!(h.to_hex().len(), 64);
        assert!(format!("{h:?}").contains("01010101"));
    }

    #[test]
    fn data_frames_round_trip_without_copying() {
        let mut buf = FrameBuf::with_capacity(1024);
        let space = start_data(&mut buf, 0xDEAD_BEEF_CAFE, 512);
        space.fill(0x5A);
        assert_eq!(buf.payload_len(), DATA_HEADER_LEN + 512);

        let payload = buf.payload().to_vec();
        match decode_incoming(&payload).unwrap() {
            Incoming::Data { offset, bytes } => {
                assert_eq!(offset, 0xDEAD_BEEF_CAFE);
                assert_eq!(bytes.len(), 512);
                assert!(bytes.iter().all(|b| *b == 0x5A));
            }
            other => panic!("expected data, got {}", other.name()),
        }
    }

    #[test]
    fn handshake_messages_round_trip() {
        let messages = vec![
            Handshake::Hello(Hello {
                min_version: 1,
                max_version: 3,
                role: Role::Sender,
                agent: "rusp 0.1.0".into(),
            }),
            Handshake::Pake(vec![1, 2, 3, 4]),
            Handshake::Confirm(vec![0xFF; 32]),
        ];
        let mut buf = FrameBuf::with_capacity(64);
        for msg in messages {
            msg.encode(&mut buf).unwrap();
            assert_eq!(Handshake::decode(buf.payload()).unwrap(), msg);
        }
    }

    #[test]
    fn garbage_payloads_are_rejected_cleanly() {
        // Empty payload.
        assert!(matches!(
            decode_incoming(&[]).unwrap_err(),
            Error::Protocol(ProtocolError::Malformed(_))
        ));
        assert!(matches!(
            Handshake::decode(&[]).unwrap_err(),
            Error::Protocol(ProtocolError::Malformed(_))
        ));
        // Unknown kind byte.
        assert!(matches!(
            decode_incoming(&[0x7F, 1, 2, 3]).unwrap_err(),
            Error::Protocol(ProtocolError::Malformed(_))
        ));
        assert!(matches!(
            Handshake::decode(&[0x7F]).unwrap_err(),
            Error::Protocol(ProtocolError::Malformed(_))
        ));
        // Data frame with a truncated offset header.
        assert!(matches!(
            decode_incoming(&[kind::DATA, 1, 2, 3]).unwrap_err(),
            Error::Protocol(ProtocolError::Malformed(_))
        ));
        // Control frame whose body is not MessagePack.
        assert!(matches!(
            decode_incoming(&[kind::CONTROL, 0xC1, 0xC1, 0xC1]).unwrap_err(),
            Error::Protocol(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn truncating_a_valid_message_never_panics() {
        let mut buf = FrameBuf::with_capacity(256);
        encode_control(&ControlMessage::Offer(sample_offer()), &mut buf).unwrap();
        let full = buf.payload().to_vec();
        for cut in 0..full.len() {
            // Must return a result either way, and must not panic.
            let _ = decode_incoming(&full[..cut]);
        }
    }

    #[test]
    fn optional_fields_may_be_absent() {
        // A peer that omits `features`, `mode`, `mtime` and `name_hint`
        // entirely must still decode — this is the forward-compatibility
        // property the named-field encoding exists for.
        #[derive(Serialize)]
        struct MinimalEntry {
            path: String,
            kind: EntryKind,
            size: u64,
        }
        #[derive(Serialize)]
        struct MinimalOffer {
            entries: Vec<MinimalEntry>,
        }

        let minimal = MinimalOffer {
            entries: vec![MinimalEntry {
                path: "a.txt".into(),
                kind: EntryKind::FILE,
                size: 10,
            }],
        };
        let bytes = rmp_serde::to_vec_named(&minimal).unwrap();
        let decoded: Offer = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.entries[0].path, "a.txt");
        assert_eq!(decoded.total_bytes, 0);
        assert_eq!(decoded.name_hint, None);
        assert_eq!(decoded.entries[0].mode, None);
    }

    #[test]
    fn unknown_entry_kinds_are_data_not_errors() {
        let future = EntryKind(200);
        assert!(future.is_unknown());
        assert!(!future.is_file());
        let msg = ControlMessage::Offer(Offer {
            entries: vec![Entry {
                kind: future,
                ..Entry::file("mystery", 0)
            }],
            total_bytes: 0,
            name_hint: None,
        });
        // Round-trips fine; it is the transfer layer's job to skip it.
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn unknown_codes_still_print_something_useful() {
        assert_eq!(FailureCode(999).to_string(), "error 999");
        assert_eq!(FailureCode::INTEGRITY.to_string(), "integrity failure");
    }

    #[test]
    fn capability_intersection_takes_the_smaller_side() {
        let a = Capabilities {
            max_frame: 1 << 20,
            chunk_size: 262_144,
            features: ["resume".into(), "zstd".into()].into_iter().collect(),
        };
        let b = Capabilities {
            max_frame: 1 << 18,
            chunk_size: 65_536,
            features: ["zstd".into(), "parallel".into()].into_iter().collect(),
        };
        let both = a.intersect(&b);
        assert_eq!(both.max_frame, 1 << 18);
        assert_eq!(both.chunk_size, 65_536);
        assert!(both.has("zstd"));
        assert!(!both.has("resume"));
        assert!(!both.has("parallel"));
        // Intersection is symmetric.
        assert_eq!(both, b.intersect(&a));
    }

    #[test]
    fn roles_are_symmetric() {
        assert_eq!(Role::Sender.peer(), Role::Receiver);
        assert_eq!(Role::Receiver.peer(), Role::Sender);
        assert_eq!(Role::Sender.to_string(), "sender");
    }
}
