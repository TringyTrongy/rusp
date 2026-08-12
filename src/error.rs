//! Error types for Rusp.
//!
//! The crate uses one concrete error enum per layer ([`CodeError`],
//! [`ProtocolError`], [`CryptoError`], [`NetworkError`], [`TransferError`]) and
//! a single top-level [`Error`] that wraps them. Layers return their own error
//! type so the type signature says what can actually go wrong; the binary only
//! ever has to deal with [`Error`].
//!
//! Every message is written to be read by someone who is trying to send a file,
//! not by someone reading a backtrace. Where a failure has an obvious next step,
//! [`Error::hint`] supplies it.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The top-level error type surfaced to the CLI.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The transfer code could not be generated or understood.
    #[error(transparent)]
    Code(#[from] CodeError),

    /// Configuration file or environment problem.
    #[error("configuration: {0}")]
    Config(String),

    /// The peer violated the wire protocol.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// Key exchange, encryption or authentication failure.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// Could not reach, or lost, the peer.
    #[error(transparent)]
    Network(#[from] NetworkError),

    /// The transfer itself failed.
    #[error(transparent)]
    Transfer(#[from] TransferError),

    /// A filesystem or socket operation failed, with human context attached.
    #[error("{context}: {source}")]
    Io {
        /// What we were trying to do, e.g. `read /home/me/photo.jpg`.
        context: String,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },

    /// The user pressed Ctrl+C, or the peer cancelled.
    #[error("transfer cancelled")]
    Cancelled,
}

impl Error {
    /// Build an [`Error::Io`] with context describing what failed.
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    /// Build an [`Error::Io`] for an operation on a specific path.
    pub fn path(action: &str, path: impl AsRef<Path>, source: io::Error) -> Self {
        Error::Io {
            context: format!("{action} {}", path.as_ref().display()),
            source,
        }
    }

    /// True when the failure was a deliberate cancellation rather than a fault.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Error::Cancelled)
    }

    /// A short, actionable suggestion to print underneath the error, when one
    /// exists. Returns `None` when the error message already says everything
    /// useful.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Error::Crypto(CryptoError::KeyMismatch) => Some(
                "Check the code for typos, then ask the sender to start again — \
                 a code may only be used once.",
            ),
            Error::Network(NetworkError::NoRoute) => Some(
                "Rusp found no peer on this network and no relay is configured. \
                 Run `rusp relay` on a reachable host and pass `--relay host:port` \
                 on both sides, or set RUSP_RELAY.",
            ),
            Error::Network(NetworkError::RoomBusy(_)) => {
                Some("Ask the sender to generate a fresh code and try again.")
            }
            Error::Network(NetworkError::Timeout(_)) => {
                Some("Make sure the other side is running and using the same code.")
            }
            Error::Protocol(ProtocolError::IncompatibleVersion { .. }) => {
                Some("Both machines need compatible Rusp versions. Upgrade the older one.")
            }
            Error::Transfer(TransferError::Exists(_)) => {
                Some("Pass `--on-conflict rename` to keep both files, or `--overwrite` to replace.")
            }
            _ => None,
        }
    }
}

/// Attach human-readable context to [`io::Result`] values without pulling in a
/// dynamic error crate.
pub trait IoContext<T> {
    /// Describe the operation that failed, e.g. `"create /tmp/out"`.
    fn ctx(self, context: impl Into<String>) -> Result<T>;

    /// Describe an operation on a path, e.g. `("read", "/tmp/x")`.
    fn path_ctx(self, action: &str, path: impl AsRef<Path>) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn ctx(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|source| Error::io(context, source))
    }

    fn path_ctx(self, action: &str, path: impl AsRef<Path>) -> Result<T> {
        self.map_err(|source| Error::path(action, path, source))
    }
}

/// Failures parsing or generating a transfer code.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodeError {
    /// Nothing was typed.
    #[error("no transfer code was given")]
    Empty,

    /// The code had a room part but no secret.
    #[error(
        "this code has no secret words — it should look like `k7m2-cotton-harbor-tiger-pencil`"
    )]
    MissingSecret,

    /// The routing part of the code is not a valid room identifier.
    #[error("`{0}` is not a valid room name: use 1-16 characters, a-z or 0-9")]
    InvalidRoom(String),

    /// The secret portion is too weak to be worth using.
    #[error("the secret part of this code is too short: use at least {min} characters")]
    SecretTooShort {
        /// Minimum accepted secret length in characters.
        min: usize,
    },

    /// Fewer words requested than the minimum.
    #[error("a generated code needs at least {min} words ({bits} bits of entropy)")]
    TooFewWords {
        /// Minimum word count.
        min: usize,
        /// Entropy that minimum buys.
        bits: u32,
    },

    /// Absurd word count requested.
    #[error("{0} words is more than a person will ever type; the maximum is {max}", max = super::code::MAX_WORDS)]
    TooManyWords(usize),

    /// The OS refused to give us randomness.
    #[error("could not read secure random bytes from the operating system: {0}")]
    Random(String),
}

/// Wire protocol violations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The peer's supported version range does not overlap ours.
    #[error(
        "incompatible protocol versions: the peer speaks v{peer_min}-v{peer_max}, \
         this build speaks v{ours_min}-v{ours_max}"
    )]
    IncompatibleVersion {
        /// Lowest version the peer accepts.
        peer_min: u16,
        /// Highest version the peer accepts.
        peer_max: u16,
        /// Lowest version we accept.
        ours_min: u16,
        /// Highest version we accept.
        ours_max: u16,
    },

    /// A frame exceeded the negotiated limit; refused before allocating.
    #[error("the peer announced a {actual} byte frame but the limit is {limit} bytes")]
    FrameTooLarge {
        /// Size the peer announced.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },

    /// The stream ended mid-message.
    #[error("the connection closed unexpectedly")]
    UnexpectedEof,

    /// The bytes did not decode into a valid message.
    #[error("malformed message from the peer: {0}")]
    Malformed(String),

    /// A valid message, but not one that is legal in this state.
    #[error("protocol desync: got {got} while expecting {expected}")]
    Unexpected {
        /// Message we received.
        got: &'static str,
        /// Message we were waiting for.
        expected: &'static str,
    },

    /// The peer reported a failure of its own.
    #[error("the peer reported an error: {0}")]
    Peer(String),

    /// The first bytes on the wire were not the Rusp magic.
    #[error("this does not look like a Rusp connection")]
    BadMagic,
}

/// Cryptographic failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// Key confirmation failed: wrong code, or an active attacker.
    #[error("the transfer codes do not match")]
    KeyMismatch,

    /// The SPAKE2 exchange itself failed (malformed element).
    #[error("password-authenticated key exchange failed")]
    Pake,

    /// AEAD authentication failed on an inbound frame.
    #[error("message authentication failed: the data was corrupted or tampered with in transit")]
    Decrypt,

    /// The 64-bit frame counter for a direction was exhausted.
    #[error("session message limit reached; start a new transfer")]
    NonceExhausted,

    /// HKDF rejected the requested output length.
    #[error("key derivation failed")]
    Kdf,
}

/// Connectivity failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetworkError {
    /// Could not open a connection to the relay.
    #[error("could not reach the relay at {addr}: {source}")]
    RelayConnect {
        /// Relay address we tried.
        addr: String,
        /// Underlying socket error.
        #[source]
        source: io::Error,
    },

    /// Neither LAN discovery nor a relay produced a usable path to the peer.
    #[error("could not find the other side: no peer on this network and no relay configured")]
    NoRoute,

    /// Ran out of patience waiting for the peer.
    #[error("timed out after {0:.0?} waiting for the other side")]
    Timeout(Duration),

    /// The relay refused us (bad token, overloaded, protocol mismatch).
    #[error("the relay refused the connection: {0}")]
    RelayRejected(String),

    /// Another pair is already using this room.
    #[error("relay room `{0}` is already in use")]
    RoomBusy(String),

    /// Could not bind a local socket.
    #[error("could not listen on {addr}: {source}")]
    Bind {
        /// Address we tried to bind.
        addr: String,
        /// Underlying socket error.
        #[source]
        source: io::Error,
    },

    /// The relay address could not be resolved.
    #[error("`{0}` did not resolve to any address")]
    Unresolvable(String),
}

/// Failures during the transfer itself.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransferError {
    /// A received file did not hash to the value the sender declared.
    #[error("{path}: integrity check failed (expected {expected}, computed {actual})")]
    Integrity {
        /// Relative path of the offending file.
        path: String,
        /// Hash the sender declared.
        expected: String,
        /// Hash we computed.
        actual: String,
    },

    /// The receiver said no.
    #[error("the other side declined the transfer{}", opt_reason(.0))]
    Declined(Option<String>),

    /// The peer offered a path that would escape the destination directory.
    #[error("the sender offered an unsafe path and it was refused: {0}")]
    UnsafePath(String),

    /// Destination already exists and the conflict policy is `fail`.
    #[error("{0} already exists")]
    Exists(PathBuf),

    /// Nothing was selected to send.
    #[error("nothing to send")]
    Empty,

    /// Byte count did not match the manifest.
    #[error("{path}: expected {expected} bytes but received {actual}")]
    SizeMismatch {
        /// Relative path of the offending file.
        path: String,
        /// Size from the manifest.
        expected: u64,
        /// Size actually received.
        actual: u64,
    },

    /// The manifest itself was not acceptable.
    #[error("the offer from the sender was rejected: {0}")]
    BadManifest(String),
}

fn opt_reason(reason: &Option<String>) -> String {
    match reason {
        Some(r) if !r.is_empty() => format!(": {r}"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_context_is_attached() {
        let err: Result<()> = Err(io::Error::new(io::ErrorKind::NotFound, "boom"))
            .path_ctx("read", Path::new("/tmp/nope"));
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("read /tmp/nope"), "{msg}");
        assert!(msg.contains("boom"), "{msg}");
    }

    #[test]
    fn declined_without_reason_reads_cleanly() {
        let e = TransferError::Declined(None);
        assert_eq!(e.to_string(), "the other side declined the transfer");
        let e = TransferError::Declined(Some("out of disk".into()));
        assert_eq!(
            e.to_string(),
            "the other side declined the transfer: out of disk"
        );
    }

    #[test]
    fn key_mismatch_has_a_hint() {
        let e = Error::from(CryptoError::KeyMismatch);
        assert!(e.hint().is_some());
        assert!(!e.to_string().contains("Error"));
    }

    #[test]
    fn cancelled_is_detectable() {
        assert!(Error::Cancelled.is_cancelled());
        assert!(!Error::Config("x".into()).is_cancelled());
    }
}
