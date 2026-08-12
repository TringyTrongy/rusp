//! Length-prefixed framing.
//!
//! Every message Rusp sends — handshake, control, or file data — travels as
//! one frame:
//!
//! ```text
//! +--------------------+----------------------------+
//! | payload length u32 | payload (`length` bytes)   |
//! |    big endian      |                            |
//! +--------------------+----------------------------+
//! ```
//!
//! The length is read before anything is allocated and checked against a
//! configured maximum, so a hostile peer cannot make us reserve gigabytes by
//! announcing a huge frame.
//!
//! [`FrameBuf`] exists so the data path never copies. It keeps the four-byte
//! prefix in front of the payload in a single allocation, which lets a caller
//! read file bytes straight into the frame, encrypt them in place, and hand
//! the whole thing to one `write_all`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, IoContext, ProtocolError, Result};

/// Width of the length prefix.
pub const LEN_PREFIX: usize = 4;

/// Largest frame accepted unless a peer negotiates something smaller.
///
/// Big enough for the largest data chunk plus AEAD overhead and a generous
/// manifest; small enough that a hostile peer cannot exhaust memory.
pub const DEFAULT_MAX_FRAME: usize = 1024 * 1024;

/// Smallest maximum frame size a peer may negotiate. Below this the protocol
/// could not carry a useful data chunk.
pub const MIN_MAX_FRAME: usize = 32 * 1024;

/// A reusable frame assembly buffer.
///
/// Layout is `[length prefix][payload]` in one allocation. The buffer grows to
/// a high-water mark and is then reused, so a long transfer performs no
/// per-frame allocation.
#[derive(Debug)]
pub struct FrameBuf {
    bytes: Vec<u8>,
    /// Bytes used, including [`LEN_PREFIX`].
    len: usize,
}

impl FrameBuf {
    /// Create a buffer sized for payloads up to `payload_capacity` bytes.
    pub fn with_capacity(payload_capacity: usize) -> Self {
        FrameBuf {
            bytes: vec![0u8; LEN_PREFIX + payload_capacity],
            len: LEN_PREFIX,
        }
    }

    /// Drop the payload, keeping the allocation.
    pub fn clear(&mut self) {
        self.len = LEN_PREFIX;
    }

    /// Number of payload bytes currently held.
    pub fn payload_len(&self) -> usize {
        self.len - LEN_PREFIX
    }

    /// True when nothing has been written since the last [`clear`](Self::clear).
    pub fn is_empty(&self) -> bool {
        self.len == LEN_PREFIX
    }

    /// The payload written so far.
    pub fn payload(&self) -> &[u8] {
        &self.bytes[LEN_PREFIX..self.len]
    }

    /// The payload written so far, mutably — used for in-place encryption.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[LEN_PREFIX..self.len]
    }

    /// Append one byte.
    pub fn push_u8(&mut self, byte: u8) {
        self.ensure(self.len + 1);
        self.bytes[self.len] = byte;
        self.len += 1;
    }

    /// Append a slice.
    pub fn push_slice(&mut self, data: &[u8]) {
        self.ensure(self.len + data.len());
        self.bytes[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
    }

    /// Claim `n` bytes at the end of the payload and hand back a mutable slice
    /// to fill — for reading file data directly into the frame.
    pub fn claim(&mut self, n: usize) -> &mut [u8] {
        self.ensure(self.len + n);
        let start = self.len;
        self.len += n;
        &mut self.bytes[start..self.len]
    }

    /// Force the payload length, for example after an AEAD tag is appended or
    /// a short read shrinks a claimed region.
    ///
    /// # Panics
    /// Panics if `n` exceeds the buffer's allocated payload capacity.
    pub fn set_payload_len(&mut self, n: usize) {
        assert!(
            LEN_PREFIX + n <= self.bytes.len(),
            "payload length {n} exceeds frame buffer capacity"
        );
        self.len = LEN_PREFIX + n;
    }

    /// Room available past the current payload without reallocating.
    pub fn spare_capacity(&self) -> usize {
        self.bytes.len() - self.len
    }

    /// Stamp the length prefix and return the complete frame.
    pub fn finish(&mut self, max_frame: usize) -> Result<&[u8]> {
        let payload_len = self.payload_len();
        if payload_len > max_frame {
            return Err(ProtocolError::FrameTooLarge {
                actual: payload_len,
                limit: max_frame,
            }
            .into());
        }
        let prefix = (payload_len as u32).to_be_bytes();
        self.bytes[..LEN_PREFIX].copy_from_slice(&prefix);
        Ok(&self.bytes[..self.len])
    }

    fn ensure(&mut self, total: usize) {
        if self.bytes.len() < total {
            // Grow geometrically so a stream of slightly larger frames does
            // not reallocate every time.
            let target = total.max(self.bytes.len() * 2);
            self.bytes.resize(target, 0);
        }
    }
}

/// Reads frames from an async source.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    max_frame: usize,
    header: [u8; LEN_PREFIX],
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Wrap a reader, refusing any frame larger than `max_frame`.
    pub fn new(inner: R, max_frame: usize) -> Self {
        FrameReader {
            inner,
            max_frame,
            header: [0u8; LEN_PREFIX],
        }
    }

    /// The largest frame this reader will accept.
    pub fn max_frame(&self) -> usize {
        self.max_frame
    }

    /// Lower the accepted frame size after negotiation. Never raises it.
    pub fn restrict_max_frame(&mut self, max_frame: usize) {
        self.max_frame = self.max_frame.min(max_frame);
    }

    /// Read one frame into `out`, replacing its contents.
    ///
    /// Returns `Ok(None)` when the peer closed the connection cleanly at a
    /// frame boundary, and [`ProtocolError::UnexpectedEof`] when it closed
    /// part-way through one.
    pub async fn read_frame(&mut self, out: &mut Vec<u8>) -> Result<Option<usize>> {
        match self.inner.read_exact(&mut self.header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::io("read frame header", e)),
        }

        let len = u32::from_be_bytes(self.header) as usize;
        if len > self.max_frame {
            return Err(ProtocolError::FrameTooLarge {
                actual: len,
                limit: self.max_frame,
            }
            .into());
        }

        out.clear();
        out.resize(len, 0);
        self.inner
            .read_exact(out)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => ProtocolError::UnexpectedEof.into(),
                _ => Error::io("read frame body", e),
            })?;
        Ok(Some(len))
    }

    /// Read a frame, treating a clean close as a protocol error.
    pub async fn read_frame_required(&mut self, out: &mut Vec<u8>) -> Result<usize> {
        self.read_frame(out)
            .await?
            .ok_or_else(|| ProtocolError::UnexpectedEof.into())
    }

    /// Borrow the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Recover the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Writes frames to an async sink.
#[derive(Debug)]
pub struct FrameWriter<W> {
    inner: W,
    max_frame: usize,
    scratch: FrameBuf,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    /// Wrap a writer, refusing to emit frames larger than `max_frame`.
    pub fn new(inner: W, max_frame: usize) -> Self {
        FrameWriter {
            inner,
            max_frame,
            scratch: FrameBuf::with_capacity(4096),
        }
    }

    /// The largest frame this writer will emit.
    pub fn max_frame(&self) -> usize {
        self.max_frame
    }

    /// Lower the emitted frame size after negotiation. Never raises it.
    pub fn restrict_max_frame(&mut self, max_frame: usize) {
        self.max_frame = self.max_frame.min(max_frame);
    }

    /// Write a payload, copying it into the internal frame buffer first.
    ///
    /// Convenient for small control messages. Data chunks should use
    /// [`write_buf`](Self::write_buf) instead.
    pub async fn write_payload(&mut self, payload: &[u8]) -> Result<()> {
        self.scratch.clear();
        self.scratch.push_slice(payload);
        let max = self.max_frame;
        let frame = self.scratch.finish(max)?;
        self.inner.write_all(frame).await.ctx("write frame")
    }

    /// Write a frame that the caller assembled, without copying it.
    pub async fn write_buf(&mut self, buf: &mut FrameBuf) -> Result<()> {
        let frame = buf.finish(self.max_frame)?;
        self.inner.write_all(frame).await.ctx("write frame")
    }

    /// Flush buffered bytes to the peer.
    pub async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await.ctx("flush connection")
    }

    /// Flush and close the write half.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await.ctx("close connection")
    }

    /// Borrow the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Recover the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn frame_buf_reserves_room_for_the_prefix() {
        let mut buf = FrameBuf::with_capacity(16);
        assert!(buf.is_empty());
        assert_eq!(buf.payload_len(), 0);
        buf.push_u8(0xAB);
        buf.push_slice(b"hello");
        assert_eq!(buf.payload(), b"\xABhello");
        let frame = buf.finish(DEFAULT_MAX_FRAME).unwrap();
        assert_eq!(&frame[..LEN_PREFIX], &6u32.to_be_bytes());
        assert_eq!(&frame[LEN_PREFIX..], b"\xABhello");
    }

    #[test]
    fn frame_buf_claim_writes_in_place_and_grows() {
        let mut buf = FrameBuf::with_capacity(4);
        buf.push_u8(1);
        buf.claim(64).fill(7);
        assert_eq!(buf.payload_len(), 65);
        assert_eq!(buf.payload()[0], 1);
        assert!(buf.payload()[1..].iter().all(|b| *b == 7));
    }

    #[test]
    fn frame_buf_reuse_keeps_the_allocation() {
        let mut buf = FrameBuf::with_capacity(1024);
        buf.claim(1000);
        let before = buf.spare_capacity();
        buf.clear();
        assert_eq!(buf.payload_len(), 0);
        buf.claim(1000);
        assert_eq!(buf.spare_capacity(), before);
    }

    #[test]
    fn frame_buf_refuses_oversized_frames() {
        let mut buf = FrameBuf::with_capacity(64);
        buf.claim(64);
        let err = buf.finish(32).unwrap_err();
        assert!(matches!(
            err,
            Error::Protocol(ProtocolError::FrameTooLarge {
                actual: 64,
                limit: 32
            })
        ));
    }

    #[test]
    fn set_payload_len_shrinks_and_regrows_within_capacity() {
        let mut buf = FrameBuf::with_capacity(64);
        buf.claim(64);
        buf.set_payload_len(8);
        assert_eq!(buf.payload_len(), 8);
        buf.set_payload_len(64);
        assert_eq!(buf.payload_len(), 64);
    }

    #[test]
    #[should_panic(expected = "exceeds frame buffer capacity")]
    fn set_payload_len_beyond_capacity_panics() {
        let mut buf = FrameBuf::with_capacity(8);
        buf.set_payload_len(9999);
    }

    #[tokio::test]
    async fn frames_round_trip() {
        let (client, server) = tokio::io::duplex(4096);
        let mut writer = FrameWriter::new(client, DEFAULT_MAX_FRAME);
        let mut reader = FrameReader::new(server, DEFAULT_MAX_FRAME);

        writer.write_payload(b"first").await.unwrap();
        writer.write_payload(b"").await.unwrap();
        writer.write_payload(&[0u8; 3000]).await.unwrap();
        writer.flush().await.unwrap();

        let mut out = Vec::new();
        assert_eq!(reader.read_frame(&mut out).await.unwrap(), Some(5));
        assert_eq!(out, b"first");
        assert_eq!(reader.read_frame(&mut out).await.unwrap(), Some(0));
        assert!(out.is_empty());
        assert_eq!(reader.read_frame(&mut out).await.unwrap(), Some(3000));
        assert_eq!(out, vec![0u8; 3000]);
    }

    #[tokio::test]
    async fn clean_close_reports_end_of_stream() {
        let (client, server) = tokio::io::duplex(64);
        let mut writer = FrameWriter::new(client, DEFAULT_MAX_FRAME);
        writer.write_payload(b"bye").await.unwrap();
        writer.shutdown().await.unwrap();
        drop(writer);

        let mut reader = FrameReader::new(server, DEFAULT_MAX_FRAME);
        let mut out = Vec::new();
        assert_eq!(reader.read_frame(&mut out).await.unwrap(), Some(3));
        assert_eq!(reader.read_frame(&mut out).await.unwrap(), None);
        assert!(matches!(
            reader.read_frame_required(&mut out).await.unwrap_err(),
            Error::Protocol(ProtocolError::UnexpectedEof)
        ));
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error_not_a_clean_close() {
        let (mut client, server) = tokio::io::duplex(64);
        // Announce ten bytes, send four, hang up.
        client.write_all(&10u32.to_be_bytes()).await.unwrap();
        client.write_all(b"abcd").await.unwrap();
        drop(client);

        let mut reader = FrameReader::new(server, DEFAULT_MAX_FRAME);
        let mut out = Vec::new();
        assert!(matches!(
            reader.read_frame(&mut out).await.unwrap_err(),
            Error::Protocol(ProtocolError::UnexpectedEof)
        ));
    }

    #[tokio::test]
    async fn oversized_announcement_is_refused_before_allocating() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(&u32::MAX.to_be_bytes()).await.unwrap();

        let mut reader = FrameReader::new(server, 1024);
        let mut out = Vec::new();
        let err = reader.read_frame(&mut out).await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::Protocol(ProtocolError::FrameTooLarge {
                    actual,
                    limit: 1024
                }) if actual == u32::MAX as usize
            ),
            "{err}"
        );
        assert!(out.is_empty(), "nothing should have been allocated");
    }

    #[test]
    fn negotiated_limits_only_shrink() {
        let mut reader = FrameReader::new(tokio::io::empty(), 1024);
        reader.restrict_max_frame(512);
        assert_eq!(reader.max_frame(), 512);
        reader.restrict_max_frame(4096);
        assert_eq!(reader.max_frame(), 512);

        let mut writer = FrameWriter::new(tokio::io::sink(), 1024);
        writer.restrict_max_frame(512);
        assert_eq!(writer.max_frame(), 512);
        writer.restrict_max_frame(4096);
        assert_eq!(writer.max_frame(), 512);
    }
}
