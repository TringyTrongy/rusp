//! The secure message channel.
//!
//! [`Channel`] is where the framing layer, the cipher and the message codec
//! meet. It runs the handshake, then exposes exactly two things: send a
//! control message, and receive whatever comes next.
//!
//! It is generic over any [`AsyncRead`]/[`AsyncWrite`] pair, so the same code
//! runs over a direct TCP connection, a relayed one, or an in-memory pipe in a
//! test. Nothing here knows how the two peers found each other.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::code::TransferCode;
use crate::crypto::{self, cipher::TAG_LEN, OpeningKey, SealingKey, SessionKeys, Transcript};
use crate::error::{ProtocolError, Result};
use crate::protocol::frame::{FrameBuf, FrameReader, FrameWriter, DEFAULT_MAX_FRAME};
use crate::protocol::message::{
    self, Capabilities, ControlMessage, FailureCode, Handshake, Hello, Incoming, Role,
    DATA_HEADER_LEN,
};
use crate::protocol::{self, MIN_CHUNK_SIZE};

/// Bytes reserved for the control-message assembly buffer. Control messages
/// are small; a manifest that outgrows this simply reallocates once.
const CONTROL_BUF_CAPACITY: usize = 8 * 1024;

/// An authenticated, encrypted, framed message channel with a peer.
#[derive(Debug)]
pub struct Channel<R, W> {
    reader: FrameReader<R>,
    writer: FrameWriter<W>,
    seal: SealingKey,
    open: OpeningKey,
    version: u16,
    role: Role,
    peer_agent: String,
    in_buf: Vec<u8>,
    out_buf: FrameBuf,
}

impl<R, W> Channel<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Run the handshake and return a channel ready to carry messages.
    ///
    /// Both sides exchange magic, `Hello`, a SPAKE2 element and a
    /// confirmation tag, in that order. A mismatched code fails at the
    /// confirmation step with [`crate::error::CryptoError::KeyMismatch`] and
    /// no user data is ever sent.
    ///
    /// This performs no timing of its own; wrap the call in
    /// [`tokio::time::timeout`] to bound how long a peer may stall.
    pub async fn establish(read: R, write: W, role: Role, code: &TransferCode) -> Result<Self> {
        let mut reader = FrameReader::new(read, DEFAULT_MAX_FRAME);
        let mut writer = FrameWriter::new(write, DEFAULT_MAX_FRAME);
        let mut out = FrameBuf::with_capacity(CONTROL_BUF_CAPACITY);
        let mut in_buf = Vec::with_capacity(CONTROL_BUF_CAPACITY);

        protocol::write_magic(writer.get_mut()).await?;
        writer.flush().await?;
        protocol::read_magic(reader.get_mut()).await?;

        // --- Hello -------------------------------------------------------
        let ours = protocol::local_hello(role);
        Handshake::Hello(ours).encode(&mut out)?;
        let our_hello_payload = out.payload().to_vec();
        writer.write_buf(&mut out).await?;
        writer.flush().await?;

        reader.read_frame_required(&mut in_buf).await?;
        let peer_hello_payload = in_buf.clone();
        let peer_hello = expect_hello(Handshake::decode(&in_buf)?)?;
        let version = protocol::negotiate_version(&peer_hello)?;
        protocol::check_role(&peer_hello, role.peer())?;

        let mut transcript = Transcript::new();
        transcript.absorb("magic", &protocol::MAGIC);
        transcript.absorb_u16("version", version);
        let (sender_hello, receiver_hello) = order(role, &our_hello_payload, &peer_hello_payload);
        transcript.absorb("hello-sender", sender_hello);
        transcript.absorb("hello-receiver", receiver_hello);

        // --- SPAKE2 ------------------------------------------------------
        let (pake_state, our_element) = crypto::pake::start(role, code);
        Handshake::Pake(our_element).encode(&mut out)?;
        let our_pake_payload = out.payload().to_vec();
        writer.write_buf(&mut out).await?;
        writer.flush().await?;

        reader.read_frame_required(&mut in_buf).await?;
        let peer_pake_payload = in_buf.clone();
        let peer_element = expect_pake(Handshake::decode(&in_buf)?)?;

        let (sender_pake, receiver_pake) = order(role, &our_pake_payload, &peer_pake_payload);
        transcript.absorb("pake-sender", sender_pake);
        transcript.absorb("pake-receiver", receiver_pake);
        let transcript = transcript.finish();

        let pake_output = pake_state.finish(&peer_element)?;
        let keys = SessionKeys::derive(role, version, &pake_output, &transcript)?;

        // --- Key confirmation --------------------------------------------
        let our_tag = crypto::confirm_tag(&keys.our_confirm, &transcript);
        Handshake::Confirm(our_tag.to_vec()).encode(&mut out)?;
        writer.write_buf(&mut out).await?;
        writer.flush().await?;

        reader.read_frame_required(&mut in_buf).await?;
        let peer_tag = expect_confirm(Handshake::decode(&in_buf)?)?;
        crypto::verify_confirm(&keys.peer_confirm, &transcript, &peer_tag)?;

        Ok(Channel {
            reader,
            writer,
            seal: SealingKey::new(&keys.seal),
            open: OpeningKey::new(&keys.open),
            version,
            role,
            peer_agent: peer_hello.agent,
            in_buf,
            out_buf: out,
        })
    }

    /// The negotiated protocol version.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// This side's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The peer's self-reported implementation string. Diagnostics only —
    /// nothing about the transfer depends on it.
    pub fn peer_agent(&self) -> &str {
        &self.peer_agent
    }

    /// Largest file chunk that fits in one frame.
    pub fn max_data_len(&self) -> usize {
        self.writer
            .max_frame()
            .saturating_sub(DATA_HEADER_LEN + TAG_LEN)
    }

    /// Apply negotiated capabilities, shrinking the frame limits to what both
    /// sides agreed. Limits only ever shrink, so a peer cannot talk us into
    /// accepting bigger frames than this build is willing to buffer.
    pub fn apply_capabilities(&mut self, caps: &Capabilities) {
        let max_frame = (caps.max_frame as usize).max(crate::protocol::frame::MIN_MAX_FRAME);
        self.reader.restrict_max_frame(max_frame);
        self.writer.restrict_max_frame(max_frame);
    }

    /// Chunk size to use for file data, given negotiated capabilities.
    pub fn chunk_size(&self, caps: &Capabilities) -> usize {
        (caps.chunk_size as usize)
            .clamp(MIN_CHUNK_SIZE, self.max_data_len())
            .max(1)
    }

    /// Encrypt and send a control message.
    pub async fn send_control(&mut self, msg: &ControlMessage) -> Result<()> {
        message::encode_control(msg, &mut self.out_buf)?;
        self.seal.seal(&mut self.out_buf)?;
        self.writer.write_buf(&mut self.out_buf).await?;
        self.writer.flush().await
    }

    /// Report a failure to the peer on a best-effort basis.
    ///
    /// Used on the way out of an error, where the connection may already be
    /// gone; a failure to deliver the message is not itself worth reporting.
    pub async fn send_failure(&mut self, code: FailureCode, message: impl Into<String>) {
        let _ = self
            .send_control(&ControlMessage::Failure {
                code,
                message: message.into(),
            })
            .await;
    }

    /// Prepare `buf` to carry file data, returning the space to fill.
    ///
    /// The caller reads file bytes straight into the returned slice, calls
    /// [`finish_data`](Self::finish_data) with the number of bytes actually
    /// read, and then [`send_frame`](Self::send_frame). No copy of the file
    /// data is made at any point.
    pub fn stage_data<'a>(&self, buf: &'a mut FrameBuf, offset: u64, len: usize) -> &'a mut [u8] {
        message::start_data(buf, offset, len)
    }

    /// Shrink a staged data frame to the number of bytes actually read.
    pub fn finish_data(&self, buf: &mut FrameBuf, filled: usize) {
        buf.set_payload_len(DATA_HEADER_LEN + filled);
    }

    /// Encrypt and send a frame the caller staged.
    pub async fn send_frame(&mut self, buf: &mut FrameBuf) -> Result<()> {
        self.seal.seal(buf)?;
        self.writer.write_buf(buf).await
    }

    /// Flush anything buffered towards the peer.
    pub async fn flush(&mut self) -> Result<()> {
        self.writer.flush().await
    }

    /// Close the write half after flushing.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.writer.shutdown().await
    }

    /// Receive the next message, or `None` if the peer closed cleanly.
    pub async fn recv(&mut self) -> Result<Option<Incoming<'_>>> {
        if self.reader.read_frame(&mut self.in_buf).await?.is_none() {
            return Ok(None);
        }
        self.open.open(&mut self.in_buf)?;
        message::decode_incoming(&self.in_buf).map(Some)
    }

    /// Receive the next message, treating a clean close as a protocol error.
    pub async fn recv_required(&mut self) -> Result<Incoming<'_>> {
        self.recv()
            .await?
            .ok_or_else(|| ProtocolError::UnexpectedEof.into())
    }

    /// Receive the next control message, refusing file data.
    ///
    /// Used wherever the state machine is waiting for an answer rather than a
    /// stream of bytes.
    pub async fn recv_control(&mut self) -> Result<ControlMessage> {
        match self.recv_required().await? {
            Incoming::Control(msg) => Ok(msg),
            Incoming::Data { .. } => Err(ProtocolError::Unexpected {
                got: "data",
                expected: "a control message",
            }
            .into()),
        }
    }

    /// Number of frames sealed and opened so far, for diagnostics.
    pub fn frame_counts(&self) -> (u64, u64) {
        (self.seal.counter(), self.open.counter())
    }
}

/// Put two payloads in sender-then-receiver order regardless of which side we
/// are, so both peers hash the same transcript.
fn order<'a>(role: Role, ours: &'a [u8], theirs: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    match role {
        Role::Sender => (ours, theirs),
        Role::Receiver => (theirs, ours),
    }
}

fn expect_hello(msg: Handshake) -> Result<Hello> {
    match msg {
        Handshake::Hello(hello) => Ok(hello),
        other => Err(ProtocolError::Unexpected {
            got: other.name(),
            expected: "hello",
        }
        .into()),
    }
}

fn expect_pake(msg: Handshake) -> Result<Vec<u8>> {
    match msg {
        Handshake::Pake(bytes) => Ok(bytes),
        other => Err(ProtocolError::Unexpected {
            got: other.name(),
            expected: "pake",
        }
        .into()),
    }
}

fn expect_confirm(msg: Handshake) -> Result<Vec<u8>> {
    match msg {
        Handshake::Confirm(bytes) => Ok(bytes),
        other => Err(ProtocolError::Unexpected {
            got: other.name(),
            expected: "confirm",
        }
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{CryptoError, Error};
    use crate::protocol::message::{Accept, Summary};
    use tokio::io::{duplex, AsyncWriteExt, DuplexStream};

    type TestChannel =
        Channel<tokio::io::ReadHalf<DuplexStream>, tokio::io::WriteHalf<DuplexStream>>;

    /// Run both handshakes concurrently over an in-memory pipe.
    async fn connect(
        sender_code: &TransferCode,
        receiver_code: &TransferCode,
    ) -> (Result<TestChannel>, Result<TestChannel>) {
        let (a, b) = duplex(2 * DEFAULT_MAX_FRAME);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let sender_code = sender_code.clone();
        let receiver_code = receiver_code.clone();

        let sender =
            tokio::spawn(
                async move { Channel::establish(ar, aw, Role::Sender, &sender_code).await },
            );
        let receiver = tokio::spawn(async move {
            Channel::establish(br, bw, Role::Receiver, &receiver_code).await
        });
        (sender.await.unwrap(), receiver.await.unwrap())
    }

    fn code(text: &str) -> TransferCode {
        TransferCode::parse(text).unwrap()
    }

    async fn established() -> (TestChannel, TestChannel) {
        let c = code("k7m2-cotton-harbor-tiger-pencil");
        let (s, r) = connect(&c, &c).await;
        (s.unwrap(), r.unwrap())
    }

    #[tokio::test]
    async fn handshake_succeeds_with_matching_codes() {
        let (sender, receiver) = established().await;
        assert_eq!(sender.version(), protocol::PROTOCOL_MAX);
        assert_eq!(receiver.version(), protocol::PROTOCOL_MAX);
        assert_eq!(sender.role(), Role::Sender);
        assert_eq!(receiver.role(), Role::Receiver);
        assert!(sender.peer_agent().starts_with("rusp/"));
    }

    #[tokio::test]
    async fn a_mistyped_code_fails_before_any_data_moves() {
        let (sender, receiver) = connect(
            &code("k7m2-cotton-harbor-tiger-pencil"),
            &code("k7m2-cotton-harbor-tiger-museum"),
        )
        .await;
        for result in [sender, receiver] {
            let err = result.expect_err("handshake must fail");
            assert!(
                matches!(err, Error::Crypto(CryptoError::KeyMismatch)),
                "{err}"
            );
            // And the message tells the user what to do about it.
            assert!(err.hint().is_some());
        }
    }

    #[tokio::test]
    async fn the_same_words_in_a_different_room_do_not_connect() {
        let (sender, _) = connect(
            &code("aaaa-cotton-harbor-tiger-pencil"),
            &code("bbbb-cotton-harbor-tiger-pencil"),
        )
        .await;
        assert!(matches!(
            sender.unwrap_err(),
            Error::Crypto(CryptoError::KeyMismatch)
        ));
    }

    #[tokio::test]
    async fn control_messages_flow_in_both_directions() {
        let (mut sender, mut receiver) = established().await;

        let caps = protocol::local_capabilities();
        sender
            .send_control(&ControlMessage::Capabilities(caps.clone()))
            .await
            .unwrap();
        match receiver.recv_control().await.unwrap() {
            ControlMessage::Capabilities(got) => assert_eq!(got, caps),
            other => panic!("got {}", other.name()),
        }

        receiver
            .send_control(&ControlMessage::Accept(Accept { wanted: vec![0, 1] }))
            .await
            .unwrap();
        match sender.recv_control().await.unwrap() {
            ControlMessage::Accept(got) => assert_eq!(got.wanted, vec![0, 1]),
            other => panic!("got {}", other.name()),
        }
    }

    #[tokio::test]
    async fn data_frames_carry_bytes_without_a_copy() {
        let (mut sender, mut receiver) = established().await;
        let chunk = vec![0xA5u8; 100_000];

        let mut buf = FrameBuf::with_capacity(sender.max_data_len() + 64);
        let space = sender.stage_data(&mut buf, 4096, chunk.len());
        space.copy_from_slice(&chunk);
        sender.finish_data(&mut buf, chunk.len());
        sender.send_frame(&mut buf).await.unwrap();
        sender.flush().await.unwrap();

        match receiver.recv_required().await.unwrap() {
            Incoming::Data { offset, bytes } => {
                assert_eq!(offset, 4096);
                assert_eq!(bytes, &chunk[..]);
            }
            other => panic!("got {}", other.name()),
        }
    }

    #[tokio::test]
    async fn a_short_read_can_shrink_a_staged_frame() {
        let (mut sender, mut receiver) = established().await;
        let mut buf = FrameBuf::with_capacity(4096);
        let space = sender.stage_data(&mut buf, 0, 4096);
        space[..10].copy_from_slice(b"only these");
        sender.finish_data(&mut buf, 10);
        sender.send_frame(&mut buf).await.unwrap();
        sender.flush().await.unwrap();

        match receiver.recv_required().await.unwrap() {
            Incoming::Data { bytes, .. } => assert_eq!(bytes, b"only these"),
            other => panic!("got {}", other.name()),
        }
    }

    #[tokio::test]
    async fn recv_control_refuses_file_data() {
        let (mut sender, mut receiver) = established().await;
        let mut buf = FrameBuf::with_capacity(64);
        sender.stage_data(&mut buf, 0, 4);
        sender.finish_data(&mut buf, 4);
        sender.send_frame(&mut buf).await.unwrap();
        sender.flush().await.unwrap();

        assert!(matches!(
            receiver.recv_control().await.unwrap_err(),
            Error::Protocol(ProtocolError::Unexpected { got: "data", .. })
        ));
    }

    #[tokio::test]
    async fn a_clean_close_is_not_an_error() {
        let (mut sender, mut receiver) = established().await;
        sender
            .send_control(&ControlMessage::Complete(Summary::default()))
            .await
            .unwrap();
        sender.shutdown().await.unwrap();
        drop(sender);

        assert!(receiver.recv().await.unwrap().is_some());
        assert!(receiver.recv().await.unwrap().is_none());
        assert!(matches!(
            receiver.recv_required().await.unwrap_err(),
            Error::Protocol(ProtocolError::UnexpectedEof)
        ));
    }

    #[tokio::test]
    async fn a_tampered_frame_ends_the_session() {
        let (a, b) = duplex(2 * DEFAULT_MAX_FRAME);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let c = code("k7m2-cotton-harbor-tiger-pencil");
        let c2 = c.clone();

        let sender = tokio::spawn(async move {
            let mut ch = Channel::establish(ar, aw, Role::Sender, &c2).await.unwrap();
            ch.send_control(&ControlMessage::Keepalive).await.unwrap();
            // Then a frame that has been corrupted in flight: a valid length
            // prefix over bytes that will not authenticate.
            let inner = ch.writer.get_mut();
            inner.write_all(&32u32.to_be_bytes()).await.unwrap();
            inner.write_all(&[0u8; 32]).await.unwrap();
            inner.flush().await.unwrap();
        });

        let mut receiver = Channel::establish(br, bw, Role::Receiver, &c)
            .await
            .unwrap();
        assert!(matches!(
            receiver.recv_required().await.unwrap(),
            Incoming::Control(ControlMessage::Keepalive)
        ));
        assert!(matches!(
            receiver.recv().await.unwrap_err(),
            Error::Crypto(CryptoError::Decrypt)
        ));
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn a_non_rusp_peer_is_rejected_immediately() {
        let (a, mut b) = duplex(1024);
        let (ar, aw) = tokio::io::split(a);
        let c = code("k7m2-cotton-harbor-tiger-pencil");

        let task = tokio::spawn(async move { Channel::establish(ar, aw, Role::Sender, &c).await });
        b.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            Error::Protocol(ProtocolError::BadMagic)
        ));
    }

    #[tokio::test]
    async fn two_senders_refuse_to_pair() {
        let (a, b) = duplex(2 * DEFAULT_MAX_FRAME);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let c = code("k7m2-cotton-harbor-tiger-pencil");
        let c2 = c.clone();

        let first =
            tokio::spawn(async move { Channel::establish(ar, aw, Role::Sender, &c2).await });
        let second = Channel::establish(br, bw, Role::Sender, &c).await;
        let err = second.unwrap_err();
        assert!(err.to_string().contains("also a sender"), "{err}");
        let _ = first.await.unwrap();
    }

    #[tokio::test]
    async fn a_peer_that_hangs_up_mid_handshake_is_reported_cleanly() {
        let (a, b) = duplex(1024);
        let (ar, aw) = tokio::io::split(a);
        let c = code("k7m2-cotton-harbor-tiger-pencil");

        let task = tokio::spawn(async move { Channel::establish(ar, aw, Role::Sender, &c).await });
        drop(b);
        let err = task.await.unwrap().unwrap_err();
        assert!(
            matches!(
                err,
                Error::Protocol(ProtocolError::UnexpectedEof) | Error::Io { .. }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn capabilities_only_ever_shrink_the_limits() {
        let (mut sender, _receiver) = established().await;
        let before = sender.max_data_len();

        sender.apply_capabilities(&Capabilities {
            max_frame: 64 * 1024,
            chunk_size: 32 * 1024,
            features: Default::default(),
        });
        assert!(sender.max_data_len() < before);

        // A peer claiming a huge frame size cannot raise our limit back up.
        let shrunk = sender.max_data_len();
        sender.apply_capabilities(&Capabilities {
            max_frame: u32::MAX,
            chunk_size: u32::MAX,
            features: Default::default(),
        });
        assert_eq!(sender.max_data_len(), shrunk);
    }

    #[tokio::test]
    async fn chunk_size_stays_inside_the_frame() {
        let (sender, _receiver) = established().await;
        let caps = Capabilities {
            max_frame: DEFAULT_MAX_FRAME as u32,
            chunk_size: u32::MAX,
            features: Default::default(),
        };
        assert!(sender.chunk_size(&caps) <= sender.max_data_len());

        let tiny = Capabilities {
            max_frame: DEFAULT_MAX_FRAME as u32,
            chunk_size: 1,
            features: Default::default(),
        };
        assert_eq!(sender.chunk_size(&tiny), MIN_CHUNK_SIZE);
    }

    #[tokio::test]
    async fn frames_are_counted() {
        let (mut sender, mut receiver) = established().await;
        assert_eq!(sender.frame_counts(), (0, 0));
        sender
            .send_control(&ControlMessage::Keepalive)
            .await
            .unwrap();
        let _ = receiver.recv_required().await.unwrap();
        assert_eq!(sender.frame_counts().0, 1);
        assert_eq!(receiver.frame_counts().1, 1);
    }
}
