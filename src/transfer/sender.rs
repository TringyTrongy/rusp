//! The sending half of a transfer.

use std::path::Path;

use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, IoContext, ProtocolError, Result, TransferError};
use crate::files::Scan;
use crate::protocol::channel::Channel;
use crate::protocol::frame::FrameBuf;
use crate::protocol::message::{
    Capabilities, ControlMessage, Entry, FailureCode, Hash32, Incoming, Offer, Summary,
};
use crate::protocol::{self, DEFAULT_CHUNK_SIZE};
use crate::transfer::progress::{Event, ProgressSink};

/// What the sender achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendReport {
    /// Files the receiver accepted and we sent.
    pub files: u32,
    /// Bytes sent.
    pub bytes: u64,
    /// Files the receiver did not want.
    pub skipped: u32,
}

/// Run the sending side of the protocol to completion.
pub async fn send<R, W>(
    channel: &mut Channel<R, W>,
    scan: &Scan,
    sink: &dyn ProgressSink,
    cancel: &CancellationToken,
) -> Result<SendReport>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let entries = scan.entries();
    let capabilities = negotiate(channel).await?;
    let chunk_size = channel.chunk_size(&capabilities);

    channel
        .send_control(&ControlMessage::Offer(Offer {
            entries: entries.clone(),
            total_bytes: scan.total_bytes,
            name_hint: scan.name_hint.clone(),
        }))
        .await?;

    let wanted = match channel.recv_control().await? {
        ControlMessage::Accept(accept) => validate_selection(&accept.wanted, entries.len())?,
        ControlMessage::Decline { reason } => return Err(TransferError::Declined(reason).into()),
        ControlMessage::Cancel { reason } => return Err(cancelled_by_peer(reason)),
        ControlMessage::Failure { code, message } => return Err(peer_failure(code, message)),
        other => return Err(unexpected(other.name(), "accept or decline")),
    };

    let selected_bytes: u64 = wanted
        .iter()
        .filter(|i| entries[**i as usize].kind.is_file())
        .map(|i| entries[*i as usize].size)
        .sum();
    let selected_files = wanted
        .iter()
        .filter(|i| entries[**i as usize].kind.is_file())
        .count() as u32;
    let skipped = entries.iter().filter(|e| e.kind.is_file()).count() as u32 - selected_files;

    sink.event(Event::Started {
        files: selected_files,
        bytes: selected_bytes,
    });

    let mut buf = FrameBuf::with_capacity(frame_capacity(chunk_size));
    let mut report = SendReport {
        files: 0,
        bytes: 0,
        skipped,
    };

    for index in wanted {
        cancel_check(cancel)?;
        let entry = &entries[index as usize];
        if !entry.kind.is_file() {
            // Directories carry no data; the receiver creates them from the
            // manifest alone.
            continue;
        }
        let Some(path) = source_path(scan, index) else {
            return Err(TransferError::BadManifest(format!(
                "no source file for entry {}",
                entry.path
            ))
            .into());
        };

        sink.event(Event::FileStarted {
            index,
            path: entry.path.clone(),
            size: entry.size,
        });

        let sent = send_file(
            channel, index, entry, path, &mut buf, chunk_size, sink, cancel,
        )
        .await?;
        report.files += 1;
        report.bytes += sent;

        sink.event(Event::FileFinished {
            index,
            path: entry.path.clone(),
        });
    }

    channel
        .send_control(&ControlMessage::Complete(Summary {
            files: report.files,
            bytes: report.bytes,
            skipped: report.skipped,
        }))
        .await?;

    match channel.recv_control().await? {
        ControlMessage::Complete(_) => {}
        ControlMessage::Failure { code, message } => return Err(peer_failure(code, message)),
        ControlMessage::Cancel { reason } => return Err(cancelled_by_peer(reason)),
        other => return Err(unexpected(other.name(), "complete")),
    }

    sink.event(Event::Finished {
        files: report.files,
        bytes: report.bytes,
        skipped: report.skipped,
    });
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
async fn send_file<R, W>(
    channel: &mut Channel<R, W>,
    index: u32,
    entry: &Entry,
    path: &Path,
    buf: &mut FrameBuf,
    chunk_size: usize,
    sink: &dyn ProgressSink,
    cancel: &CancellationToken,
) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    channel
        .send_control(&ControlMessage::FileStart { index })
        .await?;

    let mut file = File::open(path).await.path_ctx("read", path)?;
    let mut hasher = blake3::Hasher::new();
    let mut offset: u64 = 0;

    // The manifest is the contract the receiver accepted, so never send more
    // than it promised even if the file grew since it was scanned.
    while offset < entry.size {
        cancel_check(cancel)?;
        let want = chunk_size.min((entry.size - offset) as usize);
        let mut filled = 0usize;
        {
            let space = channel.stage_data(buf, offset, want);
            // Fill the frame rather than emitting a tiny one per short read.
            while filled < want {
                let n = file
                    .read(&mut space[filled..])
                    .await
                    .path_ctx("read", path)?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            hasher.update(&space[..filled]);
        }
        if filled == 0 {
            // The file shrank under us. Stop here and report what we actually
            // sent, rather than padding with zeroes.
            break;
        }
        channel.finish_data(buf, filled);
        channel.send_frame(buf).await?;
        offset += filled as u64;
        sink.event(Event::Advanced {
            bytes: filled as u64,
        });
    }
    channel.flush().await?;

    channel
        .send_control(&ControlMessage::FileEnd {
            index,
            hash: Hash32::from_bytes(*hasher.finalize().as_bytes()),
            size: offset,
        })
        .await?;
    Ok(offset)
}

/// Exchange capabilities and shrink both sides to what they agree on.
async fn negotiate<R, W>(channel: &mut Channel<R, W>) -> Result<Capabilities>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let ours = protocol::local_capabilities();
    channel
        .send_control(&ControlMessage::Capabilities(ours.clone()))
        .await?;
    let theirs = match channel.recv_control().await? {
        ControlMessage::Capabilities(caps) => caps,
        ControlMessage::Failure { code, message } => return Err(peer_failure(code, message)),
        other => return Err(unexpected(other.name(), "capabilities")),
    };
    let agreed = ours.intersect(&theirs);
    channel.apply_capabilities(&agreed);
    Ok(agreed)
}

/// Check a peer's selection before indexing anything with it.
fn validate_selection(wanted: &[u32], entry_count: usize) -> Result<Vec<u32>> {
    let mut previous: Option<u32> = None;
    for index in wanted {
        if *index as usize >= entry_count {
            return Err(TransferError::BadManifest(format!(
                "the other side asked for item {index}, which was never offered"
            ))
            .into());
        }
        if previous.is_some_and(|p| p >= *index) {
            return Err(TransferError::BadManifest(
                "the other side's selection is out of order or repeats itself".into(),
            )
            .into());
        }
        previous = Some(*index);
    }
    Ok(wanted.to_vec())
}

fn source_path(scan: &Scan, index: u32) -> Option<&Path> {
    scan.sources
        .get(index as usize)
        .and_then(|s| s.path.as_deref())
}

/// Room for a full chunk plus its header and authentication tag, so the data
/// path never reallocates.
pub(crate) fn frame_capacity(chunk_size: usize) -> usize {
    chunk_size.max(DEFAULT_CHUNK_SIZE.min(chunk_size))
        + crate::protocol::message::DATA_HEADER_LEN
        + crate::crypto::TAG_LEN
}

pub(crate) fn cancel_check(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

pub(crate) fn peer_failure(code: FailureCode, message: String) -> Error {
    ProtocolError::Peer(format!("{code}: {message}")).into()
}

pub(crate) fn cancelled_by_peer(_reason: Option<String>) -> Error {
    Error::Cancelled
}

pub(crate) fn unexpected(got: &'static str, expected: &'static str) -> Error {
    ProtocolError::Unexpected { got, expected }.into()
}

/// Drain any message the peer managed to send before the connection broke.
///
/// Called when a write fails: the receiver reports problems with a `Failure`
/// message and then stops reading, so the useful error is usually already
/// sitting in our socket buffer while the write error only says "broken pipe".
pub(crate) async fn recover_peer_error<R, W>(channel: &mut Channel<R, W>) -> Option<Error>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    match channel.recv().await {
        Ok(Some(Incoming::Control(ControlMessage::Failure { code, message }))) => {
            Some(peer_failure(code, message))
        }
        Ok(Some(Incoming::Control(ControlMessage::Cancel { reason }))) => {
            Some(cancelled_by_peer(reason))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_selection_must_be_in_range() {
        assert!(validate_selection(&[0, 1, 2], 3).is_ok());
        assert!(validate_selection(&[], 3).is_ok());
        let err = validate_selection(&[3], 3).unwrap_err();
        assert!(err.to_string().contains("never offered"), "{err}");
        let err = validate_selection(&[0, 99], 3).unwrap_err();
        assert!(err.to_string().contains("never offered"), "{err}");
    }

    #[test]
    fn a_selection_must_be_ordered_and_unique() {
        for bad in [vec![1, 0], vec![0, 0], vec![0, 2, 1]] {
            let err = validate_selection(&bad, 5).unwrap_err();
            assert!(err.to_string().contains("out of order"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn frame_capacity_leaves_room_for_the_overhead() {
        for chunk in [4096, 65_536, DEFAULT_CHUNK_SIZE] {
            assert!(frame_capacity(chunk) > chunk);
        }
    }

    #[test]
    fn cancellation_is_noticed() {
        let cancel = CancellationToken::new();
        assert!(cancel_check(&cancel).is_ok());
        cancel.cancel();
        assert!(cancel_check(&cancel).unwrap_err().is_cancelled());
    }
}
