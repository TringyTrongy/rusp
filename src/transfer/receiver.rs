//! The receiving half of a transfer.
//!
//! Receiving happens in two steps on purpose. [`begin`] runs the negotiation
//! and hands back a [`PendingOffer`] describing exactly what would land where;
//! only when the caller calls [`PendingOffer::accept`] does anything touch the
//! disk. That is what lets the CLI show the user a list and ask, without the
//! transfer engine knowing anything about prompts.

use std::collections::HashSet;
use std::path::PathBuf;

use tokio_util::sync::CancellationToken;

use crate::config::ConflictPolicy;
use crate::error::{Error, Result, TransferError};
use crate::files::safe_path;
use crate::files::writer::{self, Destination, FileWriter};
use crate::protocol::channel::Channel;
use crate::protocol::message::{
    Capabilities, ControlMessage, Entry, FailureCode, Hash32, Incoming, Offer, Summary, MAX_ENTRIES,
};
use crate::protocol::{self};
use crate::transfer::progress::{Event, ProgressSink};
use crate::transfer::sender::{cancel_check, cancelled_by_peer, peer_failure, unexpected};

/// Where received files go and what to do about collisions.
#[derive(Debug, Clone)]
pub struct ReceiveOptions {
    /// Directory to write into.
    pub output_dir: PathBuf,
    /// What to do when a file already exists.
    pub on_conflict: ConflictPolicy,
}

/// What the receiver ended up doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveReport {
    /// Files written and verified.
    pub files: u32,
    /// Bytes written.
    pub bytes: u64,
    /// Files deliberately not written.
    pub skipped: u32,
    /// Directories created.
    pub directories: u32,
    /// Where everything went.
    pub output_dir: PathBuf,
}

/// What accepting this offer would do.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// Manifest indices the receiver wants, ascending.
    pub wanted: Vec<u32>,
    /// Entries that will not be transferred, with the reason.
    pub skipped: Vec<(u32, String)>,
    /// Files that would be written.
    pub files: u32,
    /// Bytes that would be written.
    pub bytes: u64,
    /// Directories that would be created.
    pub directories: u32,
}

/// An offer that has arrived but has not been answered yet.
#[derive(Debug)]
pub struct PendingOffer<'a, R, W> {
    channel: &'a mut Channel<R, W>,
    offer: Offer,
    plan: Plan,
    options: ReceiveOptions,
    chunk_limit: usize,
}

/// Negotiate, then read the offer without acting on it.
pub async fn begin<'a, R, W>(
    channel: &'a mut Channel<R, W>,
    options: ReceiveOptions,
) -> Result<PendingOffer<'a, R, W>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let capabilities = negotiate(channel).await?;
    let chunk_limit = channel.max_data_len().max(capabilities.chunk_size as usize);

    let offer = match channel.recv_control().await? {
        ControlMessage::Offer(offer) => offer,
        ControlMessage::Cancel { reason } => return Err(cancelled_by_peer(reason)),
        ControlMessage::Failure { code, message } => return Err(peer_failure(code, message)),
        other => return Err(unexpected(other.name(), "an offer")),
    };

    if let Err(e) = inspect(&offer) {
        channel
            .send_failure(FailureCode::REFUSED, e.to_string())
            .await;
        return Err(e);
    }

    let plan = match plan_for(&offer, &options).await {
        Ok(plan) => plan,
        Err(e) => {
            channel
                .send_control(&ControlMessage::Decline {
                    reason: Some(e.to_string()),
                })
                .await
                .ok();
            return Err(e);
        }
    };

    Ok(PendingOffer {
        channel,
        offer,
        plan,
        options,
        chunk_limit,
    })
}

impl<R, W> PendingOffer<'_, R, W>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    /// What the sender is offering.
    pub fn offer(&self) -> &Offer {
        &self.offer
    }

    /// What accepting would do.
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Turn the offer down.
    pub async fn decline(self, reason: Option<String>) -> Result<()> {
        self.channel
            .send_control(&ControlMessage::Decline { reason })
            .await
    }

    /// Accept, and write everything to disk.
    pub async fn accept(
        self,
        sink: &dyn ProgressSink,
        cancel: &CancellationToken,
    ) -> Result<ReceiveReport> {
        let PendingOffer {
            channel,
            offer,
            plan,
            options,
            chunk_limit,
        } = self;

        match run(channel, &offer, &plan, &options, chunk_limit, sink, cancel).await {
            Ok(report) => Ok(report),
            Err(e) => {
                // Tell the sender why, so it reports something better than a
                // broken pipe, then give up.
                if !e.is_cancelled() {
                    channel
                        .send_failure(failure_code_for(&e), e.to_string())
                        .await;
                } else {
                    let _ = channel
                        .send_control(&ControlMessage::Cancel { reason: None })
                        .await;
                }
                Err(e)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run<R, W>(
    channel: &mut Channel<R, W>,
    offer: &Offer,
    plan: &Plan,
    options: &ReceiveOptions,
    chunk_limit: usize,
    sink: &dyn ProgressSink,
    cancel: &CancellationToken,
) -> Result<ReceiveReport>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    channel
        .send_control(&ControlMessage::Accept(crate::protocol::message::Accept {
            wanted: plan.wanted.clone(),
        }))
        .await?;

    sink.event(Event::Started {
        files: plan.files,
        bytes: plan.bytes,
    });
    for (index, reason) in &plan.skipped {
        sink.event(Event::FileSkipped {
            index: *index,
            path: offer.entries[*index as usize].path.clone(),
            reason: reason.clone(),
        });
    }

    // Directories first, so an empty one exists even if nothing else arrives.
    let mut report = ReceiveReport {
        files: 0,
        bytes: 0,
        skipped: plan.skipped.len() as u32,
        directories: 0,
        output_dir: options.output_dir.clone(),
    };
    for index in &plan.wanted {
        let entry = &offer.entries[*index as usize];
        if entry.kind.is_directory() {
            writer::create_directory(&options.output_dir, &entry.path).await?;
            report.directories += 1;
            sink.event(Event::DirectoryCreated {
                path: entry.path.clone(),
            });
        }
    }

    let mut current: Option<Active> = None;

    loop {
        cancel_check(cancel)?;

        let control = match channel.recv_required().await? {
            Incoming::Data { offset, bytes } => {
                let Some(active) = current.as_mut() else {
                    return Err(unexpected("data", "a file to have been started"));
                };
                active.write(offset, bytes, chunk_limit).await?;
                sink.event(Event::Advanced {
                    bytes: bytes.len() as u64,
                });
                None
            }
            Incoming::Control(msg) => Some(msg),
        };

        let Some(message) = control else { continue };
        match message {
            ControlMessage::FileStart { index } => {
                if let Some(active) = current.take() {
                    active.writer.discard().await;
                    return Err(unexpected("file-start", "the current file to finish"));
                }
                let entry = entry_at(offer, index)?;
                if !entry.kind.is_file() {
                    return Err(TransferError::BadManifest(format!(
                        "{} is not a file but data was sent for it",
                        entry.path
                    ))
                    .into());
                }
                if !plan.wanted.contains(&index) {
                    return Err(TransferError::BadManifest(format!(
                        "{} was not accepted but was sent anyway",
                        entry.path
                    ))
                    .into());
                }

                let destination =
                    FileWriter::create(&options.output_dir, &entry.path, options.on_conflict)
                        .await?;
                let Destination::Ready(file) = destination else {
                    // The plan already excluded everything the policy skips, so
                    // reaching here means the disk changed under us.
                    return Err(TransferError::Exists(options.output_dir.join(&entry.path)).into());
                };

                sink.event(Event::FileStarted {
                    index,
                    path: entry.path.clone(),
                    size: entry.size,
                });
                current = Some(Active {
                    index,
                    limit: entry.size,
                    received: 0,
                    writer: *file,
                });
            }
            ControlMessage::FileEnd { index, hash, size } => {
                let Some(active) = current.take() else {
                    return Err(unexpected("file-end", "a file to have been started"));
                };
                if active.index != index {
                    active.writer.discard().await;
                    return Err(unexpected("file-end", "the file that was started"));
                }
                let entry = entry_at(offer, index)?;
                let path = active.finish(hash, size).await?;
                FileWriter::apply_mode(&path, entry.mode).await?;
                report.files += 1;
                report.bytes += size;
                sink.event(Event::FileFinished {
                    index,
                    path: entry.path.clone(),
                });
            }
            ControlMessage::Complete(_) => {
                if let Some(active) = current.take() {
                    active.writer.discard().await;
                    return Err(unexpected("complete", "the current file to finish"));
                }
                break;
            }
            ControlMessage::Cancel { reason } => {
                if let Some(active) = current.take() {
                    active.writer.discard().await;
                }
                return Err(cancelled_by_peer(reason));
            }
            ControlMessage::Failure { code, message } => {
                if let Some(active) = current.take() {
                    active.writer.discard().await;
                }
                return Err(peer_failure(code, message));
            }
            ControlMessage::Keepalive => {}
            other => return Err(unexpected(other.name(), "file data or completion")),
        }
    }

    channel
        .send_control(&ControlMessage::Complete(Summary {
            files: report.files,
            bytes: report.bytes,
            skipped: report.skipped,
        }))
        .await?;

    sink.event(Event::Finished {
        files: report.files,
        bytes: report.bytes,
        skipped: report.skipped,
    });
    Ok(report)
}

/// A file currently being written.
#[derive(Debug)]
struct Active {
    index: u32,
    /// Hard cap from the manifest: a sender must not exceed what the receiver
    /// agreed to store.
    limit: u64,
    received: u64,
    writer: FileWriter,
}

impl Active {
    async fn write(&mut self, offset: u64, bytes: &[u8], chunk_limit: usize) -> Result<()> {
        if bytes.len() > chunk_limit {
            return Err(TransferError::BadManifest(format!(
                "a {} byte chunk exceeds the negotiated limit of {chunk_limit}",
                bytes.len()
            ))
            .into());
        }
        if offset != self.received {
            return Err(TransferError::BadManifest(format!(
                "data arrived for offset {offset} but {} was expected",
                self.received
            ))
            .into());
        }
        let after = self.received.saturating_add(bytes.len() as u64);
        if after > self.limit {
            return Err(TransferError::SizeMismatch {
                path: self.writer.final_path().display().to_string(),
                expected: self.limit,
                actual: after,
            }
            .into());
        }
        self.writer.write(bytes).await?;
        self.received = after;
        Ok(())
    }

    async fn finish(self, hash: Hash32, size: u64) -> Result<PathBuf> {
        if size != self.received {
            let error = TransferError::SizeMismatch {
                path: self.writer.final_path().display().to_string(),
                expected: size,
                actual: self.received,
            };
            self.writer.discard().await;
            return Err(error.into());
        }
        self.writer.commit(hash, size).await
    }
}

async fn negotiate<R, W>(channel: &mut Channel<R, W>) -> Result<Capabilities>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let theirs = match channel.recv_control().await? {
        ControlMessage::Capabilities(caps) => caps,
        ControlMessage::Failure { code, message } => return Err(peer_failure(code, message)),
        other => return Err(unexpected(other.name(), "capabilities")),
    };
    let ours = protocol::local_capabilities();
    channel
        .send_control(&ControlMessage::Capabilities(ours.clone()))
        .await?;
    let agreed = ours.intersect(&theirs);
    channel.apply_capabilities(&agreed);
    Ok(agreed)
}

/// Check an offer before believing anything in it.
fn inspect(offer: &Offer) -> Result<()> {
    if offer.entries.is_empty() {
        return Err(TransferError::BadManifest("the offer is empty".into()).into());
    }
    if offer.entries.len() > MAX_ENTRIES {
        return Err(TransferError::BadManifest(format!(
            "the offer has {} items, more than the limit of {MAX_ENTRIES}",
            offer.entries.len()
        ))
        .into());
    }

    let mut seen = HashSet::with_capacity(offer.entries.len());
    for entry in &offer.entries {
        // Refuse rather than repair: see `files::safe_path`.
        safe_path::validate(&entry.path)?;
        if !seen.insert(entry.path.as_str()) {
            return Err(TransferError::BadManifest(format!(
                "`{}` appears twice in the offer",
                entry.path
            ))
            .into());
        }
    }
    Ok(())
}

/// Work out what would happen, without writing anything.
async fn plan_for(offer: &Offer, options: &ReceiveOptions) -> Result<Plan> {
    let mut plan = Plan::default();

    for (index, entry) in offer.entries.iter().enumerate() {
        let index = index as u32;
        if entry.kind.is_unknown() {
            plan.skipped.push((
                index,
                "this build does not understand what kind of item this is".into(),
            ));
            continue;
        }
        if entry.kind.is_directory() {
            plan.wanted.push(index);
            plan.directories += 1;
            continue;
        }

        let target = safe_path::resolve(&options.output_dir, &entry.path)?;
        let exists = tokio::fs::symlink_metadata(&target).await.is_ok();
        match (exists, options.on_conflict) {
            (true, ConflictPolicy::Skip) => {
                plan.skipped.push((index, "already exists".into()));
            }
            (true, ConflictPolicy::Fail) => {
                return Err(TransferError::Exists(target).into());
            }
            _ => {
                plan.wanted.push(index);
                plan.files += 1;
                plan.bytes += entry.size;
            }
        }
    }
    Ok(plan)
}

fn entry_at(offer: &Offer, index: u32) -> Result<&Entry> {
    offer.entries.get(index as usize).ok_or_else(|| {
        TransferError::BadManifest(format!(
            "the sender referred to item {index}, which does not exist"
        ))
        .into()
    })
}

fn failure_code_for(error: &Error) -> FailureCode {
    match error {
        Error::Transfer(TransferError::Integrity { .. }) => FailureCode::INTEGRITY,
        Error::Transfer(TransferError::UnsafePath(_)) => FailureCode::REFUSED,
        Error::Transfer(TransferError::Exists(_)) => FailureCode::REFUSED,
        Error::Transfer(TransferError::BadManifest(_)) => FailureCode::BAD_MESSAGE,
        Error::Transfer(TransferError::SizeMismatch { .. }) => FailureCode::INTEGRITY,
        Error::Io { .. } => FailureCode::IO,
        Error::Protocol(_) => FailureCode::BAD_MESSAGE,
        _ => FailureCode::INTERNAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::{Entry, EntryKind};

    fn offer_of(entries: Vec<Entry>) -> Offer {
        let total = entries.iter().map(|e| e.size).sum();
        Offer {
            entries,
            total_bytes: total,
            name_hint: None,
        }
    }

    fn options(dir: &std::path::Path, policy: ConflictPolicy) -> ReceiveOptions {
        ReceiveOptions {
            output_dir: dir.to_path_buf(),
            on_conflict: policy,
        }
    }

    #[test]
    fn a_reasonable_offer_passes_inspection() {
        assert!(inspect(&offer_of(vec![
            Entry::directory("dir"),
            Entry::file("dir/a.txt", 10),
        ]))
        .is_ok());
    }

    #[test]
    fn an_empty_offer_is_refused() {
        let err = inspect(&offer_of(vec![])).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn a_traversing_offer_is_refused_before_anything_is_planned() {
        for path in ["../escape", "/etc/passwd", "a/../../b", "CON"] {
            let err = inspect(&offer_of(vec![Entry::file(path, 1)])).unwrap_err();
            assert!(
                matches!(err, Error::Transfer(TransferError::UnsafePath(_))),
                "{path}: {err}"
            );
        }
    }

    #[test]
    fn a_duplicated_path_is_refused() {
        let err = inspect(&offer_of(vec![
            Entry::file("a.txt", 1),
            Entry::file("a.txt", 2),
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("appears twice"), "{err}");
    }

    #[tokio::test]
    async fn a_plan_wants_everything_when_nothing_is_in_the_way() {
        let dir = tempfile::tempdir().unwrap();
        let offer = offer_of(vec![
            Entry::directory("d"),
            Entry::file("d/a.txt", 10),
            Entry::file("d/b.txt", 20),
        ]);
        let plan = plan_for(&offer, &options(dir.path(), ConflictPolicy::Rename))
            .await
            .unwrap();
        assert_eq!(plan.wanted, vec![0, 1, 2]);
        assert_eq!(plan.files, 2);
        assert_eq!(plan.directories, 1);
        assert_eq!(plan.bytes, 30);
        assert!(plan.skipped.is_empty());
    }

    #[tokio::test]
    async fn skip_policy_leaves_existing_files_out_of_the_request() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("a.txt"), b"mine")
            .await
            .unwrap();
        let offer = offer_of(vec![Entry::file("a.txt", 10), Entry::file("b.txt", 20)]);

        let plan = plan_for(&offer, &options(dir.path(), ConflictPolicy::Skip))
            .await
            .unwrap();
        assert_eq!(plan.wanted, vec![1], "the existing file is not requested");
        assert_eq!(plan.bytes, 20, "and its bytes never cross the network");
        assert_eq!(plan.skipped.len(), 1);
        assert!(plan.skipped[0].1.contains("already exists"));
    }

    #[tokio::test]
    async fn fail_policy_refuses_the_whole_offer() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("a.txt"), b"mine")
            .await
            .unwrap();
        let offer = offer_of(vec![Entry::file("a.txt", 10)]);
        let err = plan_for(&offer, &options(dir.path(), ConflictPolicy::Fail))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Transfer(TransferError::Exists(_))),
            "{err}"
        );
    }

    #[tokio::test]
    async fn unknown_entry_kinds_are_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let offer = offer_of(vec![
            Entry {
                kind: EntryKind(200),
                ..Entry::file("mystery", 5)
            },
            Entry::file("normal.txt", 5),
        ]);
        let plan = plan_for(&offer, &options(dir.path(), ConflictPolicy::Rename))
            .await
            .unwrap();
        assert_eq!(plan.wanted, vec![1]);
        assert_eq!(plan.skipped.len(), 1);
    }

    #[tokio::test]
    async fn a_file_may_not_exceed_the_size_it_was_offered_at() {
        let dir = tempfile::tempdir().unwrap();
        let Destination::Ready(file) =
            FileWriter::create(dir.path(), "a.bin", ConflictPolicy::Rename)
                .await
                .unwrap()
        else {
            unreachable!()
        };
        let mut active = Active {
            index: 0,
            limit: 10,
            received: 0,
            writer: *file,
        };

        active.write(0, &[0u8; 6], 1024).await.unwrap();
        let err = active.write(6, &[0u8; 6], 1024).await.unwrap_err();
        assert!(
            matches!(err, Error::Transfer(TransferError::SizeMismatch { .. })),
            "{err}"
        );
        active.writer.discard().await;
    }

    #[tokio::test]
    async fn data_must_arrive_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let Destination::Ready(file) =
            FileWriter::create(dir.path(), "a.bin", ConflictPolicy::Rename)
                .await
                .unwrap()
        else {
            unreachable!()
        };
        let mut active = Active {
            index: 0,
            limit: 100,
            received: 0,
            writer: *file,
        };
        let err = active.write(50, &[0u8; 4], 1024).await.unwrap_err();
        assert!(err.to_string().contains("offset 50"), "{err}");
        active.writer.discard().await;
    }

    #[tokio::test]
    async fn an_oversized_chunk_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let Destination::Ready(file) =
            FileWriter::create(dir.path(), "a.bin", ConflictPolicy::Rename)
                .await
                .unwrap()
        else {
            unreachable!()
        };
        let mut active = Active {
            index: 0,
            limit: 1 << 30,
            received: 0,
            writer: *file,
        };
        let err = active.write(0, &[0u8; 2048], 1024).await.unwrap_err();
        assert!(err.to_string().contains("negotiated limit"), "{err}");
        active.writer.discard().await;
    }

    #[test]
    fn failures_are_reported_with_a_useful_code() {
        assert_eq!(
            failure_code_for(
                &TransferError::Integrity {
                    path: "a".into(),
                    expected: "b".into(),
                    actual: "c".into()
                }
                .into()
            ),
            FailureCode::INTEGRITY
        );
        assert_eq!(
            failure_code_for(&TransferError::UnsafePath("x".into()).into()),
            FailureCode::REFUSED
        );
        assert_eq!(
            failure_code_for(&Error::io("x", std::io::Error::other("y"))),
            FailureCode::IO
        );
    }
}
