//! Writing received files safely.
//!
//! Three properties matter here, and all three are about what happens when
//! things go wrong:
//!
//! * **Nothing appears half-written.** Data goes to a `.rusp-part` file beside
//!   the destination, is flushed, and only then renamed into place. A transfer
//!   that dies leaves the part file, never a truncated `holiday.mp4`.
//! * **Nothing is written through a symlink.** Every directory on the way is
//!   created and checked, so a peer cannot get a file written somewhere else
//!   by getting a link there first.
//! * **Nothing existing is destroyed by accident.** The conflict policy is
//!   applied before a byte is written, and `rename` picks a free name rather
//!   than replacing anything.

use std::path::{Path, PathBuf};

use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;

use crate::code::fill_random;
use crate::config::ConflictPolicy;
use crate::error::{Error, IoContext, Result, TransferError};
use crate::files::safe_path;
use crate::protocol::message::Hash32;

/// Suffix on the temporary file a transfer writes into.
pub const PART_SUFFIX: &str = "rusp-part";

/// What happened when a destination was opened.
#[derive(Debug)]
pub enum Destination {
    /// Ready to receive bytes.
    Ready(Box<FileWriter>),
    /// The file exists and the policy says leave it alone.
    Skipped(PathBuf),
}

/// A file being received.
#[derive(Debug)]
pub struct FileWriter {
    final_path: PathBuf,
    part_path: PathBuf,
    file: File,
    hasher: blake3::Hasher,
    written: u64,
}

impl FileWriter {
    /// Open a destination for `relative` under `root`, applying `policy`.
    ///
    /// Returns [`Destination::Skipped`] when the file exists and the policy
    /// says to keep it, and an error when the policy says to refuse.
    pub async fn create(
        root: &Path,
        relative: &str,
        policy: ConflictPolicy,
    ) -> Result<Destination> {
        let target = safe_path::resolve(root, relative)?;
        let parent = target
            .parent()
            .ok_or_else(|| TransferError::UnsafePath(relative.to_owned()))?;
        create_directory_chain(root, parent).await?;

        let final_path = match resolve_conflict(&target, policy).await? {
            Some(path) => path,
            None => return Ok(Destination::Skipped(target)),
        };

        let part_path = part_path_for(&final_path)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part_path)
            .await
            .path_ctx("create", &part_path)?;

        Ok(Destination::Ready(Box::new(FileWriter {
            final_path,
            part_path,
            file,
            hasher: blake3::Hasher::new(),
            written: 0,
        })))
    }

    /// Append a chunk, hashing it on the way past.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.file
            .write_all(bytes)
            .await
            .path_ctx("write", &self.part_path)?;
        self.hasher.update(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }

    /// Bytes written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// The path this file will have once committed.
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    /// Hash of everything written so far.
    pub fn hash(&self) -> Hash32 {
        Hash32::from_bytes(*self.hasher.finalize().as_bytes())
    }

    /// Verify the hash and move the file into place.
    ///
    /// The part file is removed on any failure, so a mismatch never leaves
    /// corrupt data behind under a name that looks finished.
    pub async fn commit(mut self, expected: Hash32, expected_size: u64) -> Result<PathBuf> {
        if self.written != expected_size {
            let error = TransferError::SizeMismatch {
                path: display_name(&self.final_path),
                expected: expected_size,
                actual: self.written,
            };
            self.discard().await;
            return Err(error.into());
        }

        let actual = self.hash();
        if actual != expected {
            let error = TransferError::Integrity {
                path: display_name(&self.final_path),
                expected: expected.short(),
                actual: actual.short(),
            };
            self.discard().await;
            return Err(error.into());
        }

        // Flush before renaming: a rename that beats its own data to disk
        // would leave a file that looks complete and is not.
        let flushed = match self.file.flush().await {
            Ok(()) => self.file.sync_all().await,
            Err(e) => Err(e),
        };
        if let Err(e) = flushed {
            let part_path = self.part_path.clone();
            self.discard().await;
            return Err(Error::path("finish writing", &part_path, e));
        }
        drop(self.file);

        tokio::fs::rename(&self.part_path, &self.final_path)
            .await
            .path_ctx("move into place", &self.final_path)?;
        Ok(self.final_path)
    }

    /// Throw the partial file away.
    pub async fn discard(self) {
        drop(self.file);
        let _ = tokio::fs::remove_file(&self.part_path).await;
    }

    /// Apply the sender's permission bits, honouring only the executable bit.
    ///
    /// A peer should not be able to hand us a setuid file or something
    /// world-writable, so everything except "is this a program" is ignored and
    /// the process umask decides the rest.
    #[cfg(unix)]
    pub async fn apply_mode(path: &Path, mode: Option<u32>) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let Some(mode) = mode else { return Ok(()) };
        if mode & 0o111 == 0 {
            return Ok(());
        }
        let metadata = tokio::fs::metadata(path).await.path_ctx("read", path)?;
        let current = metadata.permissions().mode();
        let updated = current | ((current & 0o444) >> 2);
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(updated))
            .await
            .path_ctx("set permissions on", path)
    }

    /// Permissions are not carried on this platform.
    #[cfg(not(unix))]
    pub async fn apply_mode(_path: &Path, _mode: Option<u32>) -> Result<()> {
        Ok(())
    }
}

/// Create a directory from a manifest entry, with the same symlink checks.
pub async fn create_directory(root: &Path, relative: &str) -> Result<PathBuf> {
    let target = safe_path::resolve(root, relative)?;
    create_directory_chain(root, &target).await?;
    Ok(target)
}

/// Create every directory between `root` and `target`, refusing to walk
/// through anything that is not a real directory.
///
/// `create_dir_all` would happily follow a symlink that a local attacker (or a
/// previous transfer) left in the destination, which is exactly the case this
/// exists to stop.
async fn create_directory_chain(root: &Path, target: &Path) -> Result<()> {
    let relative = target.strip_prefix(root).map_err(|_| {
        TransferError::UnsafePath(format!("{} is outside the destination", target.display()))
    })?;

    // The destination root is the user's own choice, so it is created the
    // ordinary way — including through a symlink they put there themselves.
    // Everything below it comes from the peer and gets the strict treatment.
    ensure_root(root).await?;

    let mut path = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(TransferError::UnsafePath(format!(
                "{} is not a plain relative path",
                relative.display()
            ))
            .into());
        };
        path.push(name);
        ensure_directory(&path).await?;
    }
    Ok(())
}

/// Make sure the destination directory itself exists.
async fn ensure_root(root: &Path) -> Result<()> {
    match tokio::fs::metadata(root).await {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(TransferError::UnsafePath(format!(
            "{} exists and is not a directory",
            root.display()
        ))
        .into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => tokio::fs::create_dir_all(root)
            .await
            .path_ctx("create destination directory", root),
        Err(e) => Err(Error::path("inspect", root, e)),
    }
}

async fn ensure_directory(path: &Path) -> Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(metadata) if metadata.is_symlink() => Err(TransferError::UnsafePath(format!(
            "{} is a symbolic link; refusing to write through it",
            path.display()
        ))
        .into()),
        Ok(_) => Err(TransferError::UnsafePath(format!(
            "{} exists and is not a directory",
            path.display()
        ))
        .into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match tokio::fs::create_dir(path).await {
                Ok(()) => Ok(()),
                // Another task in this transfer got there first.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(Error::path("create", path, e)),
            }
        }
        Err(e) => Err(Error::path("inspect", path, e)),
    }
}

/// Decide what path to write, given what is already there.
///
/// `Ok(None)` means skip this file.
async fn resolve_conflict(target: &Path, policy: ConflictPolicy) -> Result<Option<PathBuf>> {
    // `symlink_metadata` rather than `metadata`: a dangling symlink still
    // occupies the name, and following it is the thing we are guarding against.
    if tokio::fs::symlink_metadata(target).await.is_err() {
        return Ok(Some(target.to_path_buf()));
    }

    match policy {
        ConflictPolicy::Skip => Ok(None),
        ConflictPolicy::Fail => Err(TransferError::Exists(target.to_path_buf()).into()),
        ConflictPolicy::Overwrite => {
            // Remove first so that overwriting a symlink replaces the link
            // rather than writing through it, and so a directory in the way
            // produces a clear error instead of a confusing rename failure.
            match tokio::fs::symlink_metadata(target).await {
                Ok(metadata) if metadata.is_dir() => {
                    return Err(TransferError::UnsafePath(format!(
                        "{} is a directory",
                        target.display()
                    ))
                    .into())
                }
                _ => {
                    tokio::fs::remove_file(target)
                        .await
                        .path_ctx("replace", target)?;
                }
            }
            Ok(Some(target.to_path_buf()))
        }
        ConflictPolicy::Rename => Ok(Some(free_name(target).await?)),
    }
}

/// Find `name (1).ext`, `name (2).ext`, … until one is free.
async fn free_name(target: &Path) -> Result<PathBuf> {
    let parent = target.parent().unwrap_or(Path::new("."));
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| TransferError::UnsafePath(target.display().to_string()))?;
    let (stem, extension) = match Path::new(name).extension().and_then(|e| e.to_str()) {
        Some(ext) if !name.starts_with('.') => (&name[..name.len() - ext.len() - 1], Some(ext)),
        _ => (name, None),
    };

    for n in 1..10_000 {
        let candidate = parent.join(match extension {
            Some(ext) => format!("{stem} ({n}).{ext}"),
            None => format!("{stem} ({n})"),
        });
        if tokio::fs::symlink_metadata(&candidate).await.is_err() {
            return Ok(candidate);
        }
    }
    Err(TransferError::Exists(target.to_path_buf()).into())
}

/// `name.<random>.rusp-part`, beside the destination so the final rename stays
/// on one filesystem and is therefore atomic.
fn part_path_for(final_path: &Path) -> Result<PathBuf> {
    let mut suffix = [0u8; 6];
    fill_random(&mut suffix).map_err(Error::Code)?;
    let name = final_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| TransferError::UnsafePath(final_path.display().to_string()))?;
    let parent = final_path.parent().unwrap_or(Path::new("."));
    Ok(parent.join(format!("{name}.{}.{PART_SUFFIX}", hex::encode(suffix))))
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn hash_of(bytes: &[u8]) -> Hash32 {
        Hash32::from_bytes(*blake3::hash(bytes).as_bytes())
    }

    async fn receive(
        root: &Path,
        relative: &str,
        contents: &[u8],
        policy: ConflictPolicy,
    ) -> Result<PathBuf> {
        let Destination::Ready(mut writer) = FileWriter::create(root, relative, policy).await?
        else {
            panic!("expected a writable destination");
        };
        writer.write(contents).await?;
        writer
            .commit(hash_of(contents), contents.len() as u64)
            .await
    }

    fn dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    #[tokio::test]
    async fn a_file_arrives_with_its_contents() {
        let root = dir();
        let path = receive(root.path(), "a.txt", b"hello", ConflictPolicy::Rename)
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"hello");
        assert_eq!(path, root.path().join("a.txt"));
    }

    #[tokio::test]
    async fn nested_directories_are_created() {
        let root = dir();
        let path = receive(root.path(), "a/b/c/deep.txt", b"x", ConflictPolicy::Rename)
            .await
            .unwrap();
        assert!(path.exists());
        assert!(root.path().join("a/b/c").is_dir());
    }

    #[tokio::test]
    async fn empty_files_work() {
        let root = dir();
        let path = receive(root.path(), "empty.txt", b"", ConflictPolicy::Rename)
            .await
            .unwrap();
        assert_eq!(tokio::fs::metadata(&path).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn nothing_is_left_behind_after_a_successful_transfer() {
        let root = dir();
        receive(root.path(), "a.txt", b"hello", ConflictPolicy::Rename)
            .await
            .unwrap();
        let mut entries = tokio::fs::read_dir(root.path()).await.unwrap();
        let mut names = Vec::new();
        while let Some(e) = entries.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(names, vec!["a.txt"], "no part files should survive");
    }

    #[tokio::test]
    async fn a_wrong_hash_fails_and_leaves_nothing() {
        let root = dir();
        let Destination::Ready(mut writer) =
            FileWriter::create(root.path(), "a.txt", ConflictPolicy::Rename)
                .await
                .unwrap()
        else {
            unreachable!()
        };
        writer.write(b"tampered").await.unwrap();
        let err = writer.commit(hash_of(b"original"), 8).await.unwrap_err();
        assert!(
            matches!(err, Error::Transfer(TransferError::Integrity { .. })),
            "{err}"
        );

        let mut entries = tokio::fs::read_dir(root.path()).await.unwrap();
        assert!(
            entries.next_entry().await.unwrap().is_none(),
            "a failed file must leave nothing behind"
        );
    }

    #[tokio::test]
    async fn a_wrong_size_fails_before_the_hash_is_even_considered() {
        let root = dir();
        let Destination::Ready(mut writer) =
            FileWriter::create(root.path(), "a.txt", ConflictPolicy::Rename)
                .await
                .unwrap()
        else {
            unreachable!()
        };
        writer.write(b"short").await.unwrap();
        let err = writer.commit(hash_of(b"short"), 99).await.unwrap_err();
        assert!(
            matches!(err, Error::Transfer(TransferError::SizeMismatch { .. })),
            "{err}"
        );
        assert!(!root.path().join("a.txt").exists());
    }

    #[tokio::test]
    async fn an_abandoned_transfer_leaves_no_partial_file() {
        let root = dir();
        let Destination::Ready(mut writer) =
            FileWriter::create(root.path(), "big.bin", ConflictPolicy::Rename)
                .await
                .unwrap()
        else {
            unreachable!()
        };
        writer.write(&[0u8; 1024]).await.unwrap();
        assert!(!root.path().join("big.bin").exists(), "nothing yet");
        writer.discard().await;

        let mut entries = tokio::fs::read_dir(root.path()).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn conflict_rename_keeps_both() {
        let root = dir();
        tokio::fs::write(root.path().join("a.txt"), b"original")
            .await
            .unwrap();

        let path = receive(root.path(), "a.txt", b"new", ConflictPolicy::Rename)
            .await
            .unwrap();
        assert_eq!(path, root.path().join("a (1).txt"));
        assert_eq!(
            tokio::fs::read(root.path().join("a.txt")).await.unwrap(),
            b"original"
        );

        // And again.
        let path = receive(root.path(), "a.txt", b"newer", ConflictPolicy::Rename)
            .await
            .unwrap();
        assert_eq!(path, root.path().join("a (2).txt"));
    }

    #[tokio::test]
    async fn conflict_rename_handles_names_without_an_extension() {
        let root = dir();
        tokio::fs::write(root.path().join("README"), b"x")
            .await
            .unwrap();
        let path = receive(root.path(), "README", b"y", ConflictPolicy::Rename)
            .await
            .unwrap();
        assert_eq!(path, root.path().join("README (1)"));
    }

    #[tokio::test]
    async fn conflict_overwrite_replaces() {
        let root = dir();
        tokio::fs::write(root.path().join("a.txt"), b"original")
            .await
            .unwrap();
        let path = receive(root.path(), "a.txt", b"new", ConflictPolicy::Overwrite)
            .await
            .unwrap();
        assert_eq!(path, root.path().join("a.txt"));
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"new");
    }

    #[tokio::test]
    async fn conflict_skip_leaves_the_original() {
        let root = dir();
        tokio::fs::write(root.path().join("a.txt"), b"original")
            .await
            .unwrap();
        let destination = FileWriter::create(root.path(), "a.txt", ConflictPolicy::Skip)
            .await
            .unwrap();
        assert!(matches!(destination, Destination::Skipped(_)));
        assert_eq!(
            tokio::fs::read(root.path().join("a.txt")).await.unwrap(),
            b"original"
        );
    }

    #[tokio::test]
    async fn conflict_fail_refuses() {
        let root = dir();
        tokio::fs::write(root.path().join("a.txt"), b"original")
            .await
            .unwrap();
        let err = FileWriter::create(root.path(), "a.txt", ConflictPolicy::Fail)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Transfer(TransferError::Exists(_))),
            "{err}"
        );
        assert!(err.hint().is_some());
    }

    #[tokio::test]
    async fn traversal_never_reaches_the_filesystem() {
        let root = dir();
        let outside = root.path().parent().unwrap().join("escaped.txt");
        let _ = tokio::fs::remove_file(&outside).await;

        for offered in ["../escaped.txt", "a/../../escaped.txt", "/tmp/escaped.txt"] {
            let err = FileWriter::create(root.path(), offered, ConflictPolicy::Overwrite)
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::Transfer(TransferError::UnsafePath(_))),
                "{offered}: {err}"
            );
        }
        assert!(!outside.exists(), "nothing may be written outside the root");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_directory_is_not_written_through() {
        let root = dir();
        let elsewhere = dir();
        // A link planted in the destination, as a local attacker might.
        std::os::unix::fs::symlink(elsewhere.path(), root.path().join("uploads")).unwrap();

        let err = FileWriter::create(
            root.path(),
            "uploads/payload.txt",
            ConflictPolicy::Overwrite,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, Error::Transfer(TransferError::UnsafePath(_))),
            "{err}"
        );
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(!elsewhere.path().join("payload.txt").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn overwriting_a_symlink_replaces_the_link_not_its_target() {
        let root = dir();
        let elsewhere = dir();
        let target = elsewhere.path().join("important.txt");
        tokio::fs::write(&target, b"do not touch").await.unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("a.txt")).unwrap();

        receive(root.path(), "a.txt", b"new", ConflictPolicy::Overwrite)
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read(&target).await.unwrap(),
            b"do not touch",
            "the link target must be untouched"
        );
        assert_eq!(
            tokio::fs::read(root.path().join("a.txt")).await.unwrap(),
            b"new"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_dangling_symlink_still_counts_as_occupied() {
        let root = dir();
        std::os::unix::fs::symlink("/nowhere/at/all", root.path().join("a.txt")).unwrap();
        let destination = FileWriter::create(root.path(), "a.txt", ConflictPolicy::Skip)
            .await
            .unwrap();
        assert!(matches!(destination, Destination::Skipped(_)));
    }

    #[tokio::test]
    async fn a_file_in_the_way_of_a_directory_is_reported_clearly() {
        let root = dir();
        tokio::fs::write(root.path().join("a"), b"i am a file")
            .await
            .unwrap();
        let err = FileWriter::create(root.path(), "a/b.txt", ConflictPolicy::Overwrite)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[tokio::test]
    async fn directories_from_the_manifest_are_created() {
        let root = dir();
        let path = create_directory(root.path(), "empty/nested").await.unwrap();
        assert!(path.is_dir());
        assert!(root.path().join("empty").is_dir());
    }

    #[tokio::test]
    async fn the_destination_directory_is_created_if_missing() {
        let root = dir();
        let nested = root.path().join("does/not/exist");
        let path = receive(&nested, "a.txt", b"x", ConflictPolicy::Rename)
            .await
            .unwrap();
        assert!(path.exists());
    }

    #[tokio::test]
    async fn part_files_are_unique_per_transfer() {
        let target = Path::new("/tmp/thing.bin");
        let a = part_path_for(target).unwrap();
        let b = part_path_for(target).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            a.parent(),
            target.parent(),
            "renames must stay on one filesystem"
        );
        assert!(a.to_string_lossy().ends_with(PART_SUFFIX));
        assert!(a.to_string_lossy().contains("thing.bin"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn only_the_executable_bit_is_honoured() {
        use std::os::unix::fs::PermissionsExt;
        let root = dir();
        let path = receive(
            root.path(),
            "run.sh",
            b"#!/bin/sh\n",
            ConflictPolicy::Rename,
        )
        .await
        .unwrap();

        // A hostile setuid, world-writable mode must not survive.
        FileWriter::apply_mode(&path, Some(0o104777)).await.unwrap();
        let mode = tokio::fs::metadata(&path)
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111, "executable bit should be set");
        assert_eq!(mode & 0o4000, 0, "setuid must never be set");
        assert_eq!(mode & 0o002, 0, "must not become world writable");

        // A non-executable file stays non-executable.
        let plain = receive(root.path(), "notes.txt", b"x", ConflictPolicy::Rename)
            .await
            .unwrap();
        FileWriter::apply_mode(&plain, Some(0o644)).await.unwrap();
        let mode = tokio::fs::metadata(&plain)
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0);
    }

    #[tokio::test]
    async fn a_large_file_streams_without_buffering_it_all() {
        let root = dir();
        let chunk = vec![0xABu8; 256 * 1024];
        let mut hasher = blake3::Hasher::new();

        let Destination::Ready(mut writer) =
            FileWriter::create(root.path(), "big.bin", ConflictPolicy::Rename)
                .await
                .unwrap()
        else {
            unreachable!()
        };
        for _ in 0..40 {
            writer.write(&chunk).await.unwrap();
            hasher.update(&chunk);
        }
        let total = 40 * chunk.len() as u64;
        assert_eq!(writer.written(), total);
        let path = writer
            .commit(Hash32::from_bytes(*hasher.finalize().as_bytes()), total)
            .await
            .unwrap();
        assert_eq!(tokio::fs::metadata(&path).await.unwrap().len(), total);
    }
}
