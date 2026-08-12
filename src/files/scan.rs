//! Turning the paths on the command line into a manifest.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::error::{Error, IoContext, Result, TransferError};
use crate::files::safe_path;
use crate::protocol::message::{Entry, EntryKind, MAX_ENTRIES};

/// How to walk the source paths.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanOptions {
    /// Follow symbolic links and send what they point at, instead of skipping
    /// them. Off by default: following links can pull in files from outside
    /// the directory the user named, which is rarely what they meant.
    pub follow_symlinks: bool,
}

/// One manifest entry together with the local file it came from.
#[derive(Debug, Clone)]
pub struct Source {
    /// What goes in the manifest.
    pub entry: Entry,
    /// Where to read it from. `None` for directories.
    pub path: Option<PathBuf>,
}

/// The result of walking the command line.
#[derive(Debug, Default)]
pub struct Scan {
    /// Entries in the order they will be sent: a directory always appears
    /// before anything inside it.
    pub sources: Vec<Source>,
    /// Total bytes across all files.
    pub total_bytes: u64,
    /// Things that were deliberately left out, with the reason.
    pub skipped: Vec<String>,
    /// A short name for what is being sent, for display only.
    pub name_hint: Option<String>,
}

impl Scan {
    /// The manifest entries.
    pub fn entries(&self) -> Vec<Entry> {
        self.sources.iter().map(|s| s.entry.clone()).collect()
    }

    /// Number of regular files.
    pub fn file_count(&self) -> usize {
        self.sources
            .iter()
            .filter(|s| s.entry.kind.is_file())
            .count()
    }

    /// Number of directories.
    pub fn directory_count(&self) -> usize {
        self.sources
            .iter()
            .filter(|s| s.entry.kind.is_directory())
            .count()
    }
}

/// Walk `paths` and build a manifest.
pub fn scan(paths: &[PathBuf], options: ScanOptions) -> Result<Scan> {
    if paths.is_empty() {
        return Err(TransferError::Empty.into());
    }

    let mut scan = Scan::default();
    let mut used_names = HashSet::new();

    for path in paths {
        let metadata = std::fs::symlink_metadata(path).path_ctx("read", path)?;

        if metadata.is_symlink() && !options.follow_symlinks {
            scan.skipped.push(format!(
                "{}: symbolic link (use --follow-symlinks to send what it points at)",
                path.display()
            ));
            continue;
        }

        // Resolve through the link only when the user asked for it.
        let metadata = if metadata.is_symlink() {
            std::fs::metadata(path).path_ctx("read", path)?
        } else {
            metadata
        };

        let top_name = top_level_name(path)?;
        let top_name = disambiguate(&top_name, &mut used_names);

        if metadata.is_dir() {
            add_directory(&mut scan, path, &top_name, options)?;
        } else if metadata.is_file() {
            scan.sources.push(Source {
                entry: file_entry(top_name.clone(), &metadata),
                path: Some(path.clone()),
            });
            scan.total_bytes += metadata.len();
        } else {
            scan.skipped.push(format!(
                "{}: not a regular file or directory",
                path.display()
            ));
        }
    }

    if scan.sources.is_empty() {
        return Err(TransferError::Empty.into());
    }
    if scan.sources.len() > MAX_ENTRIES {
        return Err(TransferError::BadManifest(format!(
            "{} items is more than one transfer can carry (the limit is {MAX_ENTRIES})",
            scan.sources.len()
        ))
        .into());
    }

    scan.name_hint = name_hint(&scan, paths);
    Ok(scan)
}

fn add_directory(scan: &mut Scan, root: &Path, top_name: &str, options: ScanOptions) -> Result<()> {
    // The directory itself, so an empty one still arrives.
    scan.sources.push(Source {
        entry: Entry::directory(top_name.to_owned()),
        path: None,
    });

    let walk = WalkDir::new(root)
        .follow_links(options.follow_symlinks)
        .sort_by_file_name();

    for item in walk {
        let item = match item {
            Ok(item) => item,
            Err(e) => {
                // One unreadable subdirectory should not lose the rest of the
                // tree, but the user must be told it was left out.
                scan.skipped.push(describe_walk_error(&e));
                continue;
            }
        };
        if item.depth() == 0 {
            continue;
        }

        let relative = item
            .path()
            .strip_prefix(root)
            .map_err(|_| TransferError::UnsafePath(item.path().display().to_string()))?;
        let manifest_path = format!("{top_name}/{}", safe_path::to_manifest_path(relative)?);
        // Anything we are about to offer must be something a receiver will
        // accept, so it is checked here rather than surprising them later.
        safe_path::validate(&manifest_path)?;

        let file_type = item.file_type();
        if file_type.is_symlink() {
            scan.skipped.push(format!(
                "{}: symbolic link (use --follow-symlinks to send what it points at)",
                item.path().display()
            ));
        } else if file_type.is_dir() {
            scan.sources.push(Source {
                entry: Entry::directory(manifest_path),
                path: None,
            });
        } else if file_type.is_file() {
            let metadata = item
                .metadata()
                .map_err(|e| walk_io_error(&e, item.path()))?;
            scan.sources.push(Source {
                entry: file_entry(manifest_path, &metadata),
                path: Some(item.path().to_path_buf()),
            });
            scan.total_bytes += metadata.len();
        } else {
            scan.skipped.push(format!(
                "{}: not a regular file or directory",
                item.path().display()
            ));
        }

        if scan.sources.len() > MAX_ENTRIES {
            return Err(TransferError::BadManifest(format!(
                "more than {MAX_ENTRIES} items under {}",
                root.display()
            ))
            .into());
        }
    }
    Ok(())
}

fn file_entry(path: String, metadata: &std::fs::Metadata) -> Entry {
    Entry {
        path,
        kind: EntryKind::FILE,
        size: metadata.len(),
        mode: unix_mode(metadata),
        mtime: modified_seconds(metadata),
    }
}

#[cfg(unix)]
fn unix_mode(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode())
}

#[cfg(not(unix))]
fn unix_mode(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

fn modified_seconds(metadata: &std::fs::Metadata) -> Option<i64> {
    let modified = metadata.modified().ok()?;
    match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).ok(),
        // Files older than 1970 exist; represent them rather than dropping the
        // timestamp entirely.
        Err(before) => i64::try_from(before.duration().as_secs()).ok().map(|s| -s),
    }
}

/// The name a top-level argument will appear under on the receiving side.
fn top_level_name(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        // `.` and `..` and bare `/` have no usable file name of their own.
        .or_else(|| {
            std::fs::canonicalize(path)
                .ok()
                .and_then(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_owned))
        })
        .ok_or_else(|| {
            Error::from(TransferError::BadManifest(format!(
                "cannot work out a name to send {} under",
                path.display()
            )))
        })?;

    // The name has to survive the receiver's checks; if it will not, say so
    // now, while the user can still rename the file.
    safe_path::validate(&name)?;
    Ok(name)
}

/// Give a second `photo.jpg` from a different directory its own name.
fn disambiguate(name: &str, used: &mut HashSet<String>) -> String {
    if used.insert(name.to_owned()) {
        return name.to_owned();
    }
    let (stem, extension) = split_extension(name);
    for n in 2..1000 {
        let candidate = match extension {
            Some(ext) => format!("{stem} ({n}).{ext}"),
            None => format!("{stem} ({n})"),
        };
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    // Practically unreachable; a distinct name is still better than a clash.
    let fallback = format!("{name}.{}", used.len());
    used.insert(fallback.clone());
    fallback
}

/// Split off a trailing extension, keeping multi-dot names such as
/// `archive.tar.gz` intact where it matters.
fn split_extension(name: &str) -> (&str, Option<&str>) {
    match Path::new(name).extension().and_then(|e| e.to_str()) {
        // A leading-dot name such as `.gitignore` is all stem.
        Some(ext) if !name.starts_with('.') => (&name[..name.len() - ext.len() - 1], Some(ext)),
        _ => (name, None),
    }
}

fn name_hint(scan: &Scan, paths: &[PathBuf]) -> Option<String> {
    if paths.len() == 1 {
        scan.sources.first().map(|s| s.entry.path.clone())
    } else {
        None
    }
}

fn describe_walk_error(error: &walkdir::Error) -> String {
    match error.path() {
        Some(path) => format!("{}: {}", path.display(), io_reason(error)),
        None => format!("could not read a directory: {}", io_reason(error)),
    }
}

fn io_reason(error: &walkdir::Error) -> String {
    match error.io_error() {
        Some(io) => io.to_string(),
        None => "symbolic link loop".to_string(),
    }
}

fn walk_io_error(error: &walkdir::Error, path: &Path) -> Error {
    Error::path(
        "read",
        path,
        error
            .io_error()
            .map(|e| std::io::Error::new(e.kind(), e.to_string()))
            .unwrap_or_else(|| std::io::Error::other("symbolic link loop")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn paths_of(scan: &Scan) -> Vec<String> {
        scan.sources.iter().map(|s| s.entry.path.clone()).collect()
    }

    #[test]
    fn a_single_file_is_sent_under_its_own_name() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("report.pdf");
        write(&file, "hello");

        let scan = scan(std::slice::from_ref(&file), ScanOptions::default()).unwrap();
        assert_eq!(paths_of(&scan), vec!["report.pdf"]);
        assert_eq!(scan.total_bytes, 5);
        assert_eq!(scan.file_count(), 1);
        assert_eq!(scan.sources[0].path.as_ref().unwrap(), &file);
        assert_eq!(scan.name_hint.as_deref(), Some("report.pdf"));
    }

    #[test]
    fn several_files_keep_command_line_order() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        write(&a, "aa");
        write(&b, "bbb");

        let scan = scan(&[a, b], ScanOptions::default()).unwrap();
        assert_eq!(paths_of(&scan), vec!["a.txt", "b.txt"]);
        assert_eq!(scan.total_bytes, 5);
        assert_eq!(scan.name_hint, None);
    }

    #[test]
    fn directories_are_walked_with_parents_before_children() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("photos");
        write(&root.join("one.jpg"), "1");
        write(&root.join("nested/two.jpg"), "22");
        write(&root.join("nested/deeper/three.jpg"), "333");

        let scan = scan(&[root], ScanOptions::default()).unwrap();
        let paths = paths_of(&scan);
        assert_eq!(
            paths,
            vec![
                "photos",
                "photos/nested",
                "photos/nested/deeper",
                "photos/nested/deeper/three.jpg",
                "photos/nested/two.jpg",
                "photos/one.jpg",
            ]
        );
        assert_eq!(scan.total_bytes, 6);
        assert_eq!(scan.file_count(), 3);
        assert_eq!(scan.directory_count(), 3);

        // Every directory appears before anything inside it.
        for (i, path) in paths.iter().enumerate() {
            if let Some((parent, _)) = path.rsplit_once('/') {
                let parent_index = paths
                    .iter()
                    .position(|p| p == parent)
                    .expect("parent listed");
                assert!(parent_index < i, "{parent} must come before {path}");
            }
        }
    }

    #[test]
    fn an_empty_directory_still_appears() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        fs::create_dir_all(empty.join("also-empty")).unwrap();

        let scan = scan(&[empty], ScanOptions::default()).unwrap();
        assert_eq!(paths_of(&scan), vec!["empty", "empty/also-empty"]);
        assert_eq!(scan.file_count(), 0);
        assert_eq!(scan.total_bytes, 0);
    }

    #[test]
    fn empty_files_are_carried() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("nothing.txt");
        write(&file, "");
        let scan = scan(&[file], ScanOptions::default()).unwrap();
        assert_eq!(scan.sources[0].entry.size, 0);
        assert_eq!(scan.total_bytes, 0);
    }

    #[test]
    fn unicode_and_spaces_survive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("files");
        write(&root.join("café ☕.jpg"), "x");
        write(&root.join("日本語.txt"), "y");

        let scan = scan(&[root], ScanOptions::default()).unwrap();
        let paths = paths_of(&scan);
        assert!(
            paths.contains(&"files/café ☕.jpg".to_string()),
            "{paths:?}"
        );
        assert!(paths.contains(&"files/日本語.txt".to_string()), "{paths:?}");
    }

    #[test]
    fn identical_names_from_different_directories_are_disambiguated() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("one/photo.jpg");
        let b = dir.path().join("two/photo.jpg");
        let c = dir.path().join("three/photo.jpg");
        write(&a, "a");
        write(&b, "bb");
        write(&c, "ccc");

        let scan = scan(&[a, b, c], ScanOptions::default()).unwrap();
        assert_eq!(
            paths_of(&scan),
            vec!["photo.jpg", "photo (2).jpg", "photo (3).jpg"]
        );
        // Each entry still points at its own source file.
        assert_eq!(scan.total_bytes, 6);
    }

    #[test]
    fn extensionless_and_dotfile_names_disambiguate_sensibly() {
        let mut used = HashSet::new();
        assert_eq!(disambiguate("README", &mut used), "README");
        assert_eq!(disambiguate("README", &mut used), "README (2)");
        assert_eq!(disambiguate(".gitignore", &mut used), ".gitignore");
        assert_eq!(disambiguate(".gitignore", &mut used), ".gitignore (2)");
        assert_eq!(disambiguate("a.tar.gz", &mut used), "a.tar.gz");
        assert_eq!(disambiguate("a.tar.gz", &mut used), "a.tar (2).gz");
    }

    #[test]
    fn nothing_to_send_is_an_error() {
        assert!(matches!(
            scan(&[], ScanOptions::default()).unwrap_err(),
            Error::Transfer(TransferError::Empty)
        ));
    }

    #[test]
    fn a_missing_path_reports_the_name() {
        let err = scan(
            &[PathBuf::from("/definitely/not/here.txt")],
            ScanOptions::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("/definitely/not/here.txt"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_unless_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret.txt");
        write(&secret, "not yours");
        let root = dir.path().join("share");
        write(&root.join("ok.txt"), "fine");
        std::os::unix::fs::symlink(&secret, root.join("sneaky.txt")).unwrap();

        let result = scan(std::slice::from_ref(&root), ScanOptions::default()).unwrap();
        let paths = paths_of(&result);
        assert!(paths.contains(&"share/ok.txt".to_string()));
        assert!(
            !paths.iter().any(|p| p.ends_with("sneaky.txt")),
            "a symlink must not be sent by default: {paths:?}"
        );
        assert_eq!(result.skipped.len(), 1);
        assert!(result.skipped[0].contains("symbolic link"));

        // With the flag, the target's contents are sent under the link's name.
        let followed = paths_of(
            &scan(
                &[root],
                ScanOptions {
                    follow_symlinks: true,
                },
            )
            .unwrap(),
        );
        assert!(
            followed.contains(&"share/sneaky.txt".to_string()),
            "{followed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_named_on_the_command_line_is_also_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.txt");
        write(&real, "x");
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = scan(&[link], ScanOptions::default()).unwrap_err();
        assert!(matches!(err, Error::Transfer(TransferError::Empty)));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_loop_does_not_hang() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("loop");
        fs::create_dir_all(&root).unwrap();
        write(&root.join("file.txt"), "x");
        std::os::unix::fs::symlink(&root, root.join("self")).unwrap();

        // Without following links the loop is invisible.
        let result = scan(std::slice::from_ref(&root), ScanOptions::default()).unwrap();
        assert!(paths_of(&result).contains(&"loop/file.txt".to_string()));

        // With following links, walkdir detects the cycle and reports it as a
        // skipped path rather than recursing forever.
        let followed = scan(
            &[root],
            ScanOptions {
                follow_symlinks: true,
            },
        )
        .unwrap();
        assert!(
            !followed.skipped.is_empty(),
            "the loop should be reported: {followed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn permissions_travel_with_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("run.sh");
        write(&script, "#!/bin/sh\n");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let scan = scan(&[script], ScanOptions::default()).unwrap();
        let mode = scan.sources[0].entry.mode.expect("mode recorded");
        assert_eq!(mode & 0o111, 0o111, "executable bit should be recorded");
    }

    #[test]
    fn modification_times_are_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        write(&file, "x");
        let scan = scan(&[file], ScanOptions::default()).unwrap();
        let mtime = scan.sources[0].entry.mtime.expect("mtime recorded");
        assert!(
            mtime > 1_600_000_000,
            "{mtime} should be a recent unix time"
        );
    }
}
