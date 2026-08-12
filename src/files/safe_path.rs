//! Turning a path a stranger sent us into a path we are willing to write.
//!
//! Everything in a manifest comes from the other machine, so every path is
//! treated as hostile input. The rule is **reject, do not repair**: a path that
//! is not obviously safe is refused and named, rather than quietly rewritten
//! into something the sender did not ask for.
//!
//! What is refused:
//!
//! * absolute paths, including `C:\...`, `\\server\share` and `\\?\...`,
//! * any `..` component, in either slash direction,
//! * `.` components and empty components, so `a//b` and `a/./b` cannot smuggle
//!   an empty name past a later check,
//! * NUL and other control characters,
//! * names longer than 255 bytes, or whole paths longer than
//!   [`crate::protocol::message::MAX_PATH_LEN`],
//! * Windows device names (`CON`, `NUL`, `COM1`, …), with or without an
//!   extension, on every platform — so a tree built on Linux cannot produce a
//!   file that is unusable, or worse, on Windows,
//! * names with a trailing dot or space, which Windows silently strips and
//!   which therefore alias onto a different file than the one requested.
//!
//! Both `/` and `\` count as separators regardless of the platform we are
//! running on. A sender on Windows offering `a\b.txt` means two components, and
//! a hostile sender must not be able to hide `..\..` from a Unix receiver by
//! choosing the other slash.

use std::path::{Component, Path, PathBuf};

use crate::error::TransferError;
use crate::protocol::message::MAX_PATH_LEN;

/// Longest single path component accepted, in bytes. Matches the limit on
/// every mainstream filesystem.
pub const MAX_COMPONENT_LEN: usize = 255;

/// Windows device names, which resolve to devices rather than files no matter
/// which directory they appear in.
const WINDOWS_DEVICE_NAMES: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Split a peer-supplied path into validated components.
///
/// Returns the components in order, or the reason the path was refused.
pub fn validate(offered: &str) -> Result<Vec<&str>, TransferError> {
    let refuse = |why: &str| TransferError::UnsafePath(format!("`{offered}` {why}"));

    if offered.is_empty() {
        return Err(refuse("is empty"));
    }
    if offered.len() > MAX_PATH_LEN {
        return Err(refuse("is longer than the protocol allows"));
    }
    if offered.chars().any(|c| c.is_control()) {
        return Err(refuse("contains control characters"));
    }
    if offered.starts_with('/') || offered.starts_with('\\') {
        return Err(refuse("is an absolute path"));
    }
    if is_windows_drive_prefixed(offered) {
        return Err(refuse("names a Windows drive"));
    }

    let components: Vec<&str> = offered.split(['/', '\\']).collect();
    for component in &components {
        if component.is_empty() {
            return Err(refuse("has an empty path component"));
        }
        if *component == "." || *component == ".." {
            return Err(refuse("tries to leave the destination directory"));
        }
        if component.len() > MAX_COMPONENT_LEN {
            return Err(refuse("has a path component that is too long"));
        }
        if component.ends_with(' ') || component.ends_with('.') {
            return Err(refuse(
                "has a component ending in a dot or space, which some systems silently rewrite",
            ));
        }
        if is_windows_device_name(component) {
            return Err(refuse("uses a reserved Windows device name"));
        }
        #[cfg(windows)]
        if component.contains(['<', '>', ':', '"', '|', '?', '*']) {
            return Err(refuse(
                "contains characters Windows does not allow in a name",
            ));
        }
    }

    Ok(components)
}

/// Resolve a peer-supplied path against a destination directory.
///
/// The returned path is always inside `root`. Validation happens first, and
/// the joined result is checked again — the second check costs nothing and
/// means a mistake in the first would still not let anything escape.
pub fn resolve(root: &Path, offered: &str) -> Result<PathBuf, TransferError> {
    let components = validate(offered)?;

    let mut path = root.to_path_buf();
    for component in &components {
        path.push(component);
    }

    // Belt and braces: whatever the validation above did or did not catch, the
    // result must still be a plain descendant of the root.
    if !is_plain_descendant(root, &path) {
        return Err(TransferError::UnsafePath(format!(
            "`{offered}` would end up outside the destination directory"
        )));
    }
    Ok(path)
}

/// True when `path` is `root` plus only ordinary named components.
fn is_plain_descendant(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let mut any = false;
    for component in relative.components() {
        match component {
            Component::Normal(_) => any = true,
            // Prefix, RootDir, CurDir and ParentDir all mean this is not a
            // simple path below the root.
            _ => return false,
        }
    }
    any
}

/// True for `C:foo`, `C:/foo`, and the `\\?\` and `\\server\share` forms.
fn is_windows_drive_prefixed(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return true;
    }
    path.starts_with("\\\\") || path.starts_with("//")
}

/// True for `CON`, `nul.txt`, `COM1`, and friends.
pub fn is_windows_device_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ')
        .to_ascii_lowercase();
    WINDOWS_DEVICE_NAMES.contains(&stem.as_str())
}

/// Turn a local path into the `/`-separated relative form the protocol uses.
///
/// Only ordinary components survive; anything else means the caller built a
/// path we should not be offering, and is reported rather than guessed at.
pub fn to_manifest_path(relative: &Path) -> Result<String, TransferError> {
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => match part.to_str() {
                Some(text) => parts.push(text),
                None => {
                    return Err(TransferError::UnsafePath(format!(
                        "{} is not valid UTF-8 and cannot be sent",
                        relative.display()
                    )))
                }
            },
            _ => {
                return Err(TransferError::UnsafePath(format!(
                    "{} is not a plain relative path",
                    relative.display()
                )))
            }
        }
    }
    if parts.is_empty() {
        return Err(TransferError::UnsafePath("empty path".into()));
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from("/dest")
    }

    fn refused(offered: &str) -> String {
        match resolve(&root(), offered) {
            Ok(path) => panic!("`{offered}` was accepted as {}", path.display()),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn ordinary_paths_are_accepted() {
        for (offered, expected) in [
            ("a.txt", "/dest/a.txt"),
            ("dir/a.txt", "/dest/dir/a.txt"),
            ("a/b/c/d.txt", "/dest/a/b/c/d.txt"),
            ("café ☕.jpg", "/dest/café ☕.jpg"),
            ("with spaces.txt", "/dest/with spaces.txt"),
            ("日本語/ファイル.txt", "/dest/日本語/ファイル.txt"),
            ("emoji-🚀.bin", "/dest/emoji-🚀.bin"),
            ("dots.in.the.name.tar.gz", "/dest/dots.in.the.name.tar.gz"),
            ("..hidden-but-fine", "/dest/..hidden-but-fine"),
            ("...three", "/dest/...three"),
            ("-leading-dash", "/dest/-leading-dash"),
        ] {
            let got = resolve(&root(), offered).unwrap_or_else(|e| panic!("{offered}: {e}"));
            assert_eq!(got, PathBuf::from(expected), "{offered}");
        }
    }

    #[test]
    fn a_windows_sender_reaching_a_unix_receiver_still_nests() {
        assert_eq!(
            resolve(&root(), "dir\\sub\\file.txt").unwrap(),
            PathBuf::from("/dest/dir/sub/file.txt")
        );
    }

    #[test]
    fn traversal_is_refused_in_every_disguise() {
        for offered in [
            "../escape",
            "..",
            "a/../../escape",
            "a/..",
            "..\\escape",
            "a\\..\\..\\escape",
            "a/b/../../../escape",
            "./../escape",
            "subdir/../../../../../../etc/passwd",
        ] {
            let message = refused(offered);
            assert!(
                message.contains("leave the destination directory"),
                "{offered}: {message}"
            );
        }
    }

    #[test]
    fn absolute_paths_are_refused() {
        for offered in [
            "/etc/passwd",
            "/",
            "\\windows\\system32",
            "C:\\Windows\\System32",
            "c:/windows",
            "C:relative",
            "\\\\server\\share\\file",
            "\\\\?\\C:\\file",
            "//server/share",
        ] {
            let message = refused(offered);
            assert!(
                message.contains("absolute") || message.contains("Windows drive"),
                "{offered}: {message}"
            );
        }
    }

    #[test]
    fn empty_components_are_refused() {
        // `a//b` normalises away on some systems and not others; refusing it
        // means the receiver never has to care which.
        for offered in ["a//b", "a/", "/a", "a\\\\b", "a/b//", ""] {
            refused(offered);
        }
    }

    #[test]
    fn dot_components_are_refused() {
        for offered in ["./a", "a/./b", "a/."] {
            refused(offered);
        }
    }

    #[test]
    fn control_characters_are_refused() {
        for offered in ["a\0b", "a\nb", "a\rb", "a\tb", "\u{7f}"] {
            let message = refused(offered);
            assert!(message.contains("control characters"), "{message}");
        }
    }

    #[test]
    fn windows_device_names_are_refused_on_every_platform() {
        for offered in [
            "CON",
            "con",
            "nul",
            "NUL.txt",
            "aux.tar.gz",
            "COM1",
            "lpt9",
            "dir/con",
            "prn",
        ] {
            let message = refused(offered);
            assert!(message.contains("device name"), "{offered}: {message}");
        }
        // Names that merely start with a device name are fine.
        for ok in ["console.log", "connection", "nullable.txt", "com10"] {
            assert!(resolve(&root(), ok).is_ok(), "{ok} should be allowed");
        }
    }

    #[test]
    fn trailing_dots_and_spaces_are_refused() {
        for offered in ["file.", "file ", "dir./file", "dir /file", "a/b."] {
            let message = refused(offered);
            assert!(message.contains("dot or space"), "{offered}: {message}");
        }
    }

    #[test]
    fn overlong_names_are_refused() {
        let long_component = "a".repeat(MAX_COMPONENT_LEN + 1);
        assert!(refused(&long_component).contains("too long"));

        let long_path = std::iter::repeat_n("dir", 2000)
            .collect::<Vec<_>>()
            .join("/");
        assert!(long_path.len() > MAX_PATH_LEN);
        assert!(refused(&long_path).contains("longer than the protocol allows"));

        // Exactly at the limit is fine.
        assert!(resolve(&root(), &"a".repeat(MAX_COMPONENT_LEN)).is_ok());
    }

    #[test]
    fn every_refusal_names_the_offending_path() {
        for offered in ["../x", "/x", "a\0b", "CON", "file.", ""] {
            let message = refused(offered);
            assert!(message.contains("unsafe path"), "{offered}: {message}");
        }
    }

    #[test]
    fn descendant_check_catches_what_validation_might_not() {
        assert!(is_plain_descendant(
            Path::new("/dest"),
            Path::new("/dest/a/b")
        ));
        assert!(!is_plain_descendant(Path::new("/dest"), Path::new("/dest")));
        assert!(!is_plain_descendant(
            Path::new("/dest"),
            Path::new("/other")
        ));
        assert!(!is_plain_descendant(
            Path::new("/dest"),
            Path::new("/dest/../other")
        ));
    }

    #[test]
    fn manifest_paths_use_forward_slashes() {
        assert_eq!(to_manifest_path(Path::new("dir")).unwrap().as_str(), "dir");
        let nested: PathBuf = ["dir", "sub", "file.txt"].iter().collect();
        assert_eq!(to_manifest_path(&nested).unwrap(), "dir/sub/file.txt");
    }

    #[test]
    fn manifest_paths_refuse_anything_not_plainly_relative() {
        assert!(to_manifest_path(Path::new("/absolute")).is_err());
        assert!(to_manifest_path(Path::new("../up")).is_err());
        assert!(to_manifest_path(Path::new("")).is_err());
    }

    #[test]
    fn round_trip_between_the_two_directions() {
        // Anything we are willing to offer must be something we are willing to
        // accept, or a transfer between two Rusp builds could refuse itself.
        for original in ["a.txt", "dir/sub/file.txt", "café ☕.jpg", "日本語/x.txt"] {
            let components = validate(original).unwrap();
            let local: PathBuf = components.iter().collect();
            assert_eq!(to_manifest_path(&local).unwrap(), original);
        }
    }
}
