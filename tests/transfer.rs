//! End-to-end transfers: two peers, a real relay, real files.

mod common;

use std::path::PathBuf;

use common::{pseudo_random, round_trip, round_trip_with, tree, write, TestRelay};
use rusp::config::ConflictPolicy;
use rusp::error::{Error, TransferError};

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_single_file_arrives_intact() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    write(
        &source.path().join("report.txt"),
        b"hello from the other side",
    );

    let result = round_trip(
        &relay,
        "one1",
        &[source.path().join("report.txt")],
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    assert_eq!(result.sent.files, 1);
    assert_eq!(result.received.files, 1);
    assert_eq!(tree(destination.path()), vec!["report.txt"]);
    assert_eq!(
        std::fs::read(destination.path().join("report.txt")).unwrap(),
        b"hello from the other side"
    );
    // Both sides observed the same number of bytes moving.
    assert_eq!(result.sender_bytes, result.receiver_bytes);
}

#[tokio::test(flavor = "multi_thread")]
async fn several_files_arrive_together() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    let names = ["a.txt", "b.bin", "c.log"];
    for (i, name) in names.iter().enumerate() {
        write(
            &source.path().join(name),
            &pseudo_random(1000 * (i + 1), i as u64),
        );
    }
    let sources: Vec<PathBuf> = names.iter().map(|n| source.path().join(n)).collect();

    let result = round_trip(
        &relay,
        "many",
        &sources,
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    assert_eq!(result.received.files, 3);
    assert_eq!(tree(destination.path()), vec!["a.txt", "b.bin", "c.log"]);
    for name in names {
        assert_eq!(
            std::fs::read(source.path().join(name)).unwrap(),
            std::fs::read(destination.path().join(name)).unwrap(),
            "{name} should match"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_directory_arrives_with_its_shape_intact() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    let root = source.path().join("photos");
    write(&root.join("one.jpg"), b"1");
    write(&root.join("nested/two.jpg"), b"22");
    write(&root.join("nested/deeper/three.jpg"), b"333");
    std::fs::create_dir_all(root.join("empty")).unwrap();
    std::fs::create_dir_all(root.join("nested/also-empty")).unwrap();

    let result = round_trip(
        &relay,
        "dir1",
        &[root],
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    assert_eq!(result.received.files, 3);
    assert_eq!(
        tree(destination.path()),
        vec![
            "photos/",
            "photos/empty/",
            "photos/nested/",
            "photos/nested/also-empty/",
            "photos/nested/deeper/",
            "photos/nested/deeper/three.jpg",
            "photos/nested/two.jpg",
            "photos/one.jpg",
        ],
        "empty directories must survive the trip"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unicode_and_awkward_names_survive() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    let root = source.path().join("names");
    let names = [
        "café ☕.jpg",
        "日本語のファイル.txt",
        "with spaces and 'quotes'.txt",
        "emoji-🚀.bin",
        "dots.in.the.name.tar.gz",
        &"long-".repeat(40),
    ];
    for name in names {
        write(&root.join(name), name.as_bytes());
    }

    round_trip(
        &relay,
        "uni1",
        &[root],
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    for name in names {
        let path = destination.path().join("names").join(name);
        assert_eq!(
            std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: {e}")),
            name.as_bytes()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_files_and_empty_directories_are_carried() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    let root = source.path().join("mixed");
    write(&root.join("empty.txt"), b"");
    write(&root.join("not-empty.txt"), b"x");
    std::fs::create_dir_all(root.join("nothing-here")).unwrap();

    let result = round_trip(
        &relay,
        "empt",
        &[root],
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    assert_eq!(result.received.files, 2);
    assert_eq!(
        std::fs::metadata(destination.path().join("mixed/empty.txt"))
            .unwrap()
            .len(),
        0
    );
    assert!(destination.path().join("mixed/nothing-here").is_dir());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_file_crosses_many_chunks_and_verifies() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    // Comfortably more than the 256 KiB chunk size, with a deliberately
    // awkward tail so the last frame is a partial one.
    let contents = pseudo_random(3 * 1024 * 1024 + 12_345, 42);
    write(&source.path().join("big.bin"), &contents);

    let result = round_trip(
        &relay,
        "big1",
        &[source.path().join("big.bin")],
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    assert_eq!(result.received.bytes, contents.len() as u64);
    assert_eq!(
        std::fs::read(destination.path().join("big.bin")).unwrap(),
        contents,
        "a multi-chunk file must arrive byte for byte"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn many_small_files_do_not_need_a_round_trip_each() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    let root = source.path().join("many");
    for i in 0..500 {
        write(
            &root.join(format!("file-{i:04}.txt")),
            format!("{i}").as_bytes(),
        );
    }

    let started = std::time::Instant::now();
    let result = round_trip(
        &relay,
        "smal",
        &[root],
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");
    let elapsed = started.elapsed();

    assert_eq!(result.received.files, 500);
    assert_eq!(tree(destination.path()).len(), 501, "500 files and one dir");
    // Over loopback this is generous; it would fail loudly if a per-file
    // acknowledgement were ever reintroduced on a real network.
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "500 files took {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_files_are_renamed_by_default() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    write(&source.path().join("a.txt"), b"new");
    write(&destination.path().join("a.txt"), b"original");

    round_trip(
        &relay,
        "ren1",
        &[source.path().join("a.txt")],
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    assert_eq!(
        std::fs::read(destination.path().join("a.txt")).unwrap(),
        b"original",
        "the existing file must be untouched"
    );
    assert_eq!(
        std::fs::read(destination.path().join("a (1).txt")).unwrap(),
        b"new"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn overwrite_replaces_and_skip_keeps() {
    let relay = TestRelay::start().await;
    let source = dir();
    write(&source.path().join("a.txt"), b"new");

    let overwrite = dir();
    write(&overwrite.path().join("a.txt"), b"original");
    round_trip(
        &relay,
        "ovw1",
        &[source.path().join("a.txt")],
        overwrite.path(),
        ConflictPolicy::Overwrite,
    )
    .await
    .expect("transfer should succeed");
    assert_eq!(
        std::fs::read(overwrite.path().join("a.txt")).unwrap(),
        b"new"
    );

    let skip = dir();
    write(&skip.path().join("a.txt"), b"original");
    let result = round_trip(
        &relay,
        "skp1",
        &[source.path().join("a.txt")],
        skip.path(),
        ConflictPolicy::Skip,
    )
    .await
    .expect("transfer should succeed");
    assert_eq!(
        std::fs::read(skip.path().join("a.txt")).unwrap(),
        b"original"
    );
    assert_eq!(result.received.files, 0);
    assert_eq!(result.received.skipped, 1);
    assert_eq!(
        result.sender_bytes, 0,
        "a skipped file's bytes must never cross the network"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_fail_policy_refuses_the_whole_transfer() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    write(&source.path().join("a.txt"), b"new");
    write(&source.path().join("b.txt"), b"also new");
    write(&destination.path().join("a.txt"), b"original");

    let err = round_trip(
        &relay,
        "fail",
        &[source.path().join("a.txt"), source.path().join("b.txt")],
        destination.path(),
        ConflictPolicy::Fail,
    )
    .await
    .expect_err("should refuse");
    assert!(
        matches!(err, Error::Transfer(TransferError::Exists(_)))
            || matches!(err, Error::Transfer(TransferError::Declined(_))),
        "{err}"
    );

    assert_eq!(
        std::fs::read(destination.path().join("a.txt")).unwrap(),
        b"original"
    );
    assert!(
        !destination.path().join("b.txt").exists(),
        "nothing should be written when the transfer is refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declined_offer_is_reported_to_the_sender() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    write(&source.path().join("a.txt"), b"x");

    let (sent, declined) = common::decline(
        &relay,
        "dcln",
        &[source.path().join("a.txt")],
        destination.path(),
    )
    .await;

    declined.expect("declining should succeed");
    let err = sent.expect_err("the sender should be told");
    assert!(
        matches!(err, Error::Transfer(TransferError::Declined(_))),
        "{err}"
    );
    assert!(err.to_string().contains("no thanks"), "{err}");
    assert!(tree(destination.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_partial_is_left_behind_on_success() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    write(&source.path().join("a.bin"), &pseudo_random(500_000, 7));

    round_trip(
        &relay,
        "part",
        &[source.path().join("a.bin")],
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    let leftovers: Vec<String> = tree(destination.path())
        .into_iter()
        .filter(|p| p.contains("rusp-part"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_executable_bit_travels_but_nothing_else_does() {
    use std::os::unix::fs::PermissionsExt;

    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    let script = source.path().join("run.sh");
    write(&script, b"#!/bin/sh\necho hi\n");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o4755)).unwrap();
    let plain = source.path().join("notes.txt");
    write(&plain, b"just text");
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o600)).unwrap();

    round_trip(
        &relay,
        "mode",
        &[script, plain],
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    let mode = std::fs::metadata(destination.path().join("run.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "the executable bit should arrive");
    assert_eq!(mode & 0o4000, 0, "setuid must never arrive");

    let mode = std::fs::metadata(destination.path().join("notes.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0, "a plain file stays non-executable");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn symlinks_are_left_behind_unless_asked_for() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    let secret = source.path().join("secret.txt");
    write(&secret, b"not for sharing");
    let root = source.path().join("share");
    write(&root.join("ok.txt"), b"fine");
    std::os::unix::fs::symlink(&secret, root.join("sneaky.txt")).unwrap();

    round_trip(
        &relay,
        "link",
        std::slice::from_ref(&root),
        destination.path(),
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    assert_eq!(tree(destination.path()), vec!["share/", "share/ok.txt"]);

    // With --follow-symlinks the contents come across under the link's name.
    let followed = dir();
    round_trip_with(
        &relay,
        "lnk2",
        &[root],
        followed.path(),
        ConflictPolicy::Rename,
        rusp::files::ScanOptions {
            follow_symlinks: true,
        },
    )
    .await
    .expect("transfer should succeed");
    assert_eq!(
        std::fs::read(followed.path().join("share/sneaky.txt")).unwrap(),
        b"not for sharing"
    );
    assert!(
        !followed.path().join("share/sneaky.txt").is_symlink(),
        "the receiver writes a regular file, never a link"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_destination_directory_is_created_if_it_is_missing() {
    let relay = TestRelay::start().await;
    let source = dir();
    let destination = dir();
    write(&source.path().join("a.txt"), b"x");
    let nested = destination.path().join("does/not/exist/yet");

    round_trip(
        &relay,
        "mkdi",
        &[source.path().join("a.txt")],
        &nested,
        ConflictPolicy::Rename,
    )
    .await
    .expect("transfer should succeed");

    assert_eq!(std::fs::read(nested.join("a.txt")).unwrap(), b"x");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_transfers_can_share_a_relay_at_once() {
    let relay = TestRelay::start().await;
    let source = dir();
    let first = dir();
    let second = dir();
    write(&source.path().join("a.txt"), b"first");
    write(&source.path().join("b.txt"), b"second");
    let a_source = [source.path().join("a.txt")];
    let b_source = [source.path().join("b.txt")];

    let (a, b) = tokio::join!(
        round_trip(
            &relay,
            "cca1",
            &a_source,
            first.path(),
            ConflictPolicy::Rename,
        ),
        round_trip(
            &relay,
            "ccb1",
            &b_source,
            second.path(),
            ConflictPolicy::Rename,
        )
    );

    a.expect("first transfer");
    b.expect("second transfer");
    assert_eq!(std::fs::read(first.path().join("a.txt")).unwrap(), b"first");
    assert_eq!(
        std::fs::read(second.path().join("b.txt")).unwrap(),
        b"second"
    );
}
