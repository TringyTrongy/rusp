//! Tests that run the real `rusp` binary the way a person would.

use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const RUSP: &str = env!("CARGO_BIN_EXE_rusp");
const CODE: &str = "clit-cotton-harbor-tiger-pencil";

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

fn write(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

/// A port nothing is listening on, chosen by the OS and then released.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// A relay running for the duration of a test.
struct RelayProcess {
    child: Child,
    address: String,
}

impl RelayProcess {
    fn start() -> RelayProcess {
        let port = free_port();
        let address = format!("127.0.0.1:{port}");
        let child = Command::new(RUSP)
            .args(["relay", "--listen", &address])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the relay");
        // Owned straight away, so `Drop` reaps it even if the wait below
        // gives up and panics.
        let relay = RelayProcess { child, address };

        // Wait for it to actually be listening rather than sleeping blindly.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(&relay.address).is_ok() {
                return relay;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the relay never started listening on {}", relay.address);
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn rusp(working_dir: &Path, relay: &str) -> Command {
    let mut command = Command::new(RUSP);
    command
        .current_dir(working_dir)
        .env("RUSP_RELAY", relay)
        .env("RUSP_CONFIG", "/nonexistent/rusp-tests/config.toml")
        .env("NO_COLOR", "1");
    command
}

#[test]
fn help_and_version_work_without_any_setup() {
    let output = Command::new(RUSP).arg("--version").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.starts_with("rusp "), "{text}");

    let output = Command::new(RUSP).arg("--help").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    for expected in ["send", "receive", "relay", "config"] {
        assert!(text.contains(expected), "help should mention {expected}");
    }
}

#[test]
fn a_bad_code_is_explained_not_dumped() {
    let output = Command::new(RUSP)
        .args(["receive", "nonsense"])
        .env("RUSP_CONFIG", "/nonexistent/rusp-tests/config.toml")
        .output()
        .unwrap();
    assert!(!output.status.success());

    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("error:"), "{text}");
    assert!(text.contains("secret words"), "{text}");
    // No panic, no backtrace, no Debug formatting.
    assert!(!text.contains("panicked"), "{text}");
    assert!(!text.contains("RUST_BACKTRACE"), "{text}");
    assert!(!text.contains("CodeError"), "{text}");
}

#[test]
fn sending_a_missing_file_names_the_file() {
    let output = Command::new(RUSP)
        .args(["send", "/definitely/not/here.txt"])
        .env("RUSP_CONFIG", "/nonexistent/rusp-tests/config.toml")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("/definitely/not/here.txt"), "{text}");
    assert!(!text.contains("panicked"), "{text}");
}

#[test]
fn with_no_relay_and_no_lan_the_error_says_what_to_do() {
    let workspace = dir();
    write(&workspace.path().join("a.txt"), b"x");

    let output = Command::new(RUSP)
        .current_dir(workspace.path())
        .args(["send", "--no-relay", "--no-lan", "a.txt"])
        .env("RUSP_CONFIG", "/nonexistent/rusp-tests/config.toml")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("could not find the other side"), "{text}");
    assert!(text.contains("hint:"), "{text}");
    assert!(text.contains("rusp relay"), "{text}");
}

#[test]
fn config_show_and_init_behave() {
    let workspace = dir();
    let config_path = workspace.path().join("config.toml");

    let output = Command::new(RUSP)
        .args(["config", "init", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(config_path.exists());

    // Running it again must not clobber the file.
    std::fs::write(&config_path, "words = 5\n").unwrap();
    let output = Command::new(RUSP)
        .args(["config", "init", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        "words = 5\n"
    );

    let output = Command::new(RUSP)
        .args(["config", "show", "--config"])
        .arg(&config_path)
        .env_remove("RUSP_RELAY")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("words          = 5"), "{text}");
}

#[test]
fn a_transfer_between_two_processes_arrives_intact() {
    let relay = RelayProcess::start();
    let source = dir();
    let destination = dir();

    write(&source.path().join("report.txt"), b"hello across processes");
    write(&source.path().join("photos/one.jpg"), &vec![7u8; 300_000]);
    std::fs::create_dir_all(source.path().join("photos/empty")).unwrap();

    let sender = rusp(source.path(), &relay.address)
        .args(["send", "--no-lan", "--code", CODE, "report.txt", "photos"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the sender");

    // Give the sender a moment to register its room with the relay.
    std::thread::sleep(Duration::from_millis(300));

    let received = rusp(destination.path(), &relay.address)
        .args(["receive", "--no-lan", "-y", CODE])
        .output()
        .expect("run the receiver");

    let sent = sender.wait_with_output().expect("sender finishes");
    assert!(
        sent.status.success(),
        "sender failed: {}",
        String::from_utf8_lossy(&sent.stderr)
    );
    assert!(
        received.status.success(),
        "receiver failed: {}",
        String::from_utf8_lossy(&received.stderr)
    );

    assert_eq!(
        std::fs::read(destination.path().join("report.txt")).unwrap(),
        b"hello across processes"
    );
    assert_eq!(
        std::fs::read(destination.path().join("photos/one.jpg")).unwrap(),
        vec![7u8; 300_000]
    );
    assert!(destination.path().join("photos/empty").is_dir());

    // The sender prints the code where a person can see it.
    let sender_output = String::from_utf8_lossy(&sent.stderr);
    assert!(sender_output.contains(CODE), "{sender_output}");
    assert!(sender_output.contains("rusp receive"), "{sender_output}");
}

#[test]
fn a_wrong_code_fails_on_both_sides_with_a_hint() {
    let relay = RelayProcess::start();
    let source = dir();
    let destination = dir();
    write(&source.path().join("a.txt"), b"x");

    let sender = rusp(source.path(), &relay.address)
        .args([
            "send",
            "--no-lan",
            "--code",
            "wrng-cotton-harbor-tiger-pencil",
            "a.txt",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the sender");
    std::thread::sleep(Duration::from_millis(300));

    let received = rusp(destination.path(), &relay.address)
        .args([
            "receive",
            "--no-lan",
            "-y",
            "wrng-cotton-harbor-tiger-museum",
        ])
        .output()
        .expect("run the receiver");

    let sent = sender.wait_with_output().expect("sender finishes");
    assert!(!received.status.success());
    assert!(!sent.status.success());

    let text = String::from_utf8_lossy(&received.stderr);
    assert!(text.contains("transfer codes do not match"), "{text}");
    assert!(text.contains("hint:"), "{text}");
    assert!(!text.contains("panicked"), "{text}");
    assert!(
        destination.path().read_dir().unwrap().next().is_none(),
        "nothing should be written when the code is wrong"
    );
}

#[test]
fn the_receiver_can_decline_an_offer() {
    let relay = RelayProcess::start();
    let source = dir();
    let destination = dir();
    write(&source.path().join("a.txt"), b"unwanted");

    let sender = rusp(source.path(), &relay.address)
        .args([
            "send",
            "--no-lan",
            "--code",
            "decl-cotton-harbor-tiger-pencil",
            "a.txt",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the sender");
    std::thread::sleep(Duration::from_millis(300));

    // Answering "n" on a pipe is not a terminal, so drive the decision with a
    // conflict policy instead: `--on-conflict fail` against a file that is
    // already there refuses the transfer.
    write(&destination.path().join("a.txt"), b"mine");
    let received = rusp(destination.path(), &relay.address)
        .args([
            "receive",
            "--no-lan",
            "-y",
            "--on-conflict",
            "fail",
            "decl-cotton-harbor-tiger-pencil",
        ])
        .output()
        .expect("run the receiver");

    let sent = sender.wait_with_output().expect("sender finishes");
    assert!(!received.status.success());
    assert!(!sent.status.success());

    assert_eq!(
        std::fs::read(destination.path().join("a.txt")).unwrap(),
        b"mine",
        "the existing file must be untouched"
    );
    let sender_text = String::from_utf8_lossy(&sent.stderr);
    assert!(
        sender_text.contains("declined") || sender_text.contains("already exists"),
        "the sender should be told why: {sender_text}"
    );
}

#[test]
fn the_receiver_prompts_for_a_code_when_none_is_given() {
    let destination = dir();
    let mut child = Command::new(RUSP)
        .current_dir(destination.path())
        .args(["receive", "--no-lan", "--no-relay"])
        .env("RUSP_CONFIG", "/nonexistent/rusp-tests/config.toml")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the receiver");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"prmt-cotton-harbor-tiger-pencil\n")
        .expect("write the code");

    let output = child.wait_with_output().expect("receiver finishes");
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("Enter the transfer code"), "{text}");
    // With no relay and no LAN there is nowhere to go, which is the expected
    // failure — the point is that the code was read from stdin first.
    assert!(text.contains("could not find the other side"), "{text}");
}
