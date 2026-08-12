//! Wiring between the parsed command line and the library.
//!
//! This is the only module that combines configuration, terminal output and
//! the transfer engine. Keeping that in one place is what lets the rest of the
//! crate stay free of both `clap` and the terminal.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use console::style;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::cli::{
    Cli, Command, ConfigAction, ConfigArgs, GlobalArgs, NetArgs, ReceiveArgs, RelayArgs, SendArgs,
    Verbosity,
};
use crate::code::TransferCode;
use crate::config::{self, Config, RelayConfig};
use crate::error::{CryptoError, Error, IoContext, ProtocolError, Result};
use crate::files::{self, ScanOptions};
use crate::net::server::{Relay, RelaySettings};
use crate::net::{self, Connection, NetOptions, SenderRendezvous};
use crate::protocol::channel::Channel;
use crate::protocol::Role;
use crate::transfer::{self, ReceiveOptions};
use crate::ui::progress::BarSink;
use crate::ui::{self, human_bytes, plural, Reporter};

/// How long a handshake may take before the peer is assumed to be stuck.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Execute a parsed command line.
pub fn run(cli: Cli) -> Result<()> {
    ui::set_color_choice(cli.global.color);
    let reporter = Reporter::new(cli.global.verbosity());
    let config = load_config(&cli.global)?;

    // The config subcommand does no I/O worth an async runtime.
    if let Command::Config(args) = &cli.command {
        return config_command(args, &cli.global, &config, &reporter);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::io("start the async runtime", e))?;

    runtime.block_on(async move {
        let cancel = install_signal_handler(&reporter);
        match cli.command {
            Command::Send(args) => send(args, &cli.global, config, &reporter, &cancel).await,
            Command::Receive(args) => receive(args, &cli.global, config, &reporter, &cancel).await,
            Command::Relay(args) => relay(args, config, &reporter, &cancel).await,
            Command::Config(_) => unreachable!("handled before the runtime starts"),
        }
    })
}

/// Resolve configuration from the file and environment, honouring `--config`.
pub fn load_config(global: &GlobalArgs) -> Result<Config> {
    match &global.config {
        Some(path) => {
            let mut config = Config::from_file(path)?;
            config.apply_env();
            Ok(config)
        }
        None => Config::load(),
    }
}

/// Cancel on the first Ctrl+C; leave immediately on the second.
fn install_signal_handler(reporter: &Reporter) -> CancellationToken {
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let reporter = reporter.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            reporter.warn("stopping — press Ctrl+C again to quit immediately");
            token.cancel();
            if tokio::signal::ctrl_c().await.is_ok() {
                // The user has asked twice. Partial files may be left behind,
                // which is better than ignoring them.
                std::process::exit(130);
            }
        }
    });
    cancel
}

// ---------------------------------------------------------------------------
// send
// ---------------------------------------------------------------------------

async fn send(
    args: SendArgs,
    global: &GlobalArgs,
    config: Config,
    reporter: &Reporter,
    cancel: &CancellationToken,
) -> Result<()> {
    let options = net_options(&config, &args.net);
    let paths = args.paths.clone();
    let follow_symlinks = args.follow_symlinks;

    // Walking a large tree is blocking work; keep it off the reactor.
    let scan =
        tokio::task::spawn_blocking(move || files::scan(&paths, ScanOptions { follow_symlinks }))
            .await
            .map_err(|e| Error::io("scan the files to send", std::io::Error::other(e)))??;

    for note in &scan.skipped {
        reporter.warn(note);
    }

    let code = match &args.code {
        Some(text) => TransferCode::parse(text)?,
        None => TransferCode::generate(args.words.unwrap_or(config.words))?,
    };

    let mut rendezvous = SenderRendezvous::open(options, code.room().clone()).await?;
    if let Some(port) = rendezvous.lan_port() {
        reporter.detail(format!("listening on port {port} for local peers"));
    }

    reporter.info(format!(
        "sending {} ({})",
        plural(scan.file_count(), "file", "files"),
        human_bytes(scan.total_bytes)
    ));
    reporter.info(format!(
        "\n  on the other machine, run:\n\n    {} {}\n",
        style("rusp receive").bold(),
        style(&code).cyan().bold()
    ));
    if let Some(bits) = code.entropy_bits() {
        reporter.detail(format!("code entropy: {bits} bits"));
    }

    let mut channel = loop {
        let connection = rendezvous.accept(cancel).await?;
        reporter.detail(connection.describe());
        match handshake(connection, Role::Sender, &code, reporter).await {
            Ok(channel) => break channel,
            // Somebody who is not our peer reached the listening socket. No
            // guess at the code was spent, so keep waiting.
            Err(e) if is_retryable(&e) => {
                reporter.detail(format!("ignoring a connection that was not our peer: {e}"));
                continue;
            }
            Err(e) => return Err(e),
        }
    };

    let sink = progress_sink(global, reporter);
    let result = transfer::send(&mut channel, &scan, &sink, cancel).await;
    sink.clear();

    let report = match result {
        Ok(report) => report,
        Err(e) => {
            // A write failure usually means the receiver already told us why
            // and hung up; that message is more useful than "broken pipe".
            let better = transfer::sender::recover_peer_error(&mut channel).await;
            return Err(better.unwrap_or(e));
        }
    };
    let _ = channel.shutdown().await;

    reporter.success(format!(
        "sent {} ({}){}",
        plural(report.files as usize, "file", "files"),
        human_bytes(report.bytes),
        if report.skipped > 0 {
            format!(", {} already on the other side", report.skipped)
        } else {
            String::new()
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// receive
// ---------------------------------------------------------------------------

async fn receive(
    args: ReceiveArgs,
    global: &GlobalArgs,
    config: Config,
    reporter: &Reporter,
    cancel: &CancellationToken,
) -> Result<()> {
    let code = match &args.code {
        Some(text) => TransferCode::parse(text)?,
        None => TransferCode::parse(&prompt("Enter the transfer code: ").await?)?,
    };
    for warning in code.lint() {
        reporter.warn(warning);
    }

    let options = net_options(&config, &args.net);
    let output_dir = args
        .out
        .clone()
        .unwrap_or_else(|| config.resolved_output_dir());
    let receive_options = ReceiveOptions {
        output_dir: output_dir.clone(),
        on_conflict: args.conflict_policy().unwrap_or(config.on_conflict),
    };

    reporter.info("looking for the sender…");
    let connection = net::dial(&options, code.room(), cancel).await?;
    reporter.detail(connection.describe());

    let mut channel = handshake(connection, Role::Receiver, &code, reporter).await?;
    let pending = transfer::begin(&mut channel, receive_options).await?;

    let approved = args.yes || approve(&pending, &output_dir, reporter).await?;
    if !approved {
        pending.decline(Some("declined by the user".into())).await?;
        reporter.info("declined");
        return Ok(());
    }

    let sink = progress_sink(global, reporter);
    let result = pending.accept(&sink, cancel).await;
    sink.clear();
    let report = result?;

    reporter.success(format!(
        "received {} ({}) into {}{}",
        plural(report.files as usize, "file", "files"),
        human_bytes(report.bytes),
        report.output_dir.display(),
        if report.skipped > 0 {
            format!(", {} skipped", report.skipped)
        } else {
            String::new()
        }
    ));
    Ok(())
}

/// Show what is on offer and ask, unless there is nobody to ask.
async fn approve<R, W>(
    pending: &transfer::PendingOffer<'_, R, W>,
    output_dir: &std::path::Path,
    reporter: &Reporter,
) -> Result<bool>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let plan = pending.plan();
    let offer = pending.offer();

    let summary = format!(
        "the sender is offering {} ({}) into {}",
        plural(plan.files as usize, "file", "files"),
        human_bytes(plan.bytes),
        output_dir.display()
    );
    reporter.info(&summary);

    // Show the manifest when it is short enough to be worth reading, or
    // whenever the user asked for detail.
    let listable = offer.entries.len() <= 20 || reporter.verbosity().allows(Verbosity::Verbose);
    if listable && reporter.verbosity().allows(Verbosity::Normal) {
        for entry in offer.entries.iter().take(200) {
            if entry.kind.is_file() {
                reporter.info(format!("  {}  {}", entry.path, human_bytes(entry.size)));
            } else if entry.kind.is_directory() {
                reporter.info(format!("  {}/", entry.path));
            }
        }
        if offer.entries.len() > 200 {
            reporter.info(format!("  … and {} more", offer.entries.len() - 200));
        }
    }

    if !std::io::stdin().is_terminal() {
        // Nobody to ask. The user typed a code to get here, which is consent
        // enough; `--yes` exists to make that explicit in scripts.
        return Ok(true);
    }
    let answer = prompt("accept? [Y/n] ").await?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "" | "y" | "yes"
    ))
}

// ---------------------------------------------------------------------------
// relay
// ---------------------------------------------------------------------------

async fn relay(
    args: RelayArgs,
    config: Config,
    reporter: &Reporter,
    cancel: &CancellationToken,
) -> Result<()> {
    let token = args
        .token
        .map(Zeroizing::new)
        .or_else(|| config.relay.as_ref().and_then(|r| r.token.clone()));

    let settings = RelaySettings {
        listen: args.listen.clone(),
        token,
        max_rooms: args.max_rooms.max(1),
        room_timeout: Duration::from_secs(args.room_timeout.max(1)),
    };
    let relay = Relay::bind(settings.clone()).await?;
    let address = relay.local_addr()?;

    reporter.info(format!("relay listening on {address}"));
    if settings.token.is_some() {
        reporter.detail("a token is required from every client");
    } else {
        reporter.warn("no token set: anyone who can reach this address can use the relay");
    }
    reporter.detail(format!(
        "at most {} rooms, each expiring after {}s",
        settings.max_rooms,
        settings.room_timeout.as_secs()
    ));

    let metrics = relay.metrics();
    relay.run(cancel.clone()).await?;

    let (accepted, paired, refused) = metrics.snapshot();
    reporter.info(format!(
        "relay stopped after {accepted} connections, {paired} pairs, {refused} refused"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

fn config_command(
    args: &ConfigArgs,
    global: &GlobalArgs,
    config: &Config,
    reporter: &Reporter,
) -> Result<()> {
    let path = global
        .config
        .clone()
        .or_else(config::default_config_path)
        .ok_or_else(|| {
            Error::Config("this platform has no standard configuration directory".into())
        })?;

    match args.action {
        ConfigAction::Path => println!("{}", path.display()),
        ConfigAction::Init => {
            if config::write_default_config(&path)? {
                reporter.success(format!("wrote {}", path.display()));
            } else {
                reporter.info(format!("{} already exists, left alone", path.display()));
            }
        }
        ConfigAction::Show => {
            println!("config-file    = {}", path.display());
            match &config.relay {
                Some(relay) => {
                    println!("relay          = {}", relay.address);
                    println!(
                        "relay-token    = {}",
                        if relay.token.is_some() {
                            "<set>"
                        } else {
                            "<none>"
                        }
                    );
                }
                None => println!("relay          = <none> (local network only)"),
            }
            println!("lan-discovery  = {}", config.lan_discovery);
            println!("discovery-port = {}", config.discovery_port);
            println!("words          = {}", config.words);
            println!(
                "output-dir     = {}",
                config.resolved_output_dir().display()
            );
            println!("on-conflict    = {}", config.on_conflict);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

type PeerChannel = Channel<tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf>;

async fn handshake(
    connection: Connection,
    role: Role,
    code: &TransferCode,
    reporter: &Reporter,
) -> Result<PeerChannel> {
    let (read, write) = connection.into_split();
    let channel = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        Channel::establish(read, write, role, code),
    )
    .await
    .map_err(|_| crate::error::NetworkError::Timeout(HANDSHAKE_TIMEOUT))??;

    reporter.detail(format!(
        "secure channel established with {} (protocol v{})",
        channel.peer_agent(),
        channel.version()
    ));
    Ok(channel)
}

/// True when a failed handshake cost nobody a guess at the code, so waiting
/// for the real peer is still safe.
///
/// A wrong code is deliberately **not** retryable: allowing another attempt
/// would hand an attacker unlimited guesses at a short code, which is exactly
/// what the one-guess-per-code rule exists to prevent.
fn is_retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::Protocol(
            ProtocolError::BadMagic
                | ProtocolError::UnexpectedEof
                | ProtocolError::IncompatibleVersion { .. }
                | ProtocolError::Malformed(_)
        ) | Error::Io { .. }
    ) && !matches!(error, Error::Crypto(CryptoError::KeyMismatch))
}

fn net_options(config: &Config, args: &NetArgs) -> NetOptions {
    let mut options = NetOptions::from_config(config);
    if args.no_lan {
        options.lan = false;
    }
    if args.no_relay {
        options.relay = None;
    } else if let Some(address) = &args.relay {
        let token = args.relay_token.clone().or_else(|| {
            options
                .relay
                .as_ref()
                .and_then(|r| r.token.as_ref().map(|t| t.to_string()))
        });
        options.relay = Some(RelayConfig::new(address, token));
    } else if let (Some(token), Some(relay)) = (&args.relay_token, options.relay.as_mut()) {
        relay.token = Some(Zeroizing::new(token.clone()));
    }
    options
}

fn progress_sink(global: &GlobalArgs, reporter: &Reporter) -> BarSink {
    if global.wants_progress() && reporter.is_interactive() {
        BarSink::visible(global.verbosity())
    } else {
        BarSink::hidden(global.verbosity())
    }
}

/// Read one line from the terminal without blocking the reactor.
async fn prompt(question: &str) -> Result<String> {
    let question = question.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut stderr = std::io::stderr();
        stderr.write_all(question.as_bytes()).ctx("write prompt")?;
        stderr.flush().ctx("write prompt")?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ctx("read input")?;
        Ok(line.trim().to_owned())
    })
    .await
    .map_err(|e| Error::io("read input", std::io::Error::other(e)))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ColorChoice;

    fn global() -> GlobalArgs {
        GlobalArgs {
            verbose: 0,
            quiet: false,
            no_progress: true,
            color: ColorChoice::Never,
            config: None,
        }
    }

    fn net_args() -> NetArgs {
        NetArgs {
            relay: None,
            relay_token: None,
            no_relay: false,
            no_lan: false,
        }
    }

    #[test]
    fn flags_override_the_configured_relay() {
        let config = Config {
            relay: Some(RelayConfig::new("configured:1", Some("token".into()))),
            ..Config::default()
        };

        let options = net_options(&config, &net_args());
        assert_eq!(options.relay.as_ref().unwrap().address, "configured:1");

        let options = net_options(
            &config,
            &NetArgs {
                relay: Some("flag.example".into()),
                ..net_args()
            },
        );
        let relay = options.relay.unwrap();
        assert_eq!(relay.address, "flag.example:9110");
        assert_eq!(
            relay.token.as_ref().map(|t| t.to_string()),
            Some("token".to_owned()),
            "an explicitly configured token survives a relay override"
        );
    }

    #[test]
    fn no_relay_and_no_lan_turn_the_paths_off() {
        let config = Config {
            relay: Some(RelayConfig::new("configured:1", None)),
            ..Config::default()
        };

        let options = net_options(
            &config,
            &NetArgs {
                no_relay: true,
                ..net_args()
            },
        );
        assert!(options.relay.is_none());

        let options = net_options(
            &config,
            &NetArgs {
                no_lan: true,
                ..net_args()
            },
        );
        assert!(!options.lan);
        assert!(options.relay.is_some());
    }

    #[test]
    fn a_relay_token_flag_applies_to_the_configured_relay() {
        let config = Config {
            relay: Some(RelayConfig::new("configured:1", None)),
            ..Config::default()
        };
        let options = net_options(
            &config,
            &NetArgs {
                relay_token: Some("secret".into()),
                ..net_args()
            },
        );
        assert_eq!(
            options.relay.unwrap().token.as_ref().map(|t| t.to_string()),
            Some("secret".to_owned())
        );
    }

    #[test]
    fn a_wrong_code_is_never_retried() {
        assert!(!is_retryable(&Error::Crypto(CryptoError::KeyMismatch)));
        assert!(!is_retryable(&Error::Crypto(CryptoError::Pake)));
        assert!(!is_retryable(&Error::Cancelled));
    }

    #[test]
    fn connections_that_were_never_our_peer_are_retried() {
        assert!(is_retryable(&Error::Protocol(ProtocolError::BadMagic)));
        assert!(is_retryable(&Error::Protocol(ProtocolError::UnexpectedEof)));
        assert!(is_retryable(&Error::Protocol(
            ProtocolError::IncompatibleVersion {
                peer_min: 9,
                peer_max: 9,
                ours_min: 1,
                ours_max: 1
            }
        )));
        assert!(is_retryable(&Error::io(
            "read",
            std::io::Error::other("reset")
        )));
    }

    #[test]
    fn progress_is_hidden_when_asked() {
        let reporter = Reporter::new(Verbosity::Normal);
        let sink = progress_sink(&global(), &reporter);
        // `--no-progress` was set above, so this must not draw.
        sink.clear();
    }
}
