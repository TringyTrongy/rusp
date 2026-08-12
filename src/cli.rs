//! Command-line surface.
//!
//! This module is pure argument parsing and normalisation: it turns `argv` into
//! plain data. It does no I/O and knows nothing about transfers, so the CLI can
//! be exercised in unit tests without a network.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::code::{MAX_WORDS, MIN_WORDS};
use crate::config::{ConflictPolicy, DEFAULT_RELAY_PORT};

const AFTER_HELP: &str = "\
Examples:
  rusp send report.pdf                 send one file
  rusp send a.jpg b.jpg notes.txt      send several
  rusp send ./photos                   send a directory, recursively
  rusp receive                         prompt for a code, then receive
  rusp receive k7m2-cotton-harbor-tiger-pencil
  rusp relay --listen 0.0.0.0:9110     run a relay for two networks

Rusp finds peers on the local network by itself. Transfers between different
networks need a relay: run `rusp relay` on a reachable host and point both
sides at it with --relay or RUSP_RELAY.";

/// Secure file transfer over a short human-friendly code.
#[derive(Debug, Parser)]
#[command(
    name = "rusp",
    version,
    about,
    after_help = AFTER_HELP,
    disable_help_subcommand = true,
    propagate_version = true
)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,

    /// Options accepted before or after the subcommand.
    #[command(flatten)]
    pub global: GlobalArgs,
}

/// Options that apply to every subcommand.
#[derive(Debug, Args, Clone)]
pub struct GlobalArgs {
    /// Print more detail; repeat for protocol-level tracing.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Print nothing but errors.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Do not draw progress bars (implied by --quiet and by non-terminal output).
    #[arg(long, global = true)]
    pub no_progress: bool,

    /// When to colourise output.
    #[arg(long, global = true, value_name = "WHEN", default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,

    /// Read configuration from this file instead of the default location.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
}

impl GlobalArgs {
    /// Collapse the verbosity flags into a single level.
    pub fn verbosity(&self) -> Verbosity {
        if self.quiet {
            Verbosity::Quiet
        } else {
            match self.verbose {
                0 => Verbosity::Normal,
                1 => Verbosity::Verbose,
                _ => Verbosity::Trace,
            }
        }
    }

    /// Whether progress bars should be drawn at all, ignoring TTY detection
    /// (which the UI layer applies separately).
    pub fn wants_progress(&self) -> bool {
        !self.no_progress && !self.quiet
    }
}

/// How chatty to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    /// Errors only.
    Quiet,
    /// The default: what is happening, and how far along it is.
    Normal,
    /// Adds connection details and per-file lines.
    Verbose,
    /// Adds protocol message tracing.
    Trace,
}

impl Verbosity {
    /// True when messages at `at_least` should be printed.
    pub fn allows(self, at_least: Verbosity) -> bool {
        self >= at_least
    }
}

/// Colour policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum ColorChoice {
    /// Colour when writing to a terminal.
    #[default]
    Auto,
    /// Always colour.
    Always,
    /// Never colour.
    Never,
}

impl std::fmt::Display for ColorChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ColorChoice::Auto => "auto",
            ColorChoice::Always => "always",
            ColorChoice::Never => "never",
        })
    }
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Send files or directories.
    #[command(visible_alias = "tx")]
    Send(SendArgs),

    /// Receive files using a transfer code.
    #[command(visible_alias = "recv")]
    Receive(ReceiveArgs),

    /// Run a relay so two machines on different networks can meet.
    Relay(RelayArgs),

    /// Inspect or create the configuration file.
    Config(ConfigArgs),
}

/// Arguments for `rusp send`.
#[derive(Debug, Args)]
pub struct SendArgs {
    /// Files and directories to send.
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Use this code instead of generating one.
    #[arg(long, value_name = "CODE")]
    pub code: Option<String>,

    /// Number of words in the generated code.
    #[arg(short = 'w', long, value_name = "N", value_parser = word_count_parser)]
    pub words: Option<usize>,

    /// Send the contents of symlinked files instead of skipping them.
    #[arg(long)]
    pub follow_symlinks: bool,

    /// Connection options.
    #[command(flatten)]
    pub net: NetArgs,
}

/// Arguments for `rusp receive`.
#[derive(Debug, Args)]
pub struct ReceiveArgs {
    /// The transfer code. Prompted for if omitted.
    #[arg(value_name = "CODE")]
    pub code: Option<String>,

    /// Directory to write into.
    #[arg(short, long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// What to do when a file already exists.
    #[arg(long, value_name = "POLICY", conflicts_with = "overwrite")]
    pub on_conflict: Option<ConflictPolicy>,

    /// Shorthand for --on-conflict overwrite.
    #[arg(long)]
    pub overwrite: bool,

    /// Accept the offer without asking.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Connection options.
    #[command(flatten)]
    pub net: NetArgs,
}

/// Connection options shared by `send` and `receive`.
#[derive(Debug, Args, Clone)]
pub struct NetArgs {
    /// Relay to use, as `host` or `host:port`.
    #[arg(long, value_name = "ADDR")]
    pub relay: Option<String>,

    /// Token required by a private relay.
    #[arg(long, value_name = "TOKEN")]
    pub relay_token: Option<String>,

    /// Do not use a relay, even if one is configured.
    #[arg(long, conflicts_with_all = ["relay", "relay_token"])]
    pub no_relay: bool,

    /// Do not look for the peer on the local network.
    #[arg(long)]
    pub no_lan: bool,
}

/// Arguments for `rusp relay`.
#[derive(Debug, Args)]
pub struct RelayArgs {
    /// Address to listen on.
    #[arg(short, long, value_name = "ADDR", default_value_t = default_relay_listen())]
    pub listen: String,

    /// Require this token from every client.
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    /// Maximum number of rooms waiting for a second peer.
    #[arg(long, value_name = "N", default_value_t = 1024)]
    pub max_rooms: usize,

    /// Seconds a half-open room is kept before it is dropped.
    #[arg(long, value_name = "SECS", default_value_t = 600)]
    pub room_timeout: u64,
}

/// Arguments for `rusp config`.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Config action.
    #[command(subcommand)]
    pub action: ConfigAction,
}

/// What to do with the configuration file.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum ConfigAction {
    /// Print the resolved settings.
    Show,
    /// Print the path of the configuration file.
    Path,
    /// Write a commented starter configuration file.
    Init,
}

fn default_relay_listen() -> String {
    format!("0.0.0.0:{DEFAULT_RELAY_PORT}")
}

fn word_count_parser(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("`{s}` is not a number of words"))?;
    if (MIN_WORDS..=MAX_WORDS).contains(&n) {
        Ok(n)
    } else {
        Err(format!("choose between {MIN_WORDS} and {MAX_WORDS} words"))
    }
}

// `ConflictPolicy` lives in `config` so that module stays free of clap; the
// trait impl lives here so the coupling points the right way.
impl ValueEnum for ConflictPolicy {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            ConflictPolicy::Rename,
            ConflictPolicy::Overwrite,
            ConflictPolicy::Skip,
            ConflictPolicy::Fail,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        use clap::builder::PossibleValue;
        Some(match self {
            ConflictPolicy::Rename => {
                PossibleValue::new("rename").help("keep both, saving as `name (1).ext`")
            }
            ConflictPolicy::Overwrite => {
                PossibleValue::new("overwrite").help("replace the existing file")
            }
            ConflictPolicy::Skip => PossibleValue::new("skip").help("keep the existing file"),
            ConflictPolicy::Fail => {
                PossibleValue::new("fail").help("refuse the transfer if anything would be replaced")
            }
        })
    }
}

impl ReceiveArgs {
    /// The conflict policy the user asked for, if any.
    pub fn conflict_policy(&self) -> Option<ConflictPolicy> {
        if self.overwrite {
            Some(ConflictPolicy::Overwrite)
        } else {
            self.on_conflict
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn send_takes_several_paths() {
        let cli = parse(&["rusp", "send", "a.txt", "b.txt", "dir"]);
        let Command::Send(args) = cli.command else {
            panic!("expected send")
        };
        assert_eq!(args.paths.len(), 3);
        assert_eq!(args.paths[2], PathBuf::from("dir"));
        assert!(!args.follow_symlinks);
    }

    #[test]
    fn send_requires_a_path() {
        assert!(Cli::try_parse_from(["rusp", "send"]).is_err());
    }

    #[test]
    fn aliases_work() {
        assert!(matches!(
            parse(&["rusp", "tx", "a.txt"]).command,
            Command::Send(_)
        ));
        assert!(matches!(
            parse(&["rusp", "recv"]).command,
            Command::Receive(_)
        ));
    }

    #[test]
    fn word_count_is_range_checked() {
        assert!(Cli::try_parse_from(["rusp", "send", "-w", "2", "a"]).is_err());
        assert!(Cli::try_parse_from(["rusp", "send", "-w", "99", "a"]).is_err());
        assert!(Cli::try_parse_from(["rusp", "send", "-w", "x", "a"]).is_err());
        let cli = parse(&["rusp", "send", "-w", "6", "a"]);
        let Command::Send(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.words, Some(6));
    }

    #[test]
    fn global_flags_work_on_either_side_of_the_subcommand() {
        for args in [
            &["rusp", "--verbose", "send", "a.txt"],
            &["rusp", "send", "--verbose", "a.txt"],
        ] {
            assert_eq!(parse(args).global.verbosity(), Verbosity::Verbose);
        }
    }

    #[test]
    fn verbosity_levels() {
        assert_eq!(
            parse(&["rusp", "send", "a"]).global.verbosity(),
            Verbosity::Normal
        );
        assert_eq!(
            parse(&["rusp", "-q", "send", "a"]).global.verbosity(),
            Verbosity::Quiet
        );
        assert_eq!(
            parse(&["rusp", "-vv", "send", "a"]).global.verbosity(),
            Verbosity::Trace
        );
        assert!(Cli::try_parse_from(["rusp", "-q", "-v", "send", "a"]).is_err());
        assert!(Verbosity::Verbose.allows(Verbosity::Normal));
        assert!(!Verbosity::Quiet.allows(Verbosity::Normal));
    }

    #[test]
    fn quiet_disables_progress() {
        assert!(!parse(&["rusp", "-q", "send", "a"]).global.wants_progress());
        assert!(!parse(&["rusp", "send", "--no-progress", "a"])
            .global
            .wants_progress());
        assert!(parse(&["rusp", "send", "a"]).global.wants_progress());
    }

    #[test]
    fn receive_conflict_shorthands() {
        let cli = parse(&["rusp", "receive", "--overwrite"]);
        let Command::Receive(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.conflict_policy(), Some(ConflictPolicy::Overwrite));

        let cli = parse(&["rusp", "receive", "--on-conflict", "skip"]);
        let Command::Receive(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.conflict_policy(), Some(ConflictPolicy::Skip));

        let cli = parse(&["rusp", "receive"]);
        let Command::Receive(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.conflict_policy(), None);

        assert!(
            Cli::try_parse_from(["rusp", "receive", "--overwrite", "--on-conflict", "skip"])
                .is_err()
        );
    }

    #[test]
    fn receive_code_is_optional_and_positional() {
        let cli = parse(&["rusp", "receive", "k7m2-cotton-harbor-tiger"]);
        let Command::Receive(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.code.as_deref(), Some("k7m2-cotton-harbor-tiger"));
    }

    #[test]
    fn no_relay_conflicts_with_relay() {
        assert!(Cli::try_parse_from(["rusp", "receive", "--no-relay", "--relay", "h:1"]).is_err());
        assert!(Cli::try_parse_from(["rusp", "receive", "--no-relay"]).is_ok());
    }

    #[test]
    fn relay_defaults_to_all_interfaces_on_the_rusp_port() {
        let cli = parse(&["rusp", "relay"]);
        let Command::Relay(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.listen, format!("0.0.0.0:{DEFAULT_RELAY_PORT}"));
        assert_eq!(args.max_rooms, 1024);
    }

    #[test]
    fn config_actions() {
        let cli = parse(&["rusp", "config", "init"]);
        let Command::Config(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.action, ConfigAction::Init);
        assert!(Cli::try_parse_from(["rusp", "config"]).is_err());
    }
}
