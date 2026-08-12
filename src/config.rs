//! Layered configuration.
//!
//! Settings come from four places, each overriding the one before it:
//!
//! 1. compiled-in defaults ([`Config::default`]),
//! 2. `$XDG_CONFIG_HOME/rusp/config.toml` (or the platform equivalent),
//! 3. `RUSP_*` environment variables,
//! 4. command-line flags.
//!
//! Layers 1-3 are resolved here; the CLI applies layer 4 on top of the result.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, IoContext, Result};

/// Port a Rusp relay listens on when the address does not name one.
pub const DEFAULT_RELAY_PORT: u16 = 9110;

/// UDP port used for LAN discovery announcements.
pub const DEFAULT_DISCOVERY_PORT: u16 = 9111;

/// Organisation-local IPv4 multicast group for LAN discovery.
pub const DISCOVERY_MULTICAST_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(239, 255, 83, 80);

/// Environment variable naming the relay to use.
pub const ENV_RELAY: &str = "RUSP_RELAY";
/// Environment variable holding a relay's shared access token.
pub const ENV_RELAY_TOKEN: &str = "RUSP_RELAY_TOKEN";
/// Environment variable pointing at an alternative config file.
pub const ENV_CONFIG: &str = "RUSP_CONFIG";
/// Environment variable setting the default receive directory.
pub const ENV_OUTPUT_DIR: &str = "RUSP_OUTPUT_DIR";

/// What to do when a file being received already exists on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictPolicy {
    /// Save alongside the existing file as `name (1).ext`.
    #[default]
    Rename,
    /// Replace the existing file.
    Overwrite,
    /// Leave the existing file alone and do not receive this one.
    Skip,
    /// Refuse the whole transfer.
    Fail,
}

impl std::fmt::Display for ConflictPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ConflictPolicy::Rename => "rename",
            ConflictPolicy::Overwrite => "overwrite",
            ConflictPolicy::Skip => "skip",
            ConflictPolicy::Fail => "fail",
        };
        f.write_str(s)
    }
}

/// How to reach a relay.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// `host:port`, already normalised to include a port.
    pub address: String,
    /// Optional shared token a private relay may require.
    pub token: Option<Zeroizing<String>>,
}

impl RelayConfig {
    /// Build a relay config, filling in [`DEFAULT_RELAY_PORT`] if absent.
    pub fn new(address: &str, token: Option<String>) -> Self {
        RelayConfig {
            address: normalize_relay_address(address),
            token: token.filter(|t| !t.is_empty()).map(Zeroizing::new),
        }
    }
}

/// Fully resolved configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Relay to fall back to when the peer is not on this network.
    pub relay: Option<RelayConfig>,
    /// Whether to announce/listen for peers on the local network.
    pub lan_discovery: bool,
    /// UDP port used by LAN discovery.
    pub discovery_port: u16,
    /// Words in a generated transfer code.
    pub words: usize,
    /// Where received files land when `--out` is not given.
    pub output_dir: Option<PathBuf>,
    /// Default behaviour for existing destination files.
    pub on_conflict: ConflictPolicy,
    /// How long to wait for a single connection attempt.
    pub connect_timeout: Duration,
    /// How long to wait for the other side to show up at all.
    pub rendezvous_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            relay: None,
            lan_discovery: true,
            discovery_port: DEFAULT_DISCOVERY_PORT,
            words: crate::code::DEFAULT_WORDS,
            output_dir: None,
            on_conflict: ConflictPolicy::default(),
            connect_timeout: Duration::from_secs(10),
            rendezvous_timeout: Duration::from_secs(300),
        }
    }
}

impl Config {
    /// Resolve defaults, then the config file, then the environment.
    pub fn load() -> Result<Self> {
        let path = std::env::var_os(ENV_CONFIG)
            .map(PathBuf::from)
            .or_else(default_config_path);
        let mut config = match path {
            Some(p) => Self::from_file(&p)?,
            None => Config::default(),
        };
        config.apply_env();
        Ok(config)
    }

    /// Resolve defaults and then a specific config file, skipping the
    /// environment. Used by tests and by `--config`.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            // A missing config file is the normal case, not an error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => return Err(Error::path("read config", path, e)),
        };
        let file: FileConfig = toml::from_str(&text).map_err(|e| {
            // `message()` is the human part ("unknown field `relayy`, expected
            // one of ..."); the full Display adds a source snippet that is
            // noise on a terminal.
            let where_ = match e.span() {
                Some(span) => format!(" (byte {})", span.start),
                None => String::new(),
            };
            Error::Config(format!(
                "{}{where_}: {}",
                path.display(),
                e.message().trim()
            ))
        })?;
        file.into_config(path)
    }

    /// Overlay `RUSP_*` environment variables.
    pub fn apply_env(&mut self) {
        if let Some(addr) = non_empty_env(ENV_RELAY) {
            let token = non_empty_env(ENV_RELAY_TOKEN).or_else(|| {
                self.relay
                    .as_ref()
                    .and_then(|r| r.token.as_ref().map(|t| t.to_string()))
            });
            self.relay = Some(RelayConfig::new(&addr, token));
        } else if let (Some(token), Some(relay)) =
            (non_empty_env(ENV_RELAY_TOKEN), self.relay.as_mut())
        {
            relay.token = Some(Zeroizing::new(token));
        }
        if let Some(dir) = non_empty_env(ENV_OUTPUT_DIR) {
            self.output_dir = Some(PathBuf::from(dir));
        }
    }

    /// Directory that received files go into, resolving the default.
    pub fn resolved_output_dir(&self) -> PathBuf {
        self.output_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

/// The on-disk shape of the config file. Every field optional so a partial
/// file is valid; unknown keys are rejected so typos surface immediately
/// instead of silently doing nothing.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct FileConfig {
    relay: Option<String>,
    relay_token: Option<String>,
    lan_discovery: Option<bool>,
    discovery_port: Option<u16>,
    words: Option<usize>,
    output_dir: Option<PathBuf>,
    on_conflict: Option<ConflictPolicy>,
    connect_timeout_secs: Option<u64>,
    rendezvous_timeout_secs: Option<u64>,
}

impl FileConfig {
    fn into_config(self, path: &Path) -> Result<Config> {
        let defaults = Config::default();
        let words = self.words.unwrap_or(defaults.words);
        if !(crate::code::MIN_WORDS..=crate::code::MAX_WORDS).contains(&words) {
            return Err(Error::Config(format!(
                "{}: `words` must be between {} and {}, got {words}",
                path.display(),
                crate::code::MIN_WORDS,
                crate::code::MAX_WORDS,
            )));
        }
        Ok(Config {
            relay: self
                .relay
                .filter(|r| !r.is_empty())
                .map(|addr| RelayConfig::new(&addr, self.relay_token)),
            lan_discovery: self.lan_discovery.unwrap_or(defaults.lan_discovery),
            discovery_port: self.discovery_port.unwrap_or(defaults.discovery_port),
            words,
            output_dir: self.output_dir,
            on_conflict: self.on_conflict.unwrap_or(defaults.on_conflict),
            connect_timeout: self
                .connect_timeout_secs
                .map(Duration::from_secs)
                .unwrap_or(defaults.connect_timeout),
            rendezvous_timeout: self
                .rendezvous_timeout_secs
                .map(Duration::from_secs)
                .unwrap_or(defaults.rendezvous_timeout),
        })
    }
}

/// `~/.config/rusp/config.toml` and platform equivalents.
pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("rusp").join("config.toml"))
}

/// Append [`DEFAULT_RELAY_PORT`] when the address does not carry one, taking
/// care not to mangle bare or bracketed IPv6 literals.
pub fn normalize_relay_address(addr: &str) -> String {
    let addr = addr.trim();
    if addr.starts_with('[') {
        // `[::1]` or `[::1]:9110`
        return match addr.rfind("]:") {
            Some(_) => addr.to_owned(),
            None => format!("{addr}:{DEFAULT_RELAY_PORT}"),
        };
    }
    match addr.matches(':').count() {
        0 => format!("{addr}:{DEFAULT_RELAY_PORT}"),
        1 => addr.to_owned(),
        // Bare IPv6 literal such as `::1` or `fe80::1`.
        _ => format!("[{addr}]:{DEFAULT_RELAY_PORT}"),
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Write a commented starter config to `path`, creating parent directories.
/// Never overwrites an existing file.
pub fn write_default_config(path: &Path) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).path_ctx("create", parent)?;
    }
    std::fs::write(path, DEFAULT_CONFIG_TEMPLATE).path_ctx("write", path)?;
    Ok(true)
}

const DEFAULT_CONFIG_TEMPLATE: &str = concat!(
    "# Rusp configuration. Every key is optional.\n",
    "\n",
    "# Relay used when the other machine is not on this network.\n",
    "# Rusp ships with no default relay: run `rusp relay` somewhere reachable.\n",
    "# relay = \"relay.example.com:9110\"\n",
    "# relay-token = \"shared secret required by that relay\"\n",
    "\n",
    "# Announce and look for peers on the local network (no relay needed).\n",
    "# lan-discovery = true\n",
    "# discovery-port = 9111\n",
    "\n",
    "# Words in a generated transfer code (3-12). Each word is 10 bits.\n",
    "# words = 4\n",
    "\n",
    "# Where received files are written, and what to do about collisions:\n",
    "# rename | overwrite | skip | fail\n",
    "# output-dir = \"~/Downloads\"\n",
    "# on-conflict = \"rename\"\n",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert!(c.relay.is_none(), "no third-party relay may be baked in");
        assert!(c.lan_discovery);
        assert_eq!(c.words, crate::code::DEFAULT_WORDS);
        assert_eq!(c.on_conflict, ConflictPolicy::Rename);
    }

    #[test]
    fn missing_config_file_is_not_an_error() {
        let c = Config::from_file(Path::new("/nonexistent/rusp/config.toml")).unwrap();
        assert_eq!(c.words, Config::default().words);
    }

    #[test]
    fn config_file_overrides_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "relay = \"example.test\"\nwords = 6\non-conflict = \"overwrite\"\nlan-discovery = false\n",
        )
        .unwrap();
        let c = Config::from_file(&path).unwrap();
        assert_eq!(c.relay.unwrap().address, "example.test:9110");
        assert_eq!(c.words, 6);
        assert_eq!(c.on_conflict, ConflictPolicy::Overwrite);
        assert!(!c.lan_discovery);
    }

    #[test]
    fn typos_in_config_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "relayy = \"example.test\"\n").unwrap();
        let err = Config::from_file(&path).unwrap_err().to_string();
        assert!(err.contains("relayy"), "{err}");
    }

    #[test]
    fn out_of_range_word_count_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "words = 99\n").unwrap();
        assert!(Config::from_file(&path).is_err());
    }

    #[test]
    fn relay_addresses_get_a_port() {
        assert_eq!(normalize_relay_address("host"), "host:9110");
        assert_eq!(normalize_relay_address("host:1234"), "host:1234");
        assert_eq!(normalize_relay_address("1.2.3.4"), "1.2.3.4:9110");
        assert_eq!(normalize_relay_address("1.2.3.4:99"), "1.2.3.4:99");
        assert_eq!(normalize_relay_address("::1"), "[::1]:9110");
        assert_eq!(normalize_relay_address("[::1]:99"), "[::1]:99");
        assert_eq!(normalize_relay_address("[fe80::1]"), "[fe80::1]:9110");
        assert_eq!(normalize_relay_address("  host  "), "host:9110");
    }

    #[test]
    fn relay_token_is_dropped_when_blank() {
        assert!(RelayConfig::new("h", Some(String::new())).token.is_none());
        assert!(RelayConfig::new("h", None).token.is_none());
        assert!(RelayConfig::new("h", Some("t".into())).token.is_some());
    }

    #[test]
    fn starter_config_is_valid_and_never_clobbers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert!(write_default_config(&path).unwrap());
        assert!(!write_default_config(&path).unwrap());
        // The template is entirely comments, so it must parse to defaults.
        let c = Config::from_file(&path).unwrap();
        assert_eq!(c.words, Config::default().words);
    }
}
