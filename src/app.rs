//! Wiring between the parsed command line and the library.
//!
//! This is the only module that is allowed to combine configuration, terminal
//! output and the transfer engine. Keeping that in one place is what lets the
//! rest of the crate stay free of both `clap` and the terminal.

use crate::cli::{Cli, Command, ConfigAction, ConfigArgs, GlobalArgs};
use crate::config::{self, Config};
use crate::error::{Error, Result};
use crate::ui::{self, Reporter};

/// Execute a parsed command line.
pub fn run(cli: Cli) -> Result<()> {
    ui::set_color_choice(cli.global.color);
    let reporter = Reporter::new(cli.global.verbosity());
    let config = load_config(&cli.global)?;

    match &cli.command {
        Command::Config(args) => config_command(args, &cli.global, &config, &reporter),
        Command::Send(_) | Command::Receive(_) | Command::Relay(_) => Err(Error::Config(
            "this build does not have the transfer engine wired up yet".into(),
        )),
    }
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
        ConfigAction::Path => {
            println!("{}", path.display());
        }
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
