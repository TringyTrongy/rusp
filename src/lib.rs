//! Rusp — secure file transfer over a short human-friendly code.
//!
//! # Layering
//!
//! ```text
//!   cli  ──▶  app  ──▶  transfer  ──▶  protocol  ──▶  crypto  ──▶  net
//!                          │                                        │
//!                          └──▶ files                          discovery
//!                          └──▶ ui (progress events)             relay
//! ```
//!
//! Each layer only knows about the one beneath it:
//!
//! * [`net`] moves bytes. It knows nothing about files or messages.
//! * [`crypto`] turns a byte stream into an authenticated, encrypted one.
//! * [`protocol`] defines the versioned messages that stream carries.
//! * [`files`] handles the filesystem, including everything a hostile peer
//!   might put in a path.
//! * [`transfer`] drives sender and receiver state machines and emits
//!   [`transfer::progress`] events.
//! * [`ui`] renders those events. Nothing below it depends on a terminal.
//!
//! The library half of this crate has no terminal dependencies in its core
//! path, so a transfer can be driven from a test, a GUI, or a daemon.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod app;
pub mod cli;
pub mod code;
pub mod config;
pub mod error;
pub mod ui;

pub use code::TransferCode;
pub use config::Config;
pub use error::{Error, Result};

/// The version of the `rusp` crate, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
