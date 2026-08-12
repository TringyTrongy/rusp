//! Drawing transfer progress.
//!
//! This is the only place that knows a progress bar exists. It consumes the
//! [`Event`]s the transfer engine emits and turns them into a bar, a rate and
//! an ETA.
//!
//! Redraws are capped at [`REFRESH_HZ`]. The engine emits an event per chunk,
//! which at a gigabit is thousands per second; redrawing that often would cost
//! more than the transfer.

use std::borrow::Cow;

use console::style;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use crate::cli::Verbosity;
use crate::transfer::progress::{Event, ProgressSink};
use crate::ui::human_bytes;

/// Most redraws per second.
pub const REFRESH_HZ: u8 = 12;

/// Longest file name shown next to the bar before it is shortened.
const MAX_NAME: usize = 40;

const TEMPLATE: &str =
    "{spinner:.cyan} [{bar:28.cyan/blue}] {bytes}/{total_bytes}  {binary_bytes_per_sec}  eta {eta}  {msg}";

/// Renders transfer events as a progress bar on stderr.
#[derive(Debug)]
pub struct BarSink {
    bar: ProgressBar,
    verbosity: Verbosity,
    /// True when the bar is not being drawn, in which case status lines have
    /// to go to stderr directly — a hidden bar swallows `println`.
    hidden: bool,
}

impl BarSink {
    /// Create a bar that draws to stderr.
    pub fn visible(verbosity: Verbosity) -> Self {
        let bar =
            ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::stderr_with_hz(REFRESH_HZ));
        bar.set_style(
            ProgressStyle::with_template(TEMPLATE)
                // A broken template is a programming error, not something to
                // fail a transfer over: fall back and carry on.
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=> "),
        );
        BarSink {
            bar,
            verbosity,
            hidden: false,
        }
    }

    /// Create a sink that draws nothing but still tracks state, for
    /// `--no-progress`, `--quiet` and non-terminal output.
    pub fn hidden(verbosity: Verbosity) -> Self {
        BarSink {
            bar: ProgressBar::hidden(),
            verbosity,
            hidden: true,
        }
    }

    /// Print a line without the bar getting in the way.
    ///
    /// A hidden `ProgressBar` discards what it is given, so when nothing is
    /// being drawn the line goes straight to stderr instead — otherwise
    /// `--no-progress -v` would silently produce no output at all.
    pub fn println(&self, line: impl AsRef<str>) {
        if self.hidden {
            use std::io::Write;
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "{}", line.as_ref());
        } else {
            self.bar.println(line);
        }
    }

    /// Run `f` with the bar temporarily cleared, for prompts.
    pub fn suspend<T>(&self, f: impl FnOnce() -> T) -> T {
        self.bar.suspend(f)
    }

    /// Remove the bar from the terminal.
    pub fn clear(&self) {
        self.bar.finish_and_clear();
    }
}

impl ProgressSink for BarSink {
    fn event(&self, event: Event) {
        match event {
            Event::Started { files, bytes } => {
                self.bar.set_length(bytes);
                self.bar.set_position(0);
                self.bar
                    .enable_steady_tick(std::time::Duration::from_millis(1000 / REFRESH_HZ as u64));
                if self.verbosity.allows(Verbosity::Verbose) {
                    self.println(format!(
                        "{} {} in {}",
                        style("transferring").dim(),
                        human_bytes(bytes),
                        crate::ui::plural(files as usize, "file", "files")
                    ));
                }
            }
            Event::FileStarted { path, .. } => {
                self.bar.set_message(shorten(&path));
            }
            Event::Advanced { bytes } => {
                self.bar.inc(bytes);
            }
            Event::FileFinished { path, .. } => {
                if self.verbosity.allows(Verbosity::Verbose) {
                    self.println(format!("  {} {path}", style("✓").green()));
                }
            }
            Event::FileSkipped { path, reason, .. } => {
                // Skips change what the user ends up with, so they are worth
                // saying out loud even at the default verbosity.
                if self.verbosity.allows(Verbosity::Normal) {
                    self.println(format!("  {} {path} ({reason})", style("skipped").yellow()));
                }
            }
            Event::DirectoryCreated { path } => {
                if self.verbosity.allows(Verbosity::Trace) {
                    self.println(format!("  {} {path}/", style("created").dim()));
                }
            }
            Event::Finished { .. } => {
                self.bar.finish_and_clear();
            }
        }
    }
}

/// Shorten a path for display, keeping the end, which is the part that
/// identifies the file.
fn shorten(path: &str) -> Cow<'static, str> {
    let chars = path.chars().count();
    if chars <= MAX_NAME {
        return Cow::Owned(path.to_owned());
    }
    let tail: String = path
        .chars()
        .skip(chars.saturating_sub(MAX_NAME - 1))
        .collect();
    Cow::Owned(format!("…{tail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names_are_left_alone() {
        assert_eq!(shorten("a.txt"), "a.txt");
        assert_eq!(shorten(&"a".repeat(MAX_NAME)), "a".repeat(MAX_NAME));
    }

    #[test]
    fn long_names_keep_their_end() {
        let long = format!("{}/interesting-part.txt", "deep/".repeat(30));
        let short = shorten(&long);
        assert_eq!(short.chars().count(), MAX_NAME);
        assert!(short.starts_with('…'));
        assert!(short.ends_with("interesting-part.txt"), "{short}");
    }

    #[test]
    fn shortening_handles_multibyte_characters() {
        // Slicing by bytes here would panic; counting characters must not.
        let long = "日本語のとても長いファイル名".repeat(5);
        let short = shorten(&long);
        assert_eq!(short.chars().count(), MAX_NAME);
    }

    #[test]
    fn a_hidden_sink_still_reports_lines() {
        // Regression: a hidden `ProgressBar` swallows `println`, which used to
        // mean `--no-progress --verbose` printed nothing.
        assert!(BarSink::hidden(Verbosity::Verbose).hidden);
        assert!(!BarSink::visible(Verbosity::Verbose).hidden);
    }

    #[test]
    fn a_hidden_bar_accepts_every_event() {
        let sink = BarSink::hidden(Verbosity::Trace);
        for event in [
            Event::Started {
                files: 2,
                bytes: 100,
            },
            Event::FileStarted {
                index: 0,
                path: "a.txt".into(),
                size: 50,
            },
            Event::Advanced { bytes: 50 },
            Event::FileFinished {
                index: 0,
                path: "a.txt".into(),
            },
            Event::FileSkipped {
                index: 1,
                path: "b.txt".into(),
                reason: "already exists".into(),
            },
            Event::DirectoryCreated { path: "d".into() },
            Event::Finished {
                files: 1,
                bytes: 50,
                skipped: 1,
            },
        ] {
            sink.event(event);
        }
        sink.clear();
    }

    #[test]
    fn the_template_is_valid() {
        assert!(
            ProgressStyle::with_template(TEMPLATE).is_ok(),
            "the shipped template must parse"
        );
    }
}
