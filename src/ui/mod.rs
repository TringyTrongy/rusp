//! Terminal presentation.
//!
//! Everything that writes to a terminal lives here. The transfer core emits
//! plain data — progress events and errors — and this module decides how it
//! looks. Nothing below `ui` depends on `console` or `indicatif`, so the
//! protocol and transfer layers can be tested without a TTY.

pub mod progress;

use std::error::Error as StdError;
use std::io::{IsTerminal, Write};

use console::style;

use crate::cli::{ColorChoice, Verbosity};
use crate::error::Error;

/// Apply the requested colour policy process-wide.
pub fn set_color_choice(choice: ColorChoice) {
    match choice {
        // `console` already inspects TERM, NO_COLOR and whether stderr is a
        // terminal, which is exactly what "auto" should mean.
        ColorChoice::Auto => {}
        ColorChoice::Always => console::set_colors_enabled(true),
        ColorChoice::Never => console::set_colors_enabled(false),
    }
}

/// Print a failure to stderr in a form a non-programmer can act on.
///
/// Shows the error, then any underlying causes indented beneath it, then a
/// hint when one exists. No backtraces, no `Debug` output.
pub fn report_error(err: &Error) {
    let mut stderr = std::io::stderr().lock();
    if err.is_cancelled() {
        let _ = writeln!(stderr, "{} transfer cancelled", style("×").yellow().bold());
        return;
    }

    let _ = writeln!(stderr, "{} {err}", style("error:").red().bold());

    let mut source = err.source();
    while let Some(cause) = source {
        // `Error::Io` already folds its source into the message.
        let text = cause.to_string();
        if !err.to_string().contains(&text) {
            let _ = writeln!(stderr, "  {} {text}", style("caused by:").dim());
        }
        source = cause.source();
    }

    if let Some(hint) = err.hint() {
        let _ = writeln!(stderr, "{} {hint}", style("hint:").cyan().bold());
    }
}

/// Writes status lines at a given verbosity.
///
/// Output goes to stderr so that stdout stays clean for anything scriptable.
#[derive(Debug, Clone)]
pub struct Reporter {
    verbosity: Verbosity,
}

impl Reporter {
    /// Create a reporter for the given verbosity.
    pub fn new(verbosity: Verbosity) -> Self {
        Reporter { verbosity }
    }

    /// The verbosity this reporter was built with.
    pub fn verbosity(&self) -> Verbosity {
        self.verbosity
    }

    /// True when stderr is an interactive terminal.
    pub fn is_interactive(&self) -> bool {
        std::io::stderr().is_terminal()
    }

    /// A normal progress-of-the-operation line.
    pub fn info(&self, msg: impl std::fmt::Display) {
        self.at(Verbosity::Normal, format_args!("{msg}"));
    }

    /// A line only shown with `-v`.
    pub fn detail(&self, msg: impl std::fmt::Display) {
        self.at(Verbosity::Verbose, format_args!("{}", style(msg).dim()));
    }

    /// A line only shown with `-vv`.
    pub fn trace(&self, msg: impl std::fmt::Display) {
        self.at(Verbosity::Trace, format_args!("{}", style(msg).dim()));
    }

    /// Something went sideways but the operation continues.
    pub fn warn(&self, msg: impl std::fmt::Display) {
        // Warnings survive --quiet: they usually explain a surprising result.
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{} {msg}", style("warning:").yellow().bold());
    }

    /// The operation finished.
    pub fn success(&self, msg: impl std::fmt::Display) {
        self.at(
            Verbosity::Normal,
            format_args!("{} {msg}", style("✓").green().bold()),
        );
    }

    fn at(&self, level: Verbosity, args: std::fmt::Arguments<'_>) {
        if self.verbosity.allows(level) {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "{args}");
        }
    }
}

/// Format a byte count the way a person would say it.
///
/// Uses binary units, one decimal place above `KiB`, and never says `1.0 KiB`
/// where `1024 B` is clearer.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Format a count with its noun, pluralised.
pub fn plural(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_formatting() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1), "1 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(102400), "100 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(human_bytes(10 * 1024 * 1024 * 1024), "10.0 GiB");
        // Saturates at the largest unit we name rather than inventing one.
        assert_eq!(human_bytes(u64::MAX), "16384 PiB");
    }

    #[test]
    fn pluralisation() {
        assert_eq!(plural(1, "file", "files"), "1 file");
        assert_eq!(plural(0, "file", "files"), "0 files");
        assert_eq!(plural(2, "file", "files"), "2 files");
    }

    #[test]
    fn reporter_respects_verbosity() {
        assert!(Reporter::new(Verbosity::Normal)
            .verbosity()
            .allows(Verbosity::Normal));
        assert!(!Reporter::new(Verbosity::Quiet)
            .verbosity()
            .allows(Verbosity::Normal));
        assert!(Reporter::new(Verbosity::Trace)
            .verbosity()
            .allows(Verbosity::Verbose));
    }
}
