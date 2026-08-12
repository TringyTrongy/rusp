//! Progress reporting, without a terminal in sight.
//!
//! The transfer engine emits [`Event`]s to a [`ProgressSink`]. It has no idea
//! whether something is drawing a bar, writing a log, or throwing them away,
//! which is what lets the whole engine be tested with no TTY.

use std::sync::atomic::{AtomicU64, Ordering};

/// Something that happened during a transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The two sides agreed on what will move.
    Started {
        /// Number of files that will be transferred.
        files: u32,
        /// Total bytes across those files.
        bytes: u64,
    },
    /// Work has begun on a file.
    FileStarted {
        /// Index into the manifest.
        index: u32,
        /// Relative path, as it appears in the manifest.
        path: String,
        /// Size in bytes.
        size: u64,
    },
    /// More bytes of the current file have moved.
    Advanced {
        /// Bytes since the last `Advanced` event.
        bytes: u64,
    },
    /// A file is complete and verified.
    FileFinished {
        /// Index into the manifest.
        index: u32,
        /// Relative path.
        path: String,
    },
    /// A file was deliberately not transferred.
    FileSkipped {
        /// Index into the manifest.
        index: u32,
        /// Relative path.
        path: String,
        /// Why it was skipped, in words.
        reason: String,
    },
    /// A directory was created.
    DirectoryCreated {
        /// Relative path.
        path: String,
    },
    /// Everything is done.
    Finished {
        /// Files transferred.
        files: u32,
        /// Bytes transferred.
        bytes: u64,
        /// Files deliberately skipped.
        skipped: u32,
    },
}

/// Somewhere for [`Event`]s to go.
///
/// Takes `&self` so a sink can be shared between tasks; implementations use
/// interior mutability if they need state.
pub trait ProgressSink: Send + Sync {
    /// Handle one event.
    fn event(&self, event: Event);
}

/// Throws everything away. The default when nothing is watching.
#[derive(Debug, Clone, Copy, Default)]
pub struct Silent;

impl ProgressSink for Silent {
    fn event(&self, _event: Event) {}
}

impl<T: ProgressSink + ?Sized> ProgressSink for &T {
    fn event(&self, event: Event) {
        (**self).event(event)
    }
}

/// Counts bytes and files. Useful on its own, and in tests.
#[derive(Debug, Default)]
pub struct Counters {
    /// Bytes moved.
    pub bytes: AtomicU64,
    /// Files completed.
    pub files: AtomicU64,
    /// Files skipped.
    pub skipped: AtomicU64,
}

impl ProgressSink for Counters {
    fn event(&self, event: Event) {
        match event {
            Event::Advanced { bytes } => {
                self.bytes.fetch_add(bytes, Ordering::Relaxed);
            }
            Event::FileFinished { .. } => {
                self.files.fetch_add(1, Ordering::Relaxed);
            }
            Event::FileSkipped { .. } => {
                self.skipped.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

impl Counters {
    /// Read the counters as `(bytes, files, skipped)`.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.bytes.load(Ordering::Relaxed),
            self.files.load(Ordering::Relaxed),
            self.skipped.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_add_up() {
        let counters = Counters::default();
        counters.event(Event::Started {
            files: 2,
            bytes: 30,
        });
        counters.event(Event::Advanced { bytes: 10 });
        counters.event(Event::Advanced { bytes: 20 });
        counters.event(Event::FileFinished {
            index: 0,
            path: "a".into(),
        });
        counters.event(Event::FileSkipped {
            index: 1,
            path: "b".into(),
            reason: "exists".into(),
        });
        assert_eq!(counters.snapshot(), (30, 1, 1));
    }

    #[test]
    fn a_silent_sink_accepts_anything() {
        let sink = Silent;
        sink.event(Event::Finished {
            files: 0,
            bytes: 0,
            skipped: 0,
        });
    }

    #[test]
    fn sinks_work_behind_a_reference() {
        fn takes_sink(sink: &dyn ProgressSink) {
            sink.event(Event::Advanced { bytes: 1 });
        }
        let counters = Counters::default();
        takes_sink(&counters);
        assert_eq!(counters.snapshot().0, 1);
    }
}
