//! Filesystem handling for both ends of a transfer.
//!
//! * [`scan()`] walks what the user named on the command line into a manifest.
//! * [`safe_path`] decides whether a path a stranger sent us may touch the
//!   disk at all.
//! * [`writer`] puts received bytes on disk without ever leaving a
//!   half-written file under a finished name.

pub mod safe_path;
pub mod scan;
pub mod writer;

pub use safe_path::{resolve, validate};
pub use scan::{scan, Scan, ScanOptions, Source};
pub use writer::{Destination, FileWriter};
