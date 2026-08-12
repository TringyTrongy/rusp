//! Driving a transfer from end to end.
//!
//! [`sender`] and [`receiver`] are the two state machines. They talk over a
//! [`Channel`](crate::protocol::channel::Channel) and report what they are
//! doing through a [`progress::ProgressSink`], so neither knows anything about
//! terminals, prompts, or how the connection was made.

pub mod progress;
pub mod receiver;
pub mod sender;

pub use progress::{Event, ProgressSink, Silent};
pub use receiver::{begin, PendingOffer, Plan, ReceiveOptions, ReceiveReport};
pub use sender::{send, SendReport};
