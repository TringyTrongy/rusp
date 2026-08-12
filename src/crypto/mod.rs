//! Cryptography.
//!
//! # What protects a transfer
//!
//! 1. **Key agreement.** The transfer code's secret words are the password in
//!    a [SPAKE2] exchange ([`pake`]). SPAKE2 is a balanced PAKE: the wire only
//!    carries blinded group elements, so neither a relay nor an eavesdropper
//!    can mount an offline dictionary attack on the code. Because the blinding
//!    scalars are ephemeral, recovering the code later does not reveal past
//!    session keys.
//!
//! 2. **Key schedule.** The SPAKE2 output is bound to a transcript hash of
//!    everything said before it — magic, negotiated version, both `Hello`
//!    messages, both SPAKE2 elements — and expanded with HKDF-SHA256 into four
//!    independent keys: one AEAD key per direction and one confirmation key
//!    per direction ([`keys`]).
//!
//! 3. **Key confirmation.** Before a single byte of user data moves, each side
//!    proves it derived the same keys with an HMAC-SHA256 tag over the
//!    transcript. A wrong code fails here and the transfer is abandoned, which
//!    is what limits an attacker to exactly one online guess per code.
//!
//! 4. **Record protection.** Every frame is sealed with ChaCha20-Poly1305
//!    ([`cipher`]) under a direction-specific key and a counter nonce. Distinct
//!    keys per direction mean the counters can start at zero without any risk
//!    of nonce reuse, and a monotonic counter makes reordering, replay,
//!    dropping and truncating frames all detectable.
//!
//! # What is deliberately not here
//!
//! No primitive in this module is home-made. SPAKE2, ChaCha20-Poly1305,
//! HKDF-SHA256, HMAC-SHA256 and BLAKE3 all come from established crates, used
//! in their intended configurations.
//!
//! [SPAKE2]: https://datatracker.ietf.org/doc/html/rfc9382

pub mod cipher;
pub mod keys;
pub mod pake;

pub use cipher::{OpeningKey, SealingKey, KEY_LEN, NONCE_LEN, TAG_LEN};
pub use keys::{confirm_tag, verify_confirm, SessionKeys, Transcript, CONFIRM_LEN};
pub use pake::PakeState;
