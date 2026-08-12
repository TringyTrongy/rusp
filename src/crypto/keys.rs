//! Transcript hashing, key derivation and key confirmation.

use hkdf::Hkdf;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::cipher::KEY_LEN;
use crate::error::CryptoError;
use crate::protocol::Role;

type HmacSha256 = Hmac<Sha256>;

/// Length of a key-confirmation tag.
pub const CONFIRM_LEN: usize = 32;

/// Domain separator, so a Rusp transcript can never collide with another
/// protocol that happens to hash similar material.
const DOMAIN: &[u8] = b"rusp transcript v1";

/// A running hash of everything both sides said before the keys existed.
///
/// Each item is absorbed with its length and a label, so no combination of
/// inputs can produce the same hash as a different combination — an attacker
/// cannot move bytes from one field into the next.
#[derive(Clone)]
pub struct Transcript {
    hasher: Sha256,
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Transcript { .. }")
    }
}

impl Transcript {
    /// Start a transcript.
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update((DOMAIN.len() as u32).to_be_bytes());
        hasher.update(DOMAIN);
        Transcript { hasher }
    }

    /// Absorb one labelled item.
    pub fn absorb(&mut self, label: &str, data: &[u8]) {
        self.hasher.update((label.len() as u32).to_be_bytes());
        self.hasher.update(label.as_bytes());
        self.hasher.update((data.len() as u64).to_be_bytes());
        self.hasher.update(data);
    }

    /// Absorb a 16-bit value, such as the negotiated protocol version.
    pub fn absorb_u16(&mut self, label: &str, value: u16) {
        self.absorb(label, &value.to_be_bytes());
    }

    /// Finish and return the transcript hash.
    pub fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

/// The four keys a session runs on.
///
/// Zeroized on drop; `Debug` shows nothing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// AEAD key for frames this side sends.
    pub seal: [u8; KEY_LEN],
    /// AEAD key for frames this side receives.
    pub open: [u8; KEY_LEN],
    /// Key for the confirmation tag this side sends.
    pub our_confirm: [u8; KEY_LEN],
    /// Key for the confirmation tag this side expects.
    pub peer_confirm: [u8; KEY_LEN],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys { <redacted> }")
    }
}

impl SessionKeys {
    /// Expand the SPAKE2 output into per-direction keys.
    ///
    /// The transcript hash is the HKDF salt, which binds every derived key to
    /// the exact handshake that produced it: change the announced version, a
    /// `Hello`, or either SPAKE2 element, and both sides derive different keys
    /// and fail confirmation.
    pub fn derive(
        role: Role,
        version: u16,
        pake_output: &[u8],
        transcript: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(transcript), pake_output);

        let to_receiver = info(version, "data sender-to-receiver");
        let to_sender = info(version, "data receiver-to-sender");
        let confirm_sender = info(version, "confirm sender");
        let confirm_receiver = info(version, "confirm receiver");

        let (seal, open, our_confirm, peer_confirm) = match role {
            Role::Sender => (&to_receiver, &to_sender, &confirm_sender, &confirm_receiver),
            Role::Receiver => (&to_sender, &to_receiver, &confirm_receiver, &confirm_sender),
        };

        Ok(SessionKeys {
            seal: expand(&hkdf, seal)?,
            open: expand(&hkdf, open)?,
            our_confirm: expand(&hkdf, our_confirm)?,
            peer_confirm: expand(&hkdf, peer_confirm)?,
        })
    }
}

fn info(version: u16, purpose: &str) -> String {
    format!("rusp v{version} {purpose}")
}

fn expand(hkdf: &Hkdf<Sha256>, info: &str) -> Result<[u8; KEY_LEN], CryptoError> {
    let mut out = [0u8; KEY_LEN];
    hkdf.expand(info.as_bytes(), &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

/// Compute this side's key-confirmation tag over the transcript.
pub fn confirm_tag(key: &[u8; KEY_LEN], transcript: &[u8; 32]) -> [u8; CONFIRM_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(transcript);
    mac.finalize().into_bytes().into()
}

/// Verify the peer's key-confirmation tag in constant time.
///
/// A mismatch means the two sides did not derive the same key: either the code
/// was mistyped, or someone is sitting in the middle. Both are
/// [`CryptoError::KeyMismatch`], because from here the two are
/// indistinguishable and the response is the same — stop.
pub fn verify_confirm(
    key: &[u8; KEY_LEN],
    transcript: &[u8; 32],
    tag: &[u8],
) -> Result<(), CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(transcript);
    mac.verify_slice(tag).map_err(|_| CryptoError::KeyMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript(items: &[(&str, &[u8])]) -> [u8; 32] {
        let mut t = Transcript::new();
        for (label, data) in items {
            t.absorb(label, data);
        }
        t.finish()
    }

    #[test]
    fn transcripts_are_deterministic() {
        let a = transcript(&[("hello", b"one"), ("pake", b"two")]);
        let b = transcript(&[("hello", b"one"), ("pake", b"two")]);
        assert_eq!(a, b);
    }

    #[test]
    fn transcripts_are_unambiguous() {
        // Without length prefixes these would collide: "ab"+"c" vs "a"+"bc".
        let a = transcript(&[("x", b"ab"), ("x", b"c")]);
        let b = transcript(&[("x", b"a"), ("x", b"bc")]);
        assert_ne!(a, b);
        // Labels matter too.
        assert_ne!(transcript(&[("x", b"a")]), transcript(&[("y", b"a")]));
        // Order matters.
        assert_ne!(
            transcript(&[("x", b"a"), ("y", b"b")]),
            transcript(&[("y", b"b"), ("x", b"a")])
        );
    }

    #[test]
    fn u16_absorption_differs_by_value() {
        let mut a = Transcript::new();
        a.absorb_u16("version", 1);
        let mut b = Transcript::new();
        b.absorb_u16("version", 2);
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn the_two_sides_derive_mirrored_keys() {
        let t = transcript(&[("handshake", b"whatever")]);
        let pake = [7u8; 32];
        let s = SessionKeys::derive(Role::Sender, 1, &pake, &t).unwrap();
        let r = SessionKeys::derive(Role::Receiver, 1, &pake, &t).unwrap();

        assert_eq!(s.seal, r.open, "sender seals what receiver opens");
        assert_eq!(s.open, r.seal, "receiver seals what sender opens");
        assert_eq!(s.our_confirm, r.peer_confirm);
        assert_eq!(s.peer_confirm, r.our_confirm);
    }

    #[test]
    fn all_four_keys_are_independent() {
        let t = transcript(&[("handshake", b"whatever")]);
        let k = SessionKeys::derive(Role::Sender, 1, &[7u8; 32], &t).unwrap();
        let all = [k.seal, k.open, k.our_confirm, k.peer_confirm];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "derived keys must differ");
            }
        }
    }

    #[test]
    fn a_different_transcript_gives_different_keys() {
        let pake = [7u8; 32];
        let a = SessionKeys::derive(Role::Sender, 1, &pake, &transcript(&[("x", b"a")])).unwrap();
        let b = SessionKeys::derive(Role::Sender, 1, &pake, &transcript(&[("x", b"b")])).unwrap();
        assert_ne!(a.seal, b.seal);
        assert_ne!(a.our_confirm, b.our_confirm);
    }

    #[test]
    fn a_different_version_gives_different_keys() {
        let t = transcript(&[("x", b"a")]);
        let pake = [7u8; 32];
        let v1 = SessionKeys::derive(Role::Sender, 1, &pake, &t).unwrap();
        let v2 = SessionKeys::derive(Role::Sender, 2, &pake, &t).unwrap();
        assert_ne!(v1.seal, v2.seal);
    }

    #[test]
    fn a_different_pake_output_gives_different_keys() {
        let t = transcript(&[("x", b"a")]);
        let a = SessionKeys::derive(Role::Sender, 1, &[1u8; 32], &t).unwrap();
        let b = SessionKeys::derive(Role::Sender, 1, &[2u8; 32], &t).unwrap();
        assert_ne!(a.seal, b.seal);
    }

    #[test]
    fn confirmation_accepts_the_matching_tag() {
        let t = transcript(&[("x", b"a")]);
        let key = [3u8; KEY_LEN];
        let tag = confirm_tag(&key, &t);
        assert_eq!(tag.len(), CONFIRM_LEN);
        assert!(verify_confirm(&key, &t, &tag).is_ok());
    }

    #[test]
    fn confirmation_rejects_everything_else() {
        let t = transcript(&[("x", b"a")]);
        let key = [3u8; KEY_LEN];
        let tag = confirm_tag(&key, &t);

        // Wrong key.
        assert_eq!(
            verify_confirm(&[4u8; KEY_LEN], &t, &tag).unwrap_err(),
            CryptoError::KeyMismatch
        );
        // Wrong transcript.
        assert_eq!(
            verify_confirm(&key, &transcript(&[("x", b"b")]), &tag).unwrap_err(),
            CryptoError::KeyMismatch
        );
        // Flipped bit.
        let mut bad = tag;
        bad[0] ^= 1;
        assert_eq!(
            verify_confirm(&key, &t, &bad).unwrap_err(),
            CryptoError::KeyMismatch
        );
        // Wrong lengths, including a truncated prefix that must not be
        // accepted just because it matches as far as it goes.
        for len in [0usize, 1, 16, 31, 33, 64] {
            let mut candidate = tag.to_vec();
            candidate.resize(len, 0);
            assert_eq!(
                verify_confirm(&key, &t, &candidate).unwrap_err(),
                CryptoError::KeyMismatch,
                "length {len}"
            );
        }
    }

    #[test]
    fn a_full_wrong_code_exchange_fails_confirmation() {
        // What a mistyped code actually looks like end to end: both sides
        // derive keys, then confirmation catches the mismatch.
        let t = transcript(&[("handshake", b"same transcript")]);
        let sender = SessionKeys::derive(Role::Sender, 1, b"key-from-code-A", &t).unwrap();
        let receiver = SessionKeys::derive(Role::Receiver, 1, b"key-from-code-B", &t).unwrap();

        let from_sender = confirm_tag(&sender.our_confirm, &t);
        assert_eq!(
            verify_confirm(&receiver.peer_confirm, &t, &from_sender).unwrap_err(),
            CryptoError::KeyMismatch
        );
    }

    #[test]
    fn keys_do_not_leak_through_debug() {
        let t = transcript(&[("x", b"a")]);
        let k = SessionKeys::derive(Role::Sender, 1, &[7u8; 32], &t).unwrap();
        let text = format!("{k:?}");
        assert!(text.contains("redacted"), "{text}");
        assert!(!text.contains(&format!("{}", k.seal[0])) || k.seal[0] > 9);
        assert_eq!(format!("{:?}", Transcript::new()), "Transcript { .. }");
    }
}
