//! Record protection: ChaCha20-Poly1305 with counter nonces.
//!
//! # Nonce discipline
//!
//! Each direction has its own key, so each direction can run its own counter
//! starting at zero without any chance of reusing a (key, nonce) pair. The
//! nonce is the 64-bit counter in the low bytes of the 96-bit nonce, big
//! endian, with the top four bytes zero:
//!
//! ```text
//! 00 00 00 00 | counter (u64, big endian)
//! ```
//!
//! Because the counter is implicit rather than transmitted, it authenticates
//! the position of every frame in the stream for free. A frame that is
//! replayed, reordered, duplicated or dropped decrypts under the wrong counter
//! and fails authentication, so the receiver notices immediately.
//!
//! The counter cannot wrap: at 2^64 frames the session refuses to continue
//! rather than repeat a nonce.

use chacha20poly1305::aead::{AeadInOut, KeyInit, Tag};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::error::CryptoError;
use crate::protocol::frame::FrameBuf;

/// Length of a ChaCha20-Poly1305 key.
pub const KEY_LEN: usize = 32;

/// Length of a Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;

/// Length of a ChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 12;

fn nonce_for(counter: u64) -> Nonce {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[NONCE_LEN - 8..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(nonce)
}

/// Encrypts outbound frames.
pub struct SealingKey {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl std::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealingKey")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl SealingKey {
    /// Create a sealing key.
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        SealingKey {
            cipher: ChaCha20Poly1305::new_from_slice(key).expect("key is 32 bytes"),
            counter: 0,
        }
    }

    /// Number of frames sealed so far — the nonce the next frame will use.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Encrypt a frame's payload in place and append the authentication tag.
    ///
    /// Nothing is copied: the plaintext is already in the frame buffer, is
    /// encrypted where it lies, and the 16-byte tag is appended after it.
    pub fn seal(&mut self, buf: &mut FrameBuf) -> Result<(), CryptoError> {
        let nonce = nonce_for(self.counter);
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, &[], buf.payload_mut().into())
            .map_err(|_| CryptoError::Decrypt)?;
        buf.push_slice(&tag);
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;
        Ok(())
    }
}

/// Decrypts inbound frames.
pub struct OpeningKey {
    cipher: ChaCha20Poly1305,
    counter: u64,
    /// Set once a frame fails to authenticate. From that point the stream is
    /// not trustworthy, so nothing further is accepted from it.
    poisoned: bool,
}

impl std::fmt::Debug for OpeningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpeningKey")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl OpeningKey {
    /// Create an opening key.
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        OpeningKey {
            cipher: ChaCha20Poly1305::new_from_slice(key).expect("key is 32 bytes"),
            counter: 0,
            poisoned: false,
        }
    }

    /// Number of frames opened so far — the nonce the next frame must use.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Authenticate and decrypt a frame in place, truncating away the tag.
    ///
    /// One failure ends the stream. A frame that does not authenticate means
    /// the connection is no longer trustworthy, so the key poisons itself and
    /// every later frame is refused as well — an attacker cannot make the
    /// receiver skip a frame it dislikes and resynchronise on the next one.
    pub fn open(&mut self, buf: &mut Vec<u8>) -> Result<(), CryptoError> {
        if self.poisoned {
            return Err(CryptoError::Decrypt);
        }
        if buf.len() < TAG_LEN {
            self.poisoned = true;
            return Err(CryptoError::Decrypt);
        }
        let split = buf.len() - TAG_LEN;
        let (body, tag_bytes) = buf.split_at_mut(split);
        let Ok(tag) = Tag::<ChaCha20Poly1305>::try_from(&*tag_bytes) else {
            self.poisoned = true;
            return Err(CryptoError::Decrypt);
        };

        let nonce = nonce_for(self.counter);
        if self
            .cipher
            .decrypt_inout_detached(&nonce, &[], body.into(), &tag)
            .is_err()
        {
            self.poisoned = true;
            return Err(CryptoError::Decrypt);
        }

        buf.truncate(split);
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (SealingKey, OpeningKey) {
        let key = [42u8; KEY_LEN];
        (SealingKey::new(&key), OpeningKey::new(&key))
    }

    fn seal(key: &mut SealingKey, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = FrameBuf::with_capacity(plaintext.len() + TAG_LEN);
        buf.push_slice(plaintext);
        key.seal(&mut buf).unwrap();
        buf.payload().to_vec()
    }

    #[test]
    fn round_trip() {
        let (mut s, mut o) = pair();
        for plaintext in [
            b"".to_vec(),
            b"hello".to_vec(),
            vec![0u8; 256 * 1024],
            (0..=255u8).cycle().take(100_000).collect(),
        ] {
            let mut ciphertext = seal(&mut s, &plaintext);
            assert_eq!(ciphertext.len(), plaintext.len() + TAG_LEN);
            if !plaintext.is_empty() {
                assert_ne!(
                    &ciphertext[..plaintext.len()],
                    &plaintext[..],
                    "payload must not travel in the clear"
                );
            }
            o.open(&mut ciphertext).unwrap();
            assert_eq!(ciphertext, plaintext);
        }
    }

    #[test]
    fn identical_plaintexts_produce_different_ciphertexts() {
        let (mut s, _) = pair();
        let a = seal(&mut s, b"same message");
        let b = seal(&mut s, b"same message");
        assert_ne!(a, b, "the counter must change the keystream");
    }

    #[test]
    fn counters_advance_together() {
        let (mut s, mut o) = pair();
        assert_eq!((s.counter(), o.counter()), (0, 0));
        for i in 1..=5u64 {
            let mut frame = seal(&mut s, b"tick");
            o.open(&mut frame).unwrap();
            assert_eq!(s.counter(), i);
            assert_eq!(o.counter(), i);
        }
    }

    #[test]
    fn tampering_is_detected() {
        let (mut s, mut o) = pair();
        let original = seal(&mut s, b"important instructions");

        for index in 0..original.len() {
            let mut tampered = original.clone();
            tampered[index] ^= 0x01;
            let mut fresh = OpeningKey::new(&[42u8; KEY_LEN]);
            assert_eq!(
                fresh.open(&mut tampered).unwrap_err(),
                CryptoError::Decrypt,
                "flipping byte {index} went unnoticed"
            );
        }
        // The untampered frame still opens.
        let mut good = original;
        o.open(&mut good).unwrap();
    }

    #[test]
    fn truncation_is_detected() {
        let (mut s, _) = pair();
        let original = seal(&mut s, b"important instructions");
        for cut in 0..original.len() {
            let mut short = original[..cut].to_vec();
            let mut o = OpeningKey::new(&[42u8; KEY_LEN]);
            assert_eq!(o.open(&mut short).unwrap_err(), CryptoError::Decrypt);
        }
    }

    #[test]
    fn replay_is_detected() {
        let (mut s, mut o) = pair();
        let first = seal(&mut s, b"one");
        let mut copy = first.clone();
        o.open(&mut copy).unwrap();

        // The very same frame again: the counter has moved on.
        let mut replayed = first;
        assert_eq!(o.open(&mut replayed).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn reordering_is_detected() {
        let (mut s, mut o) = pair();
        let first = seal(&mut s, b"one");
        let second = seal(&mut s, b"two");

        // Deliver the second frame first.
        let mut out_of_order = second;
        assert_eq!(o.open(&mut out_of_order).unwrap_err(), CryptoError::Decrypt);
        // The stream is now poisoned: even the frame that *would* have been
        // correct next is refused, so an attacker cannot use a rejected frame
        // to probe and then resynchronise.
        let mut recovered = first;
        assert_eq!(o.open(&mut recovered).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn dropped_frames_are_detected() {
        let (mut s, mut o) = pair();
        let _dropped = seal(&mut s, b"one");
        let mut second = seal(&mut s, b"two");
        assert_eq!(o.open(&mut second).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn the_wrong_key_cannot_open_anything() {
        let (mut s, _) = pair();
        let mut frame = seal(&mut s, b"secret");
        let mut wrong = OpeningKey::new(&[43u8; KEY_LEN]);
        assert_eq!(wrong.open(&mut frame).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn a_frame_shorter_than_a_tag_is_rejected() {
        for len in 0..TAG_LEN {
            let (_, mut o) = pair();
            let mut buf = vec![0u8; len];
            assert_eq!(o.open(&mut buf).unwrap_err(), CryptoError::Decrypt);
        }
    }

    #[test]
    fn one_bad_frame_poisons_the_stream() {
        let (mut s, mut o) = pair();
        let good_first = seal(&mut s, b"one");
        let good_second = seal(&mut s, b"two");

        let mut tampered = good_first.clone();
        tampered[0] ^= 0xFF;
        assert_eq!(o.open(&mut tampered).unwrap_err(), CryptoError::Decrypt);

        // Neither the original frame nor the next one is accepted afterwards.
        for mut frame in [good_first, good_second] {
            assert_eq!(o.open(&mut frame).unwrap_err(), CryptoError::Decrypt);
        }
    }

    #[test]
    fn nonces_are_distinct_per_counter() {
        let a = nonce_for(0);
        let b = nonce_for(1);
        let big = nonce_for(u64::MAX);
        assert_ne!(a, b);
        assert_ne!(a, big);
        assert_eq!(a.len(), NONCE_LEN);
        assert_eq!(&a[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn debug_does_not_expose_key_material() {
        let (s, o) = pair();
        assert!(!format!("{s:?}").contains("42"));
        assert!(format!("{o:?}").contains("counter"));
    }
}
