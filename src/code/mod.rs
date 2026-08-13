//! Transfer codes: the short string a human reads out loud.
//!
//! A code has two parts separated by the first `-`:
//!
//! ```text
//! k7m2-cotton-harbor-tiger-pencil
//! ^^^^ ^--------------------------
//! room             secret
//! ```
//!
//! The **room** is public routing information. It is the only part a relay ever
//! sees, and it exists so two peers can find each other without the relay
//! learning anything that would let it attack the session.
//!
//! The **secret** never leaves the machine. It is fed into SPAKE2 (see
//! [`crate::crypto`]) as the password; the wire only ever carries SPAKE2 group
//! elements derived from it.
//!
//! Entropy: each word is drawn uniformly from a 1024-word list, so a code is
//! worth exactly `10 * words` bits. The default of four words gives 40 bits.
//! That is deliberately more than the threat model strictly needs — because a
//! failed key confirmation aborts the transfer, an attacker gets exactly one
//! online guess — but it costs nothing and covers codes that leak after the
//! fact.

pub mod wordlist;

use std::fmt;

use zeroize::Zeroizing;

use crate::error::CodeError;

/// Character that separates the room from the secret, and words from each other.
pub const SEPARATOR: char = '-';

/// Number of characters in a generated room identifier.
pub const ROOM_LEN: usize = 4;

/// Longest room identifier accepted when parsing (custom codes may be longer).
pub const MAX_ROOM_LEN: usize = 16;

/// Fewest words a generated code may contain.
pub const MIN_WORDS: usize = 3;

/// Most words a generated code may contain.
pub const MAX_WORDS: usize = 12;

/// Words used when the user does not ask for a specific count.
pub const DEFAULT_WORDS: usize = 4;

/// Shortest secret accepted from a user-supplied `--code`.
pub const MIN_SECRET_CHARS: usize = 8;

/// Alphabet for room identifiers: Crockford-style base32, minus `i`, `l`, `o`
/// and `u` so a room never reads as a word and never gets confused with `1`/`0`.
/// Exactly 32 characters, so sampling from a byte needs no rejection loop.
const ROOM_ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// A validated room identifier — the routing half of a transfer code.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoomId(String);

impl RoomId {
    /// Validate an existing room string.
    pub fn new(s: impl Into<String>) -> Result<Self, CodeError> {
        let s = s.into();
        let valid = !s.is_empty()
            && s.len() <= MAX_ROOM_LEN
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        if valid {
            Ok(RoomId(s))
        } else {
            Err(CodeError::InvalidRoom(s))
        }
    }

    /// Draw a fresh random room identifier from the OS RNG.
    pub fn generate() -> Result<Self, CodeError> {
        let mut bytes = [0u8; ROOM_LEN];
        fill_random(&mut bytes)?;
        let s: String = bytes
            .iter()
            .map(|b| ROOM_ALPHABET[(b & 0x1f) as usize] as char)
            .collect();
        Ok(RoomId(s))
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A transfer code: a public room plus a secret passphrase.
///
/// `Debug` deliberately redacts the secret so it cannot leak into logs. Use
/// [`Display`](fmt::Display) when the user genuinely needs to see it.
#[derive(Clone)]
pub struct TransferCode {
    room: RoomId,
    secret: Zeroizing<String>,
}

impl TransferCode {
    /// Generate a fresh code with `words` secret words.
    pub fn generate(words: usize) -> Result<Self, CodeError> {
        if words < MIN_WORDS {
            return Err(CodeError::TooFewWords {
                min: MIN_WORDS,
                bits: MIN_WORDS as u32 * wordlist::BITS_PER_WORD,
            });
        }
        if words > MAX_WORDS {
            return Err(CodeError::TooManyWords(words));
        }

        // Two bytes per word; the list is 1024 long, which divides 65536
        // evenly, so masking is uniform and no rejection sampling is needed.
        let mut raw = vec![0u8; words * 2];
        fill_random(&mut raw)?;
        let mut secret = String::with_capacity(words * 7);
        for (i, pair) in raw.chunks_exact(2).enumerate() {
            if i > 0 {
                secret.push(SEPARATOR);
            }
            let idx = (u16::from_le_bytes([pair[0], pair[1]]) as usize) % wordlist::WORD_COUNT;
            secret.push_str(wordlist::WORDS[idx]);
        }

        Ok(TransferCode {
            room: RoomId::generate()?,
            secret: Zeroizing::new(secret),
        })
    }

    /// Parse a code typed or pasted by a user.
    ///
    /// Accepts any mix of `-`, `_`, and whitespace as separators, and is case
    /// insensitive, because people retype these from a chat window.
    pub fn parse(input: &str) -> Result<Self, CodeError> {
        let normalized = normalize(input);
        if normalized.is_empty() {
            return Err(CodeError::Empty);
        }

        let (room, secret) = normalized
            .split_once(SEPARATOR)
            .ok_or(CodeError::MissingSecret)?;
        if secret.is_empty() {
            return Err(CodeError::MissingSecret);
        }
        if secret.chars().filter(|c| *c != SEPARATOR).count() < MIN_SECRET_CHARS {
            return Err(CodeError::SecretTooShort {
                min: MIN_SECRET_CHARS,
            });
        }

        Ok(TransferCode {
            room: RoomId::new(room)?,
            secret: Zeroizing::new(secret.to_owned()),
        })
    }

    /// Build a code from an already-validated room and secret.
    pub fn from_parts(room: RoomId, secret: impl Into<String>) -> Self {
        TransferCode {
            room,
            secret: Zeroizing::new(secret.into()),
        }
    }

    /// The public routing identifier.
    pub fn room(&self) -> &RoomId {
        &self.room
    }

    /// The secret passphrase, as the bytes handed to SPAKE2.
    pub fn secret_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }

    /// The secret as a string, for display to the user who owns it.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Estimated entropy of the secret, in bits, assuming every component is a
    /// word drawn from [`wordlist::WORDS`]. Returns `None` when the secret is
    /// not made of list words (a custom `--code`), because we cannot honestly
    /// estimate the entropy of something a human chose.
    pub fn entropy_bits(&self) -> Option<u32> {
        let mut words = 0;
        for w in self.secret.split(SEPARATOR) {
            if !wordlist::contains(w) {
                return None;
            }
            words += 1;
        }
        Some(words * wordlist::BITS_PER_WORD)
    }

    /// Report suspicious-looking words so the CLI can warn before spending a
    /// connection attempt on a typo. A code is only ever usable once, so it is
    /// worth catching `harbour` for `harbor` up front.
    pub fn lint(&self) -> Vec<CodeWarning> {
        let mut out = Vec::new();
        for word in self.secret.split(SEPARATOR) {
            if word.is_empty() || wordlist::contains(word) {
                continue;
            }
            out.push(CodeWarning {
                word: word.to_owned(),
                suggestion: wordlist::suggest(word).map(str::to_owned),
            });
        }
        out
    }
}

impl fmt::Display for TransferCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", self.room, SEPARATOR, *self.secret)
    }
}

impl fmt::Debug for TransferCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferCode")
            .field("room", &self.room)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// A word in a user-supplied code that is not in the Rusp word list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeWarning {
    /// The unrecognised word, as typed.
    pub word: String,
    /// The closest list word, when exactly one is a plausible match.
    pub suggestion: Option<String>,
}

impl fmt::Display for CodeWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` is not a Rusp code word", self.word)?;
        if let Some(s) = &self.suggestion {
            write!(f, " — did you mean `{s}`?")?;
        }
        Ok(())
    }
}

/// Lowercase, and collapse every run of separator-ish characters into one `-`.
fn normalize(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut pending_sep = false;
    for ch in input.chars() {
        if ch == SEPARATOR || ch == '_' || ch.is_whitespace() {
            // Never emit a leading separator; defer trailing ones forever.
            pending_sep = !out.is_empty();
            continue;
        }
        if pending_sep {
            out.push(SEPARATOR);
            pending_sep = false;
        }
        out.extend(ch.to_lowercase());
    }
    out
}

/// Fill `buf` with bytes from the operating system CSPRNG.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), CodeError> {
    getrandom::fill(buf).map_err(|e| CodeError::Random(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_codes_round_trip() {
        for words in MIN_WORDS..=6 {
            let code = TransferCode::generate(words).expect("generate");
            let text = code.to_string();
            let parsed = TransferCode::parse(&text).expect("parse");
            assert_eq!(parsed.room(), code.room());
            assert_eq!(parsed.secret(), code.secret());
            assert_eq!(parsed.secret().split(SEPARATOR).count(), words);
        }
    }

    #[test]
    fn generated_room_is_from_the_alphabet() {
        let code = TransferCode::generate(DEFAULT_WORDS).unwrap();
        assert_eq!(code.room().as_str().len(), ROOM_LEN);
        assert!(code
            .room()
            .as_str()
            .bytes()
            .all(|b| ROOM_ALPHABET.contains(&b)));
    }

    #[test]
    fn generated_codes_are_not_repeated() {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            assert!(seen.insert(TransferCode::generate(DEFAULT_WORDS).unwrap().to_string()));
        }
    }

    #[test]
    fn entropy_is_ten_bits_per_word() {
        let code = TransferCode::generate(5).unwrap();
        assert_eq!(code.entropy_bits(), Some(50));
    }

    #[test]
    fn entropy_is_unknown_for_custom_secrets() {
        let code = TransferCode::parse("room-correct-horse-battery").unwrap();
        assert_eq!(code.entropy_bits(), None);
    }

    #[test]
    fn parsing_is_forgiving_about_separators_and_case() {
        let canonical = TransferCode::parse("k7m2-cotton-harbor-tiger").unwrap();
        for variant in [
            "  K7M2-Cotton-Harbor-Tiger  ",
            "k7m2 cotton harbor tiger",
            "k7m2_cotton_harbor_tiger",
            "k7m2--cotton  -- harbor___tiger",
            "-k7m2-cotton-harbor-tiger-",
        ] {
            let parsed = TransferCode::parse(variant).unwrap_or_else(|e| panic!("{variant}: {e}"));
            assert_eq!(parsed.to_string(), canonical.to_string(), "{variant}");
        }
    }

    #[test]
    fn rejects_bad_codes() {
        assert_eq!(TransferCode::parse("").unwrap_err(), CodeError::Empty);
        assert_eq!(TransferCode::parse("   ").unwrap_err(), CodeError::Empty);
        assert_eq!(
            TransferCode::parse("justoneword").unwrap_err(),
            CodeError::MissingSecret
        );
        assert_eq!(
            TransferCode::parse("k7m2-short").unwrap_err(),
            CodeError::SecretTooShort {
                min: MIN_SECRET_CHARS
            }
        );
        assert!(matches!(
            TransferCode::parse("ROOM!-cotton-harbor-tiger").unwrap_err(),
            CodeError::InvalidRoom(_)
        ));
        assert!(matches!(
            TransferCode::parse("averyveryverylongroomname-cotton-harbor").unwrap_err(),
            CodeError::InvalidRoom(_)
        ));
    }

    #[test]
    fn rejects_silly_word_counts() {
        assert!(matches!(
            TransferCode::generate(MIN_WORDS - 1).unwrap_err(),
            CodeError::TooFewWords { .. }
        ));
        assert!(matches!(
            TransferCode::generate(MAX_WORDS + 1).unwrap_err(),
            CodeError::TooManyWords(_)
        ));
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let code = TransferCode::parse("k7m2-cotton-harbor-tiger").unwrap();
        let debug = format!("{code:?}");
        assert!(debug.contains("k7m2"));
        assert!(!debug.contains("cotton"), "{debug}");
    }

    #[test]
    fn lint_flags_typos_and_suggests() {
        let code = TransferCode::parse("k7m2-cotton-harbour-tiger").unwrap();
        let warnings = code.lint();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].word, "harbour");
        assert_eq!(warnings[0].suggestion.as_deref(), Some("harbor"));
        assert!(warnings[0].to_string().contains("did you mean"));
    }

    #[test]
    fn lint_is_silent_for_good_codes() {
        let code = TransferCode::generate(DEFAULT_WORDS).unwrap();
        assert!(code.lint().is_empty(), "{:?}", code.lint());
    }

    #[test]
    fn room_validation() {
        assert!(RoomId::new("abc123").is_ok());
        assert!(RoomId::new("").is_err());
        assert!(RoomId::new("UPPER").is_err());
        assert!(RoomId::new("has-dash").is_err());
        assert!(RoomId::new("a".repeat(MAX_ROOM_LEN)).is_ok());
        assert!(RoomId::new("a".repeat(MAX_ROOM_LEN + 1)).is_err());
    }
}
