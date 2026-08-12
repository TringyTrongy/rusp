//! SPAKE2 password-authenticated key exchange.
//!
//! The two sides run SPAKE2 over Ed25519 with the transfer code's secret words
//! as the password. Identities bind the exchange to the roles and to the room,
//! so an element captured from one transfer cannot be replayed into another.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::code::TransferCode;
use crate::error::CryptoError;
use crate::protocol::Role;

/// Length of the SPAKE2 message this group produces: a one-byte side tag plus
/// a compressed Edwards point.
pub const PAKE_MESSAGE_LEN: usize = 33;

/// An in-progress SPAKE2 exchange.
///
/// Consumed by [`PakeState::finish`], so the ephemeral scalar cannot be reused
/// for a second exchange.
pub struct PakeState {
    inner: Spake2<Ed25519Group>,
}

impl std::fmt::Debug for PakeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PakeState { .. }")
    }
}

/// Begin the exchange, returning our state and the element to send.
///
/// The sender takes SPAKE2's "A" side and the receiver takes "B", which means
/// the two sides use different generators and a reflected message is rejected
/// by the library rather than producing a key.
pub fn start(role: Role, code: &TransferCode) -> (PakeState, Vec<u8>) {
    let password = Password::new(code.secret_bytes());
    let id_a = identity(Role::Sender, code);
    let id_b = identity(Role::Receiver, code);

    let (inner, message) = match role {
        Role::Sender => Spake2::<Ed25519Group>::start_a(&password, &id_a, &id_b),
        Role::Receiver => Spake2::<Ed25519Group>::start_b(&password, &id_a, &id_b),
    };
    (PakeState { inner }, message)
}

impl PakeState {
    /// Complete the exchange with the peer's element.
    ///
    /// Failure here means the peer sent something structurally wrong — the
    /// wrong side tag, the wrong length, or a point that is not on the curve.
    /// A merely *incorrect* code still produces a key; that case is caught by
    /// key confirmation, which is what keeps the failure modes distinguishable.
    pub fn finish(self, peer_message: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.inner
            .finish(peer_message)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Pake)
    }
}

/// SPAKE2 identity string for a role in a particular room.
fn identity(role: Role, code: &TransferCode) -> Identity {
    Identity::new(format!("rusp:{}:{}", role.label(), code.room()).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::TransferCode;

    fn code(text: &str) -> TransferCode {
        TransferCode::parse(text).expect("valid code")
    }

    fn exchange(
        sender_code: &TransferCode,
        receiver_code: &TransferCode,
    ) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
        let (s_state, s_msg) = start(Role::Sender, sender_code);
        let (r_state, r_msg) = start(Role::Receiver, receiver_code);
        let s_key = s_state.finish(&r_msg).expect("sender finishes");
        let r_key = r_state.finish(&s_msg).expect("receiver finishes");
        (s_key, r_key)
    }

    #[test]
    fn matching_codes_agree_on_a_key() {
        let code = code("k7m2-cotton-harbor-tiger-pencil");
        let (s, r) = exchange(&code, &code);
        assert_eq!(s.as_slice(), r.as_slice());
        assert_eq!(s.len(), 32);
        assert!(s.iter().any(|b| *b != 0));
    }

    #[test]
    fn every_exchange_produces_a_fresh_key() {
        let code = code("k7m2-cotton-harbor-tiger-pencil");
        let (a, _) = exchange(&code, &code);
        let (b, _) = exchange(&code, &code);
        assert_ne!(a.as_slice(), b.as_slice(), "keys must not be deterministic");
    }

    #[test]
    fn different_codes_produce_different_keys() {
        let sender = code("k7m2-cotton-harbor-tiger-pencil");
        let receiver = code("k7m2-cotton-harbor-tiger-museum");
        let (s, r) = exchange(&sender, &receiver);
        // SPAKE2 still yields *a* key on both sides; they simply disagree.
        // Key confirmation is what turns this into a clean failure.
        assert_ne!(s.as_slice(), r.as_slice());
    }

    #[test]
    fn the_same_words_in_a_different_room_do_not_agree() {
        let a = code("aaaa-cotton-harbor-tiger-pencil");
        let b = code("bbbb-cotton-harbor-tiger-pencil");
        let (s, r) = exchange(&a, &b);
        assert_ne!(s.as_slice(), r.as_slice());
    }

    #[test]
    fn message_length_is_what_the_protocol_expects() {
        let (_, msg) = start(Role::Sender, &code("k7m2-cotton-harbor-tiger"));
        assert_eq!(msg.len(), PAKE_MESSAGE_LEN);
    }

    #[test]
    fn a_reflected_message_is_rejected() {
        // An attacker echoing our own element back must not yield a key: the
        // side tag makes A-to-A and B-to-B invalid.
        let code = code("k7m2-cotton-harbor-tiger-pencil");
        let (state, msg) = start(Role::Sender, &code);
        assert_eq!(state.finish(&msg).unwrap_err(), CryptoError::Pake);

        let (state, msg) = start(Role::Receiver, &code);
        assert_eq!(state.finish(&msg).unwrap_err(), CryptoError::Pake);
    }

    #[test]
    fn structurally_invalid_elements_are_rejected() {
        let code = code("k7m2-cotton-harbor-tiger-pencil");

        for bad in [
            Vec::new(),
            vec![0u8; PAKE_MESSAGE_LEN - 1],
            vec![0u8; PAKE_MESSAGE_LEN + 1],
            // Right length, wrong side tag.
            vec![0xFF; PAKE_MESSAGE_LEN],
            // Right length and side tag, but not a point on the curve:
            // 0x02 repeated is not a valid compressed Edwards y-coordinate.
            {
                let mut m = vec![0u8; PAKE_MESSAGE_LEN];
                m[0] = b'B';
                m[1..].fill(0x02);
                m
            },
        ] {
            let (state, _) = start(Role::Sender, &code);
            assert_eq!(
                state.finish(&bad).unwrap_err(),
                CryptoError::Pake,
                "{} bytes starting {:?}",
                bad.len(),
                bad.first()
            );
        }
    }

    #[test]
    fn a_well_formed_but_hostile_element_yields_a_useless_key() {
        // SPAKE2 cannot tell an attacker's honestly-formed element from a
        // legitimate one — anybody can put a valid curve point on the wire.
        // What it guarantees is that the resulting key is not the one the real
        // peer derived, which is what key confirmation then catches.
        let code = code("k7m2-cotton-harbor-tiger-pencil");
        let (honest_state, _) = start(Role::Receiver, &code);

        let mut hostile = vec![0u8; PAKE_MESSAGE_LEN];
        hostile[0] = b'B';
        hostile[1..].fill(0xFF);

        let (victim, victim_msg) = start(Role::Sender, &code);
        let attacked = victim
            .finish(&hostile)
            .expect("a valid point always produces some key");
        let honest = honest_state.finish(&victim_msg).expect("honest finish");
        assert_ne!(attacked.as_slice(), honest.as_slice());
    }

    #[test]
    fn truncating_a_valid_element_never_panics() {
        let code = code("k7m2-cotton-harbor-tiger-pencil");
        let (_, valid) = start(Role::Receiver, &code);
        for cut in 0..=valid.len() {
            let (state, _) = start(Role::Sender, &code);
            let _ = state.finish(&valid[..cut]);
        }
    }

    #[test]
    fn debug_reveals_nothing() {
        let (state, _) = start(Role::Sender, &code("k7m2-cotton-harbor-tiger"));
        assert_eq!(format!("{state:?}"), "PakeState { .. }");
    }
}
