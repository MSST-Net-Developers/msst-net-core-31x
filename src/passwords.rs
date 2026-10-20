//! Password verifiers (Argon2id) for room and relay passwords
//! (`docs/ROOM_RELAY_3.1.md`).
//!
//! ```text
//! verifier = Argon2id(password, salt = domain ‖ salt), m = 19 MiB, t = 2, p = 1, 32 bytes
//! ```
//!
//! Only clients run Argon2id; the Coordinator stores `SHA-256(verifier)`
//! and compares.  A leaked Coordinator database therefore needs one
//! Argon2id run per password guess.

use argon2::{Algorithm, Argon2, Params, Version};

/// Domain of room password verifiers.
pub const ROOM_DOMAIN: &[u8] = b"msst-room-pw-v1";
/// Length of the random per-room salt.
pub const ROOM_SALT_LEN: usize = 16;
/// Domain of relay password verifiers (salt: domain ‖ relay public key).
pub const RELAY_DOMAIN: &[u8] = b"msst-relay-pw-v1";

const M_COST_KIB: u32 = 19 * 1024;
const T_COST: u32 = 2;
const P_COST: u32 = 1;

/// The 32-byte verifier for `password`.  CPU-heavy (tens of ms): use
/// [`verifier_blocking`] from async code.
pub fn verifier(domain: &[u8], password: &str, salt: &[u8]) -> [u8; 32] {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, Some(32)).expect("constant Argon2 parameters are valid");
    let mut full_salt = domain.to_vec();
    full_salt.extend_from_slice(salt);
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &full_salt, &mut out)
        .expect("salt and output lengths are within Argon2 limits");
    out
}

/// [`verifier`] on the blocking pool.
pub async fn verifier_blocking(domain: &'static [u8], password: String, salt: Vec<u8>) -> [u8; 32] {
    tokio::task::spawn_blocking(move || verifier(domain, &password, &salt)).await.expect("Argon2 task panicked")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// Pinned so other implementations (and Coordinator test fixtures)
    /// can check theirs; also listed in `docs/ROOM_RELAY_3.1.md`.
    #[test]
    fn room_vector() {
        let v = verifier(ROOM_DOMAIN, "correct horse", &[0x5a; ROOM_SALT_LEN]);
        assert_eq!(hex(&v), VECTOR);
        assert_ne!(verifier(ROOM_DOMAIN, "correct horse", &[0x5b; ROOM_SALT_LEN]), v, "salted");
        assert_ne!(verifier(b"other-domain", "correct horse", &[0x5a; ROOM_SALT_LEN]), v, "domain-separated");
    }

    // Cross-checked with the reference implementation (`argon2` 20190702):
    // `echo -n "correct horse" | argon2 "msst-room-pw-v1ZZZZZZZZZZZZZZZZ" -id -t 2 -k 19456 -p 1 -l 32 -r`
    const VECTOR: &str = "71e7aa44e64ecd1cb0ddbc6049b81a191738151aa8e662402735e1a6a6224dab";

    /// `docs/ROOM_RELAY_SERVER_3.1.md` (the relay computes the same).
    #[test]
    fn relay_vector() {
        let pk = *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([2u8; 32])).as_bytes();
        assert_eq!(hex(&verifier(RELAY_DOMAIN, "relay secret", &pk)), "7a8ef8ff39824ac7476ecbe76264a5b16cc0376d6e5f805bea3436060f3af9a3");
    }
}
