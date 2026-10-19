//! Device key proof (keyproof v1) — client side.
//!
//! Proves to the Coordinator that this device holds the private half of
//! the X25519 key it registers with.  Specification and test vectors: the
//! Coordinator's `DEVICE_KEY_PROOF.md`.
//!
//! ```text
//! POST /device/key-challenge {device_id, pub_key}
//!   → {challenge_id (32 hex), server_pub (base64), expires_in}
//! shared = X25519(device_sk, server_pub)
//! k      = HKDF-SHA256(shared, salt "msst-keyproof-v1",
//!                      info device_id(8 BE) ‖ device_pub ‖ server_pub, 32)
//! mac    = HMAC-SHA256(k, "msst-keyproof-v1" ‖ challenge_id(16 raw bytes))
//! register … device.key_proof = {challenge_id, mac (base64)}
//! ```
//!
//! One challenge per registration, never reused.  A `404` from the
//! challenge endpoint means the Coordinator predates keyproof (or has it
//! off): register without a proof.  Never log `shared`, `k` or `mac`.

use super::CoordinatorClient;
use crate::identity::Identity;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const LABEL: &[u8] = b"msst-keyproof-v1";

/// Coordinator error code: the device ID is pinned to another key.
pub const CODE_KEY_MISMATCH: &str = "device_key_mismatch";
/// Coordinator error codes that a fresh challenge can fix.
pub const CODE_PROOF_INVALID: &str = "key_proof_invalid";
pub const CODE_PROOF_REQUIRED: &str = "key_proof_required";

/// Why no proof could be obtained.
#[derive(Debug, Clone, PartialEq)]
pub enum ProofError {
    /// `409 device_key_mismatch`: registration cannot succeed with this key.
    KeyMismatch,
    /// Anything else (transport, 400, 503, malformed response).  The caller
    /// registers without a proof; the Coordinator decides per its policy.
    Other(String),
}

/// Compute the proof MAC.  `None` for a low-order server key.
pub fn proof_mac(device_sk: &[u8; 32], device_id: &str, server_pub: &[u8; 32], challenge_id: &[u8; 16]) -> Option<[u8; 32]> {
    let secret = StaticSecret::from(*device_sk);
    let device_pub = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(*server_pub));
    if !shared.was_contributory() {
        return None;
    }
    let mut info = Vec::with_capacity(8 + 32 + 32);
    info.extend_from_slice(&crate::sdisc::wire_id(device_id).to_be_bytes());
    info.extend_from_slice(device_pub.as_bytes());
    info.extend_from_slice(server_pub);
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(Some(LABEL), shared.as_bytes()).expand(&info, &mut k).ok()?;
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&k).ok()?;
    m.update(LABEL);
    m.update(challenge_id);
    Some(m.finalize().into_bytes().into())
}

/// Build `device.key_proof` from a challenge response.
fn proof_from_challenge(id: &Identity, resp: &Value) -> Result<Value, ProofError> {
    let bad = |what: &str| ProofError::Other(format!("malformed key-challenge response: {}", what));
    let cid_hex = resp["challenge_id"].as_str().ok_or_else(|| bad("challenge_id"))?;
    let cid = decode_hex16(cid_hex).ok_or_else(|| bad("challenge_id"))?;
    let server_pub: [u8; 32] = resp["server_pub"]
        .as_str()
        .and_then(|s| STANDARD.decode(s).ok())
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| bad("server_pub"))?;
    let mac = proof_mac(&id.secret_key, &id.device.id, &server_pub, &cid).ok_or_else(|| bad("low-order server_pub"))?;
    Ok(json!({ "challenge_id": cid_hex, "mac": STANDARD.encode(mac) }))
}

fn decode_hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Request a fresh challenge and answer it.  `Ok(None)`: the Coordinator
/// does not support keyproof (404) — register without a proof.
pub async fn obtain(client: &CoordinatorClient, id: &Identity) -> Result<Option<Value>, ProofError> {
    let body = json!({ "device_id": id.device.id, "pub_key": id.public_key_base64() });
    let (status, resp) = client
        .api_request(reqwest::Method::POST, "/device/key-challenge", Some(&body), None)
        .await
        .map_err(ProofError::Other)?;
    match status {
        200 => proof_from_challenge(id, &resp).map(Some),
        404 => Ok(None),
        409 if resp["code"] == CODE_KEY_MISMATCH => Err(ProofError::KeyMismatch),
        _ => Err(ProofError::Other(format!("key-challenge returned {}: {}", status, resp["code"].as_str().unwrap_or("")))),
    }
}

/// Add `key_proof` to a registration body (`register` data shape).
pub fn attach(register_data: &mut Value, proof: Option<Value>) {
    if let Some(p) = proof {
        register_data["device"]["key_proof"] = p;
    }
}

/// The message logged when the device ID is pinned to another key.  Log
/// lines reach Controllers as `Diagnostic` events.
pub fn mismatch_message(device_id: &str) -> String {
    format!(
        "coordinator: device ID {} is registered with a different key (device_key_mismatch) — \
         this device cannot register until its key matches or an administrator unpins the ID",
        device_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Vector from DEVICE_KEY_PROOF.md.
    #[test]
    fn spec_vector() {
        let server_pub = *PublicKey::from(&StaticSecret::from([3u8; 32])).as_bytes();
        assert_eq!(STANDARD.encode(server_pub), "Xf7dO2vUf2+ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI=");
        let cid = decode_hex16("000102030405060708090a0b0c0d0e0f").unwrap();
        let mac = proof_mac(&[1u8; 32], "device-1a92f238", &server_pub, &cid).unwrap();
        assert_eq!(mac.to_vec(), hex("5a7b00f18835e1b07468ded872ba53a947f595eeae964ca4f293912c40516bdb"));
        assert_eq!(STANDARD.encode(mac), "WnsA8Yg14bB0aN7YcrpTqUf1le6ulkyk8pORLEBRa9s=");
    }

    #[test]
    fn proof_body_and_rejections() {
        let mut id = crate::test_support::identity_with_key([1u8; 32]);
        assert_eq!(id.device.id, "device-1a92f238");
        let resp = json!({ "challenge_id": "000102030405060708090a0b0c0d0e0f", "server_pub": "Xf7dO2vUf2+ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI=", "expires_in": 60 });
        let proof = proof_from_challenge(&id, &resp).unwrap();
        assert_eq!(proof, json!({ "challenge_id": "000102030405060708090a0b0c0d0e0f", "mac": "WnsA8Yg14bB0aN7YcrpTqUf1le6ulkyk8pORLEBRa9s=" }));

        let mut data = json!({ "device": { "id": id.device.id } });
        attach(&mut data, Some(proof));
        assert_eq!(data["device"]["key_proof"]["challenge_id"], "000102030405060708090a0b0c0d0e0f");
        let mut data2 = json!({ "device": {} });
        attach(&mut data2, None);
        assert!(data2["device"].get("key_proof").is_none());

        for bad in [
            json!({ "challenge_id": "0001", "server_pub": resp["server_pub"] }),
            json!({ "challenge_id": "000102030405060708090A0B0C0D0E0F", "server_pub": resp["server_pub"] }),
            json!({ "challenge_id": resp["challenge_id"], "server_pub": "AAAA" }),
            json!({ "challenge_id": resp["challenge_id"], "server_pub": STANDARD.encode([0u8; 32]) }),
        ] {
            assert!(matches!(proof_from_challenge(&id, &bad), Err(ProofError::Other(_))), "{}", bad);
        }
        id.device.id = "device-00000000".into();
        assert_ne!(proof_from_challenge(&id, &resp).unwrap()["mac"], "WnsA8Yg14bB0aN7YcrpTqUf1le6ulkyk8pORLEBRa9s=");
    }

    // ── Against a fake Coordinator ───────────────────────────────────────

    use crate::test_support::{core_state, eventually, FakeCoordinator};

    const VECTOR_CHALLENGE: &str = "000102030405060708090a0b0c0d0e0f";
    const VECTOR_SERVER_PUB: &str = "Xf7dO2vUf2+ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI=";

    async fn run_against(name: &str, coord: &FakeCoordinator) -> crate::runtime::CoreRuntime {
        let (state, _ipc) = core_state(name).await;
        state.apply_identity(&crate::test_support::identity_with_key([1u8; 32])).await;
        let mut rt = crate::runtime::CoreRuntime::new(state);
        rt.start_coordinator(crate::coordinator::CoordinatorConfig { coord_url: coord.url.clone() }, None);
        rt
    }

    fn registers(coord: &FakeCoordinator) -> Vec<Value> {
        coord.ws_log.lock().unwrap().iter().filter(|m| m["type"] == "register").cloned().collect()
    }

    #[tokio::test]
    async fn ws_register_carries_proof() {
        let coord = FakeCoordinator::start(
            |req| match req.path.as_str() {
                "/device/key-challenge" => (200, json!({ "challenge_id": VECTOR_CHALLENGE, "server_pub": VECTOR_SERVER_PUB, "expires_in": 60 })),
                _ => (404, json!({})),
            },
            |_| vec![],
        ).await;
        let rt = run_against("keyproof-ok", &coord).await;
        assert!(eventually(|| !registers(&coord).is_empty()).await);
        let reg = &registers(&coord)[0];
        assert_eq!(reg["data"]["device"]["id"], "device-1a92f238");
        assert_eq!(reg["data"]["device"]["key_proof"], json!({ "challenge_id": VECTOR_CHALLENGE, "mac": "WnsA8Yg14bB0aN7YcrpTqUf1le6ulkyk8pORLEBRa9s=" }));
        let ch = coord.http_log.lock().unwrap().iter().find(|r| r.path == "/device/key-challenge").cloned().unwrap();
        assert_eq!(ch.body, json!({ "device_id": "device-1a92f238", "pub_key": "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=" }));
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn key_mismatch_never_registers() {
        let coord = FakeCoordinator::start(
            |req| match req.path.as_str() {
                "/device/key-challenge" => (409, json!({ "error": "pinned", "code": CODE_KEY_MISMATCH })),
                _ => (404, json!({})),
            },
            |_| vec![],
        ).await;
        let rt = run_against("keyproof-mismatch", &coord).await;
        assert!(eventually(|| coord.http_log.lock().unwrap().iter().any(|r| r.path == "/device/key-challenge")).await);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(registers(&coord).is_empty(), "register sent despite device_key_mismatch");
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn rejected_proof_reconnects_with_fresh_challenge() {
        let coord = FakeCoordinator::start(
            |req| match req.path.as_str() {
                "/device/key-challenge" => (200, json!({ "challenge_id": VECTOR_CHALLENGE, "server_pub": VECTOR_SERVER_PUB, "expires_in": 60 })),
                _ => (404, json!({})),
            },
            |msg| match msg["type"].as_str() {
                Some("register") => vec![json!({ "type": "error", "data": { "message": "key proof invalid", "code": CODE_PROOF_INVALID } })],
                _ => vec![],
            },
        ).await;
        let rt = run_against("keyproof-retry", &coord).await;
        // Backoff 1 s after the first rejection, then a new challenge + register.
        let mut ok = false;
        for _ in 0..40 {
            if registers(&coord).len() >= 2 {
                ok = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(ok, "no re-register after key_proof_invalid");
        let challenges = coord.http_log.lock().unwrap().iter().filter(|r| r.path == "/device/key-challenge").count();
        assert!(challenges >= 2, "challenge reused");
        rt.shutdown().await;
    }
}
