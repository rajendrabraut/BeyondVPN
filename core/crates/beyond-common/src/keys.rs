//! WireGuard (Curve25519) key handling.
//!
//! Private keys are generated on the device and never leave it. Only the
//! public key is registered with the control plane.

use base64::{engine::general_purpose::STANDARD, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("key is not valid base64")]
    Base64,
    #[error("key must decode to exactly 32 bytes")]
    Length,
}

/// A WireGuard keypair encoded as standard base64 (wg(8) format).
#[derive(Clone)]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print private key material.
        f.debug_struct("KeyPair")
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Generate a fresh keypair using the OS CSPRNG.
pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    KeyPair {
        private_key: STANDARD.encode(secret.to_bytes()),
        public_key: STANDARD.encode(public.as_bytes()),
    }
}

/// Generate a 32-byte preshared key (post-quantum hardening layer of WireGuard).
pub fn generate_preshared_key() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    STANDARD.encode(buf)
}

fn decode32(key: &str) -> Result<[u8; 32], KeyError> {
    let bytes = STANDARD.decode(key.trim()).map_err(|_| KeyError::Base64)?;
    bytes.try_into().map_err(|_| KeyError::Length)
}

/// Derive the public key for a base64 private key (equivalent of `wg pubkey`).
pub fn public_from_private(private_b64: &str) -> Result<String, KeyError> {
    let secret = StaticSecret::from(decode32(private_b64)?);
    Ok(STANDARD.encode(PublicKey::from(&secret).as_bytes()))
}

/// Validate that a string is a well-formed WireGuard key.
pub fn validate_key(key: &str) -> Result<(), KeyError> {
    decode32(key).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pair_is_consistent() {
        let kp = generate_keypair();
        assert_eq!(public_from_private(&kp.private_key).unwrap(), kp.public_key);
        assert_eq!(kp.public_key.len(), 44);
    }

    #[test]
    fn known_vector_matches_wg_pubkey() {
        // RFC 7748 section 6.1 test vector (Alice).
        let private = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
        let public = hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a").unwrap();
        let derived = public_from_private(&STANDARD.encode(private)).unwrap();
        assert_eq!(derived, STANDARD.encode(public));
    }

    #[test]
    fn rejects_bad_keys() {
        assert_eq!(validate_key("not base64!!"), Err(KeyError::Base64));
        assert_eq!(validate_key(&STANDARD.encode([1u8; 16])), Err(KeyError::Length));
    }

    #[test]
    fn debug_redacts_private_key() {
        let kp = generate_keypair();
        let s = format!("{kp:?}");
        assert!(!s.contains(&kp.private_key));
        assert!(s.contains("redacted"));
    }

    #[test]
    fn psk_is_32_bytes() {
        assert!(validate_key(&generate_preshared_key()).is_ok());
    }
}
