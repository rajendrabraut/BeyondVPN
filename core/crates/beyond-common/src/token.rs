//! Verification of control-plane issued EdDSA (Ed25519) JWTs.
//!
//! The control plane signs short-lived tokens; gateways verify them offline
//! with the public key, so a compromised gateway can never mint tokens.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported algorithm")]
    Algorithm,
    #[error("bad signature")]
    Signature,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("wrong token type")]
    WrongType,
    #[error("wrong audience")]
    Audience,
    #[error("invalid public key")]
    PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// User id.
    pub sub: String,
    /// Token type: "access", "proxy", ...
    pub typ: String,
    pub exp: u64,
    #[serde(default)]
    pub iat: u64,
    #[serde(default)]
    pub nbf: Option<u64>,
    /// Audience (gateway id for proxy tokens).
    #[serde(default)]
    pub aud: Option<String>,
    /// Device / session id.
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub jti: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
}

/// Parse a raw 32-byte Ed25519 public key encoded as standard or URL-safe base64.
pub fn parse_public_key(b64: &str) -> Result<VerifyingKey, TokenError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .or_else(|_| URL_SAFE_NO_PAD.decode(b64.trim()))
        .map_err(|_| TokenError::PublicKey)?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| TokenError::PublicKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| TokenError::PublicKey)
}

/// Verify signature and time claims. `leeway` seconds tolerate clock skew.
pub fn verify(
    token: &str,
    key: &VerifyingKey,
    expected_typ: &str,
    expected_aud: Option<&str>,
    now: u64,
    leeway: u64,
) -> Result<Claims, TokenError> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(TokenError::Malformed),
    };
    let header: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).map_err(|_| TokenError::Malformed)?)
        .map_err(|_| TokenError::Malformed)?;
    if header.alg != "EdDSA" {
        // Reject "none", HS256 and anything else: prevents algorithm confusion.
        return Err(TokenError::Algorithm);
    }
    let sig_bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| TokenError::Malformed)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| TokenError::Malformed)?;
    let signing_input = &token[..h.len() + 1 + p.len()];
    key.verify(signing_input.as_bytes(), &sig).map_err(|_| TokenError::Signature)?;

    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).map_err(|_| TokenError::Malformed)?)
        .map_err(|_| TokenError::Malformed)?;
    if now > claims.exp + leeway {
        return Err(TokenError::Expired);
    }
    if let Some(nbf) = claims.nbf {
        if now + leeway < nbf {
            return Err(TokenError::NotYetValid);
        }
    }
    if claims.typ != expected_typ {
        return Err(TokenError::WrongType);
    }
    if let Some(aud) = expected_aud {
        if claims.aud.as_deref() != Some(aud) {
            return Err(TokenError::Audience);
        }
    }
    Ok(claims)
}

/// Sign claims. Used by tests and by self-hosted single-node setups.
pub fn sign(claims: &Claims, key: &SigningKey) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"));
    let input = format!("{header}.{payload}");
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn claims(exp: u64) -> Claims {
        Claims {
            sub: "u1".into(),
            typ: "proxy".into(),
            exp,
            iat: 0,
            nbf: None,
            aud: Some("gw-1".into()),
            sid: Some("d1".into()),
            jti: None,
            email: None,
        }
    }

    #[test]
    fn roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let t = sign(&claims(1000), &sk);
        let c = verify(&t, &sk.verifying_key(), "proxy", Some("gw-1"), 500, 0).unwrap();
        assert_eq!(c.sub, "u1");
    }

    #[test]
    fn rejects_expired_wrong_type_aud_and_forgery() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let t = sign(&claims(1000), &sk);
        let vk = sk.verifying_key();
        assert_eq!(verify(&t, &vk, "proxy", None, 2000, 30), Err(TokenError::Expired));
        assert_eq!(verify(&t, &vk, "access", None, 1, 0), Err(TokenError::WrongType));
        assert_eq!(verify(&t, &vk, "proxy", Some("gw-2"), 1, 0), Err(TokenError::Audience));
        assert_eq!(verify(&t, &other.verifying_key(), "proxy", None, 1, 0), Err(TokenError::Signature));
    }

    #[test]
    fn rejects_alg_none_and_tampering() {
        let sk = SigningKey::generate(&mut OsRng);
        let t = sign(&claims(1000), &sk);
        let parts: Vec<&str> = t.split('.').collect();
        let none_hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let forged = format!("{none_hdr}.{}.{}", parts[1], parts[2]);
        assert_eq!(verify(&forged, &sk.verifying_key(), "proxy", None, 1, 0), Err(TokenError::Algorithm));

        let mut c = claims(1000);
        c.sub = "admin".into();
        let evil_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).unwrap());
        let tampered = format!("{}.{evil_payload}.{}", parts[0], parts[2]);
        assert_eq!(verify(&tampered, &sk.verifying_key(), "proxy", None, 1, 0), Err(TokenError::Signature));
        assert_eq!(verify("a.b", &sk.verifying_key(), "proxy", None, 1, 0), Err(TokenError::Malformed));
    }

    #[test]
    fn parses_public_key_formats() {
        let sk = SigningKey::generate(&mut OsRng);
        let raw = sk.verifying_key().to_bytes();
        let std = base64::engine::general_purpose::STANDARD.encode(raw);
        assert!(parse_public_key(&std).is_ok());
        assert!(parse_public_key(&URL_SAFE_NO_PAD.encode(raw)).is_ok());
        assert!(parse_public_key("zz").is_err());
    }
}
