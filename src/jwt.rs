//! JSON Web Token detector.
//!
//! A JWS-serialised JWT is three Base64url segments separated by dots:
//! `header.payload.signature`. credtype decodes the header and payload,
//! confirms they are JSON objects, and surfaces the useful facts: the signing
//! algorithm (`alg`), token type (`typ`), issuer (`iss`) and expiry (`exp`).
//!
//! The signature cannot be verified offline without the signing key, so the
//! checksum verdict is honestly [`Checksum::Absent`] — **except** for the
//! dangerous `alg=none` case, which credtype flags loudly.

use crate::charset::base64url_decode;
use crate::json::{self, Json};
use crate::token::{Category, Checksum, Confidence, Detection};

/// Recognise a compact-serialised JWT and decode its header/payload.
pub fn detect(token: &str) -> Option<Detection> {
    let parts: Vec<&str> = token.split('.').collect();
    // JWS = 3 parts. JWE = 5 parts. Anything else is not a JWT.
    if parts.len() != 3 && parts.len() != 5 {
        return None;
    }
    // The header must Base64url-decode to a JSON object with an `alg`; this is
    // what separates a real JWT from any dotted string.
    let header_bytes = base64url_decode(parts[0])?;
    let header = json::parse(&header_bytes)?;
    if !header.is_object() {
        return None;
    }
    let alg = header.get("alg").and_then(Json::as_str)?;

    let is_jwe = parts.len() == 5;
    let mut d = Detection::new("jwt", "JSON Web Token", Category::Jwt, Confidence::Medium)
        .with_length(token.len())
        .detail(
            "serialization",
            if is_jwe {
                "JWE (5 segments)"
            } else {
                "JWS (3 segments)"
            },
        )
        .detail("alg", alg.to_string());

    if let Some(typ) = header.get("typ").and_then(Json::as_str) {
        d = d.detail("typ", typ.to_string());
    }

    // Decode the payload for JWS (JWE payloads are encrypted).
    if !is_jwe {
        if let Some(payload_bytes) = base64url_decode(parts[1]) {
            if let Some(payload @ Json::Obj(_)) = json::parse(&payload_bytes) {
                for claim in ["iss", "sub", "aud"] {
                    if let Some(v) = payload.get(claim).and_then(Json::as_str) {
                        d = d.detail(claim, v.to_string());
                    }
                }
                if let Some(Json::Num(exp)) = payload.get("exp") {
                    d = d.detail("exp", exp.clone());
                }
            } else {
                d = d.note("payload segment is not a JSON object");
            }
        }
    }

    // Honest checksum verdict.
    if alg.eq_ignore_ascii_case("none") {
        d = d
            .with_checksum(Checksum::Invalid)
            .note("alg=none: this token is UNSIGNED — treat as untrusted");
    } else {
        d = d.note("signature not verified: that needs the signing key, which credtype never has");
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    // header {"alg":"HS256","typ":"JWT"} . payload {"sub":"123","iss":"acme","exp":1700000000} . sig
    const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
eyJzdWIiOiIxMjMiLCJpc3MiOiJhY21lIiwiZXhwIjoxNzAwMDAwMDAwfQ.\
c2lnbmF0dXJl";

    #[test]
    fn recognises_a_three_segment_jwt() {
        let d = detect(JWT).unwrap();
        assert_eq!(d.id, "jwt");
        assert_eq!(d.category, Category::Jwt);
    }

    #[test]
    fn extracts_header_and_claims() {
        let d = detect(JWT).unwrap();
        let has = |k: &str, v: &str| d.details.iter().any(|(dk, dv)| dk == k && dv == v);
        assert!(has("alg", "HS256"));
        assert!(has("iss", "acme"));
        assert!(has("sub", "123"));
        assert!(has("exp", "1700000000")); // number kept as text, no float rounding
    }

    #[test]
    fn signature_absent_verdict_for_signed_token() {
        let d = detect(JWT).unwrap();
        assert_eq!(d.checksum, Checksum::Absent);
    }

    #[test]
    fn two_segments_is_not_a_jwt() {
        assert!(detect("aaa.bbb").is_none());
        assert!(detect("!!!.???.***").is_none());
    }

    #[test]
    fn alg_none_is_flagged_invalid() {
        // header {"alg":"none"} . {"x":1} . (empty)
        let header = "eyJhbGciOiJub25lIn0"; // {"alg":"none"}
        let payload = "eyJ4IjoxfQ"; // {"x":1}
        let tok = format!("{header}.{payload}.");
        let d = detect(&tok).unwrap();
        assert_eq!(d.checksum, Checksum::Invalid);
        assert!(d.notes.iter().any(|n| n.contains("UNSIGNED")));
    }

    #[test]
    fn header_without_alg_is_rejected() {
        // {"typ":"JWT"} has no alg
        let header = base64url_no_pad(br#"{"typ":"JWT"}"#);
        let tok = format!("{header}.eyJ4IjoxfQ.sig");
        assert!(detect(&tok).is_none());
    }

    // Local helper: encode bytes as unpadded base64url so we can build fixtures.
    fn base64url_no_pad(data: &[u8]) -> String {
        const AL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            let take = chunk.len() + 1;
            for i in 0..take {
                out.push(AL[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            }
        }
        out
    }
}
