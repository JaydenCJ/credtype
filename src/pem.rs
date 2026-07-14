//! Private-key material detector (PEM and OpenSSH).
//!
//! credtype recognises the ASCII armour of private keys — the most damaging
//! secret to leak — and reports the key kind. Where the body decodes, it does a
//! light structural check: the OpenSSH private-key format carries the magic
//! string `openssh-key-v1`, which credtype confirms after Base64-decoding the
//! body ([`Checksum::Valid`] as a structural self-check). Classic PEM bodies
//! are DER and carry no such marker, so they report [`Checksum::Absent`].

use crate::token::{Category, Checksum, Confidence, Detection};

/// (begin marker, slug, name).
const PEM_KINDS: &[(&str, &str, &str)] = &[
    (
        "-----BEGIN RSA PRIVATE KEY-----",
        "pem-rsa-private",
        "PEM RSA private key (PKCS#1)",
    ),
    (
        "-----BEGIN EC PRIVATE KEY-----",
        "pem-ec-private",
        "PEM EC private key (SEC1)",
    ),
    (
        "-----BEGIN DSA PRIVATE KEY-----",
        "pem-dsa-private",
        "PEM DSA private key",
    ),
    (
        "-----BEGIN PRIVATE KEY-----",
        "pem-pkcs8-private",
        "PEM private key (PKCS#8)",
    ),
    (
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "pem-pkcs8-encrypted",
        "PEM encrypted private key (PKCS#8)",
    ),
    (
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "openssh-private",
        "OpenSSH private key",
    ),
    (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "pgp-private",
        "PGP private key block",
    ),
];

/// Base64 (standard alphabet) decode of the concatenated body lines. Returns
/// `None` on an out-of-alphabet character.
fn base64_std_decode(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let s = s.trim_end_matches('=');
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for &b in s.as_bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Recognise PEM/OpenSSH private-key armour.
pub fn detect(token: &str) -> Option<Detection> {
    let trimmed = token.trim_start();
    let (begin, slug, name) = PEM_KINDS
        .iter()
        .find(|(m, _, _)| trimmed.starts_with(m))
        .copied()?;

    let mut d = Detection::new(slug, name, Category::PrivateKey, Confidence::Medium)
        .with_length(token.len())
        .detail("armor", begin.trim_matches('-').trim().to_string());

    // Extract the body between the BEGIN and END markers.
    let after_begin = &trimmed[begin.len()..];
    let body = match after_begin.find("-----END") {
        Some(idx) => &after_begin[..idx],
        None => {
            d.structural_ok = false;
            return Some(d.note("missing matching -----END marker"));
        }
    };

    // OpenSSH keys carry a verifiable magic string once Base64-decoded.
    if slug == "openssh-private" {
        match base64_std_decode(body) {
            Some(bytes) if bytes.starts_with(b"openssh-key-v1\0") => {
                d = d
                    .with_checksum(Checksum::Valid)
                    .detail("magic", "openssh-key-v1")
                    .note("OpenSSH v1 magic present after Base64 decode");
            }
            Some(_) => {
                d.structural_ok = false;
                d = d.note("Base64 body lacks the openssh-key-v1 magic");
            }
            None => {
                d.structural_ok = false;
                d = d.note("body is not valid Base64");
            }
        }
    } else {
        d = d.note("private key material — treat as highly sensitive; rotate if leaked");
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_rsa_private_key() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----";
        let d = detect(pem).unwrap();
        assert_eq!(d.id, "pem-rsa-private");
        assert_eq!(d.category, Category::PrivateKey);
    }

    #[test]
    fn recognises_pkcs8_private_key() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIICdQ\n-----END PRIVATE KEY-----";
        assert_eq!(detect(pem).unwrap().id, "pem-pkcs8-private");
    }

    #[test]
    fn openssh_magic_validates() {
        // Base64 of "openssh-key-v1\0..." — construct a minimal body.
        let body = base64_std_encode(b"openssh-key-v1\0rest-of-key-bytes");
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
        );
        let d = detect(&pem).unwrap();
        assert_eq!(d.id, "openssh-private");
        assert_eq!(d.checksum, Checksum::Valid);
    }

    #[test]
    fn openssh_without_magic_fails_structural() {
        let body = base64_std_encode(b"not-an-openssh-key-at-all-really");
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
        );
        let d = detect(&pem).unwrap();
        assert!(!d.structural_ok);
    }

    #[test]
    fn missing_end_marker_fails() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB";
        let d = detect(pem).unwrap();
        assert!(!d.structural_ok);
    }

    #[test]
    fn non_pem_is_none() {
        assert!(detect("not a key").is_none());
    }

    // Local base64 (standard alphabet) encoder for building fixtures.
    fn base64_std_encode(data: &[u8]) -> String {
        const AL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
            for _ in 0..(3 - chunk.len()) {
                out.push('=');
            }
        }
        out
    }
}
