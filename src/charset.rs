//! Alphabet detection and decoders used across detectors: hex, Base62,
//! Base64url (RFC 4648 §5, unpadded), Base32 (RFC 4648 §6, unpadded) and a
//! Shannon-entropy estimate for the generic fallback.
//!
//! All decoders are strict: an out-of-alphabet byte yields `None` rather than
//! silently skipping it, because credtype's job is to be precise about what a
//! string *is*.

/// Base62 alphabet in positional order: digits, uppercase, lowercase.
pub const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Returns true if every byte is an ASCII hex digit (either case) and the
/// string is non-empty.
pub fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Returns true if every byte is in the Base62 alphabet.
pub fn is_base62(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Returns true if every byte is a Base64url character (`A-Za-z0-9-_`).
pub fn is_base64url(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Returns true if every byte is an uppercase RFC 4648 Base32 character
/// (`A-Z2-7`).
pub fn is_base32(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}

/// Decode a Base62 string to an unsigned integer (big-endian positional).
///
/// Returns `None` on an out-of-alphabet byte or on overflow of `u64`.
pub fn base62_to_u64(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for &b in s.as_bytes() {
        let d = BASE62.iter().position(|&c| c == b)? as u64;
        value = value.checked_mul(62)?.checked_add(d)?;
    }
    Some(value)
}

/// Encode an unsigned integer as Base62, left-padded with `'0'` to `width`.
///
/// Used by the test/fixture helpers to build self-consistent tokens; the
/// production checksum path compares integers, not strings.
pub fn u64_to_base62(mut value: u64, width: usize) -> String {
    let mut out = Vec::new();
    if value == 0 {
        out.push(b'0');
    }
    while value > 0 {
        out.push(BASE62[(value % 62) as usize]);
        value /= 62;
    }
    while out.len() < width {
        out.push(b'0');
    }
    out.reverse();
    String::from_utf8(out).expect("base62 alphabet is ASCII")
}

/// Decode an unpadded Base64url string to bytes (RFC 4648 §5). Padding (`=`)
/// is tolerated but not required. Returns `None` on invalid input.
pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.is_empty() {
        return Some(Vec::new());
    }
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for &b in s.as_bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Any leftover bits must be zero for a well-formed encoding.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

/// Decode an unpadded uppercase Base32 string (RFC 4648 §6) to bytes.
///
/// Returns `None` on an out-of-alphabet byte.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.is_empty() {
        return Some(Vec::new());
    }
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for &b in s.as_bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None,
        } as u64;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Shannon entropy of a string in bits per character (0.0 for empty).
///
/// Used only by the generic fallback to describe an unrecognised blob; it is
/// a heuristic, never a classification.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total = total as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h
}

/// Name the dominant alphabet of a string for the generic fallback report.
pub fn describe_charset(s: &str) -> &'static str {
    if is_hex(s) {
        "hex"
    } else if is_base32(s) {
        "base32"
    } else if is_base64url(s) && !is_base62(s) {
        "base64url"
    } else if is_base62(s) {
        "base62"
    } else if s.is_ascii() {
        "mixed-ascii"
    } else {
        "non-ascii"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_detection_is_case_insensitive() {
        assert!(is_hex("deadBEEF00"));
        assert!(!is_hex("deadbeefzz"));
        assert!(!is_hex(""));
    }

    #[test]
    fn alphabet_predicates_are_strict() {
        assert!(is_base62("aZ09") && !is_base62("aZ_09"));
        assert!(is_base64url("ab-_CD") && !is_base64url("ab+/CD"));
        // 0,1,8,9 are not RFC 4648 base32 characters.
        assert!(is_base32("ABCDEF234567") && !is_base32("ABC0189"));
    }

    #[test]
    fn base62_roundtrip_and_rejects_junk() {
        for n in [0u64, 1, 61, 62, 3843, 999_999] {
            let enc = u64_to_base62(n, 6);
            assert_eq!(base62_to_u64(&enc), Some(n), "roundtrip {n}");
        }
        assert_eq!(base62_to_u64("ab-c"), None);
        assert_eq!(base62_to_u64(""), None);
    }

    #[test]
    fn base64url_decodes_known_vector_and_json() {
        // "Hello" -> SGVsbG8 ; and a real JWT header, padding tolerated.
        assert_eq!(base64url_decode("SGVsbG8"), Some(b"Hello".to_vec()));
        let hdr = base64url_decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9").unwrap();
        assert_eq!(&hdr, br#"{"alg":"HS256","typ":"JWT"}"#);
        assert_eq!(base64url_decode("SGk="), Some(b"Hi".to_vec()));
        assert_eq!(base64url_decode("ab+/"), None); // standard-base64 symbols rejected
    }

    #[test]
    fn base32_decodes_ten_bytes_from_sixteen_chars() {
        // 16 base32 chars -> 80 bits -> 10 bytes
        let bytes = base32_decode("ABCDEFGHIJKLMNOP").unwrap();
        assert_eq!(bytes.len(), 10);
    }

    #[test]
    fn entropy_of_uniform_is_higher_than_repeated() {
        let low = shannon_entropy("aaaaaaaa");
        let high = shannon_entropy("abcdefgh");
        assert!(high > low);
        assert!((low - 0.0).abs() < 1e-9);
    }

    #[test]
    fn describe_charset_picks_narrowest() {
        assert_eq!(describe_charset("deadbeef"), "hex");
        // Uppercase, includes letters beyond F so it is base32 but not hex.
        assert_eq!(describe_charset("MFRGGZDFMZ"), "base32");
        assert_eq!(describe_charset("ab-_XY"), "base64url");
        assert_eq!(describe_charset("abcXYZ789"), "base62");
    }
}
