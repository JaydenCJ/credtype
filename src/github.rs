//! GitHub token detector.
//!
//! GitHub's 2021 token format wraps a Base62 random body in a typed prefix and
//! appends a **Base62-encoded CRC-32 checksum** as the final six characters
//! (see the GitHub Engineering post "Behind GitHub's new authentication token
//! formats"). credtype recomputes that CRC-32 over the body and compares it to
//! the embedded checksum — a genuine, offline integrity check that catches
//! truncated, mistyped or fabricated tokens.
//!
//! Classic tokens are `<prefix>_` + 30 body chars + 6 checksum chars. The
//! fine-grained `github_pat_` format is longer and multi-segment; credtype
//! recognises it structurally but does not claim to check its checksum.

use crate::charset::{base62_to_u64, is_base62, u64_to_base62};
use crate::checksum::crc32;
use crate::token::{Category, Checksum, Confidence, Detection};

/// (prefix, slug, human name) for the five classic GitHub token kinds.
const CLASSIC: &[(&str, &str, &str)] = &[
    (
        "ghp_",
        "github-pat",
        "GitHub personal access token (classic)",
    ),
    ("gho_", "github-oauth", "GitHub OAuth access token"),
    (
        "ghu_",
        "github-user-to-server",
        "GitHub user-to-server token",
    ),
    (
        "ghs_",
        "github-server-to-server",
        "GitHub server-to-server token",
    ),
    ("ghr_", "github-refresh", "GitHub refresh token"),
];

/// Length of the random body between prefix and checksum.
const BODY_LEN: usize = 30;
/// Length of the trailing Base62 CRC-32 checksum.
const SUM_LEN: usize = 6;

/// Build a valid classic GitHub token for a given prefix and 30-char body by
/// appending the correct CRC-32 checksum. Used by tests and examples; it is
/// the exact inverse of the verification below.
pub fn sign(prefix: &str, body: &str) -> String {
    debug_assert_eq!(body.len(), BODY_LEN);
    let sum = u64_to_base62(crc32(body.as_bytes()) as u64, SUM_LEN);
    format!("{prefix}{body}{sum}")
}

/// Recognise a GitHub token and, for classic formats, verify its CRC-32.
pub fn detect(token: &str) -> Option<Detection> {
    // Fine-grained PAT: github_pat_<22>_<59> — structural only.
    if let Some(rest) = token.strip_prefix("github_pat_") {
        return detect_fine_grained(token, rest);
    }

    for &(prefix, slug, name) in CLASSIC {
        if let Some(rest) = token.strip_prefix(prefix) {
            return Some(detect_classic(token, rest, slug, name));
        }
    }
    None
}

fn detect_classic(token: &str, rest: &str, slug: &'static str, name: &'static str) -> Detection {
    let mut d =
        Detection::new(slug, name, Category::Vendor, Confidence::Medium).with_length(token.len());

    // Structural checks: exactly body+checksum Base62 characters.
    if rest.len() != BODY_LEN + SUM_LEN || !is_base62(rest) {
        d.structural_ok = false;
        d.checksum = Checksum::Absent;
        return d.note(format!(
            "expected {} Base62 chars after prefix, found {}",
            BODY_LEN + SUM_LEN,
            rest.len()
        ));
    }

    let (body, sum) = rest.split_at(BODY_LEN);
    let want = crc32(body.as_bytes()) as u64;
    match base62_to_u64(sum) {
        Some(got) if got == want => d
            .with_checksum(Checksum::Valid)
            .detail("checksum", "crc32/base62")
            .note("embedded CRC-32 checksum verifies"),
        Some(_) => d
            .with_checksum(Checksum::Invalid)
            .detail("checksum", "crc32/base62")
            .note("embedded CRC-32 checksum does NOT verify — truncated, mistyped or fabricated"),
        None => {
            d.structural_ok = false;
            d.note("checksum segment is not valid Base62")
        }
    }
}

fn detect_fine_grained(token: &str, rest: &str) -> Option<Detection> {
    let mut d = Detection::new(
        "github-pat-fine-grained",
        "GitHub fine-grained personal access token",
        Category::Vendor,
        Confidence::Medium,
    )
    .with_length(token.len());

    // github_pat_<random>_<random>; overall length is ~93 chars.
    let ok = rest.len() >= 70 && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !ok {
        d.structural_ok = false;
        d = d.note("does not match the github_pat_ fine-grained layout");
    } else {
        d = d.note("fine-grained PATs carry no self-contained checksum credtype can verify");
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed 30-char Base62 body so tests are fully deterministic.
    const BODY: &str = "abcdefghijklmnopqrstuvwxyz0123";

    #[test]
    fn all_classic_prefixes_sign_and_verify() {
        for (prefix, slug, _) in CLASSIC {
            let tok = sign(prefix, BODY);
            assert_eq!(tok.len(), prefix.len() + 36); // prefix + 30 body + 6 sum
            let d = detect(&tok).unwrap();
            assert_eq!(&d.id, slug);
            assert_eq!(d.checksum, Checksum::Valid);
            assert_eq!(d.confidence, Confidence::High);
        }
    }

    #[test]
    fn tampered_body_fails_checksum() {
        let tok = sign("ghp_", BODY);
        // Flip one body character; the checksum must now fail.
        let mut chars: Vec<char> = tok.chars().collect();
        chars[10] = if chars[10] == 'x' { 'y' } else { 'x' };
        let bad: String = chars.into_iter().collect();
        let d = detect(&bad).unwrap();
        assert_eq!(d.checksum, Checksum::Invalid);
        assert_eq!(d.id, "github-pat");
    }

    #[test]
    fn wrong_length_is_structural_failure() {
        let d = detect("ghp_tooshort").unwrap();
        assert!(!d.structural_ok);
        assert_eq!(d.checksum, Checksum::Absent);
    }

    #[test]
    fn fine_grained_recognised_structurally() {
        let tok = format!("github_pat_{}_{}", "A".repeat(22), "b".repeat(59));
        let d = detect(&tok).unwrap();
        assert_eq!(d.id, "github-pat-fine-grained");
        assert!(d.structural_ok);
        assert_eq!(d.checksum, Checksum::Absent);
    }

    #[test]
    fn unrelated_string_is_none() {
        assert!(detect("hello-world").is_none());
        assert!(detect("gh_notaprefix").is_none());
    }
}
