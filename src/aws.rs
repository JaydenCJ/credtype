//! AWS access key ID detector.
//!
//! An AWS access key ID is a 4-character type prefix (`AKIA`, `ASIA`, …)
//! followed by 16 Base32 characters. Those 16 characters are not random: the
//! first six decoded bytes encode the **AWS account ID** (a well-documented
//! reverse of AWS's own encoding). credtype decodes and reports it — a strong,
//! fully-offline structural signal even though the key carries no CRC.
//!
//! The decode: strip the 4-char prefix, Base32-decode the 16 remaining chars
//! to 10 bytes, take the first 6 as a big-endian integer `z`, and compute
//! `(z & 0x7fffffffff80) >> 7` to recover the account ID.

use crate::charset::{base32_decode, is_base32};
use crate::token::{Category, Confidence, Detection};

/// (prefix, human description of the key type).
const PREFIXES: &[(&str, &str)] = &[
    ("AKIA", "long-term IAM user access key"),
    ("ASIA", "temporary (STS) access key"),
    ("AROA", "IAM role unique id"),
    ("AIDA", "IAM user unique id"),
    ("AGPA", "IAM group unique id"),
    ("AIPA", "EC2 instance profile id"),
    ("ANPA", "managed policy unique id"),
    ("ANVA", "policy version unique id"),
    ("ASCA", "certificate unique id"),
    ("ABIA", "STS service bearer token id"),
    ("ACCA", "context-specific credential id"),
];

const KEY_LEN: usize = 20;
const BODY_LEN: usize = 16;

/// Recover the AWS account ID embedded in the 16-char Base32 body.
pub fn decode_account_id(body: &str) -> Option<u64> {
    let bytes = base32_decode(body)?;
    if bytes.len() < 6 {
        return None;
    }
    let mut z: u64 = 0;
    for &b in &bytes[..6] {
        z = (z << 8) | b as u64;
    }
    // Mask 0x7fffffffff80, shift right 7 (AWS's documented layout).
    Some((z & 0x7fff_ffff_ff80) >> 7)
}

/// Recognise an AWS access key ID and decode its account id where possible.
pub fn detect(token: &str) -> Option<Detection> {
    let (prefix, kind) = PREFIXES
        .iter()
        .find(|(p, _)| token.starts_with(p))
        .copied()?;

    let body = &token[prefix.len()..];
    let mut d = Detection::new(
        "aws-access-key-id",
        "AWS access key ID",
        Category::Cloud,
        Confidence::Medium,
    )
    .with_length(token.len())
    .detail("key_type", kind);

    if token.len() != KEY_LEN || body.len() != BODY_LEN || !is_base32(body) {
        d.structural_ok = false;
        return Some(d.note(format!(
            "expected {KEY_LEN}-char key ({BODY_LEN} Base32 chars after a 4-char prefix)"
        )));
    }

    // Account ID is only meaningful for the "resource" style ids whose body
    // encodes it; AWS uses the same layout for all of these prefixes.
    if let Some(acct) = decode_account_id(body) {
        // AWS account IDs are 12 digits, zero-padded.
        d = d.detail("account_id", format!("{acct:012}"));
    }
    d = d.detail("checksum", "none (structure + account-id decode only)");
    Some(d.note("AWS keys carry no self-contained checksum; validity confirmed structurally"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::Checksum;

    #[test]
    fn recognises_akia_prefix_and_length() {
        // AKIA + 16 base32 chars.
        let tok = "AKIAIOSFODNN7EXAMPLE";
        let d = detect(tok).unwrap();
        assert_eq!(d.id, "aws-access-key-id");
        assert!(d.structural_ok);
        assert_eq!(d.length, 20);
    }

    #[test]
    fn asia_temporary_key_recognised() {
        let tok = "ASIAIOSFODNN7EXAMPLE";
        let d = detect(tok).unwrap();
        assert!(d
            .details
            .iter()
            .any(|(k, v)| k == "key_type" && v.contains("temporary")));
    }

    #[test]
    fn decodes_a_twelve_digit_account_id() {
        let tok = "AKIAIOSFODNN7EXAMPLE";
        let d = detect(tok).unwrap();
        let acct = d
            .details
            .iter()
            .find(|(k, _)| k == "account_id")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(acct.len(), 12);
        assert!(acct.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn wrong_length_is_structural_failure() {
        let d = detect("AKIAtooshort").unwrap();
        assert!(!d.structural_ok);
    }

    #[test]
    fn lowercase_body_is_rejected() {
        // Base32 is uppercase; a lowercased body must not validate.
        let d = detect("AKIAiosfodnn7example").unwrap();
        assert!(!d.structural_ok);
    }

    #[test]
    fn unrelated_prefix_is_none_and_no_checksum_claimed() {
        assert!(detect("BKIAIOSFODNN7EXAMPLE").is_none());
        assert!(detect("hello").is_none());
        assert_eq!(
            detect("AKIAIOSFODNN7EXAMPLE").unwrap().checksum,
            Checksum::Absent
        );
    }
}
