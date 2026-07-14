//! UUID / GUID detector.
//!
//! A UUID is `8-4-4-4-12` lowercase-or-uppercase hex with hyphens. credtype
//! validates the layout and reads the **version** nibble (13th hex digit) and
//! the **variant** bits (17th hex digit) per RFC 4122 / RFC 9562 — a structural
//! check, not a checksum, so the verdict is [`Checksum::Absent`]. The special
//! nil and max UUIDs are recognised by name.

use crate::token::{Category, Confidence, Detection};

/// Expected hyphen positions and segment lengths: 8-4-4-4-12.
const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

fn is_hex_group(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Recognise a UUID and report version/variant.
pub fn detect(token: &str) -> Option<Detection> {
    let parts: Vec<&str> = token.split('-').collect();
    if parts.len() != 5 {
        return None;
    }
    for (part, len) in parts.iter().zip(GROUPS.iter()) {
        if !is_hex_group(part, *len) {
            return None;
        }
    }

    let hex: String = parts.concat().to_ascii_lowercase();
    let mut d = Detection::new(
        "uuid",
        "UUID / GUID",
        Category::Identifier,
        Confidence::Medium,
    )
    .with_length(token.len());

    if hex == "00000000000000000000000000000000" {
        return Some(
            d.detail("form", "nil UUID")
                .note("all-zero nil UUID (RFC 4122)"),
        );
    }
    if hex == "ffffffffffffffffffffffffffffffff" {
        return Some(
            d.detail("form", "max UUID")
                .note("all-ones max UUID (RFC 9562)"),
        );
    }

    // Version nibble is the first hex digit of the 3rd group.
    let version = u8::from_str_radix(&hex[12..13], 16).unwrap_or(0);
    // Variant is encoded in the top bits of the 17th hex digit.
    let variant_nibble = u8::from_str_radix(&hex[16..17], 16).unwrap_or(0);
    let variant = match variant_nibble >> 2 {
        0b00 | 0b01 => "NCS (legacy)",
        0b10 => "RFC 4122",
        _ => "Microsoft / reserved",
    };

    d = d
        .detail("version", version.to_string())
        .detail("variant", variant)
        .detail("checksum", "none (structure + version/variant only)");
    if (1..=8).contains(&version) {
        d = d.note(format!("well-formed version-{version} UUID"));
    } else {
        d.structural_ok = false;
        d = d.note(format!(
            "version nibble {version} is outside the defined 1–8 range"
        ));
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_v4_uuid() {
        let d = detect("9b2e4f1a-3c5d-4e6f-8a9b-0c1d2e3f4a5b").unwrap();
        assert_eq!(d.id, "uuid");
        assert!(d.details.iter().any(|(k, v)| k == "version" && v == "4"));
    }

    #[test]
    fn recognises_v1_uuid() {
        let d = detect("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap();
        assert!(d.details.iter().any(|(k, v)| k == "version" && v == "1"));
    }

    #[test]
    fn nil_and_max_uuids_named() {
        let nil = detect("00000000-0000-0000-0000-000000000000").unwrap();
        assert!(nil
            .details
            .iter()
            .any(|(k, v)| k == "form" && v == "nil UUID"));
        let max = detect("ffffffff-ffff-ffff-ffff-ffffffffffff").unwrap();
        assert!(max
            .details
            .iter()
            .any(|(k, v)| k == "form" && v == "max UUID"));
    }

    #[test]
    fn bad_grouping_is_none() {
        assert!(detect("9b2e4f1a3c5d4e6f8a9b0c1d2e3f4a5b").is_none());
        assert!(detect("9b2e-4f1a-3c5d-4e6f-8a9b").is_none());
    }

    #[test]
    fn non_hex_is_none() {
        assert!(detect("zzzzzzzz-3c5d-4e6f-8a9b-0c1d2e3f4a5b").is_none());
    }

    #[test]
    fn version_zero_is_structural_failure() {
        // version nibble 0 is outside 1..=8
        let d = detect("9b2e4f1a-3c5d-0e6f-8a9b-0c1d2e3f4a5b").unwrap();
        assert!(!d.structural_ok);
    }
}
