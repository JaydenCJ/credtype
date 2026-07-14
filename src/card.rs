//! Payment card (PAN) detector.
//!
//! A leaked card number is a credential too. credtype recognises 12–19 digit
//! numbers (spaces and dashes tolerated), identifies the issuer by IIN range,
//! and validates the **Luhn mod-10 check digit** — a real, self-contained
//! checksum, so the verdict here is genuinely [`Checksum::Valid`] or
//! [`Checksum::Invalid`].

use crate::checksum::luhn_valid;
use crate::token::{Category, Checksum, Confidence, Detection};

/// Normalise a candidate PAN: strip spaces and dashes, require all digits.
fn normalise(token: &str) -> Option<String> {
    let mut digits = String::new();
    for ch in token.chars() {
        match ch {
            ' ' | '-' => continue,
            '0'..='9' => digits.push(ch),
            _ => return None,
        }
    }
    if (12..=19).contains(&digits.len()) {
        Some(digits)
    } else {
        None
    }
}

/// Identify the issuer from the leading digits (IIN / BIN ranges).
pub fn issuer(digits: &str) -> &'static str {
    let two: u32 = digits[..2].parse().unwrap_or(0);
    let four: u32 = digits.get(..4).and_then(|s| s.parse().ok()).unwrap_or(0);
    let first = digits.as_bytes()[0];

    if first == b'4' {
        "Visa"
    } else if (51..=55).contains(&two) || (2221..=2720).contains(&four) {
        "Mastercard"
    } else if two == 34 || two == 37 {
        "American Express"
    } else if two == 36 || two == 38 || (300..=305).contains(&(four / 10)) {
        "Diners Club"
    } else if four == 6011 || two == 65 || (644..=649).contains(&(four / 10)) {
        "Discover"
    } else if (3528..=3589).contains(&four) {
        "JCB"
    } else if two == 62 {
        "UnionPay"
    } else {
        "unknown issuer"
    }
}

/// Recognise a payment card number and validate its Luhn checksum.
pub fn detect(token: &str) -> Option<Detection> {
    // The registry ranks prefixed detectors above this one, so any 12–19
    // digit run (with optional grouping separators) that reaches here is a
    // reasonable card candidate.
    let digits = normalise(token)?;

    let valid = luhn_valid(&digits);
    let iss = issuer(&digits);

    let mut d = Detection::new(
        "payment-card",
        "Payment card number (PAN)",
        Category::Card,
        Confidence::Medium,
    )
    .with_length(digits.len())
    .detail("issuer", iss)
    .detail("digits", digits.len().to_string())
    .detail("checksum", "luhn");

    if valid {
        d = d
            .with_checksum(Checksum::Valid)
            .note("Luhn checksum verifies");
    } else {
        d = d
            .with_checksum(Checksum::Invalid)
            .note("Luhn checksum does NOT verify — not a valid PAN");
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_visa_and_validates_luhn() {
        let d = detect("4111111111111111").unwrap();
        assert_eq!(d.id, "payment-card");
        assert_eq!(d.checksum, Checksum::Valid);
        assert!(d.details.iter().any(|(k, v)| k == "issuer" && v == "Visa"));
    }

    #[test]
    fn tolerates_spaces_and_dashes() {
        let d = detect("4111-1111 1111-1111").unwrap();
        assert_eq!(d.checksum, Checksum::Valid);
        assert_eq!(d.length, 16);
    }

    #[test]
    fn identifies_issuers_by_iin() {
        assert_eq!(issuer("5555555555554444"), "Mastercard");
        assert_eq!(issuer("2221000000000009"), "Mastercard"); // 2-series range
        assert_eq!(issuer("378282246310005"), "American Express");
        assert_eq!(issuer("6011111111111117"), "Discover");
        assert_eq!(issuer("3530111333300000"), "JCB");
        assert_eq!(issuer("6200000000000005"), "UnionPay");
    }

    #[test]
    fn invalid_luhn_is_reported_invalid() {
        let d = detect("4111111111111112").unwrap();
        assert_eq!(d.checksum, Checksum::Invalid);
    }

    #[test]
    fn too_short_long_or_lettered_is_none() {
        assert!(detect("41111").is_none());
        assert!(detect("41111111111111111111").is_none());
        assert!(detect("4111abcd11111111").is_none());
    }
}
