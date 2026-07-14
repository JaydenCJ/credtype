//! Self-contained checksum algorithms used to *validate* tokens, not just
//! recognise them: CRC-32 (IEEE, as embedded in GitHub token formats) and the
//! Luhn mod-10 check used by payment cards.
//!
//! Both are deterministic and offline. They are what lets credtype answer the
//! second half of "what key is this and is it real?".

/// Compute the IEEE CRC-32 of `data` (polynomial 0xEDB88320, reflected),
/// the variant embedded in GitHub's token checksum scheme.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Verify the Luhn (mod-10) check digit of a string of ASCII digits.
///
/// Returns `false` if the string contains a non-digit or is shorter than two
/// digits (a single digit has no meaningful check digit).
pub fn luhn_valid(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    if bytes.len() < 2 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    // Walk right-to-left, doubling every second digit.
    for &b in bytes.iter().rev() {
        if !b.is_ascii_digit() {
            return false;
        }
        let mut d = (b - b'0') as u32;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_of_empty_is_zero() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc32_known_vector_123456789() {
        // The canonical CRC-32/ISO-HDLC check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_of_the_fox_matches_reference() {
        // "The quick brown fox jumps over the lazy dog"
        let v = crc32(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(v, 0x414F_A339);
    }

    #[test]
    fn luhn_accepts_known_test_cards() {
        assert!(luhn_valid("4111111111111111")); // Visa
        assert!(luhn_valid("378282246310005")); // Amex
        assert!(luhn_valid("5555555555554444")); // Mastercard
    }

    #[test]
    fn luhn_textbook_example() {
        // 79927398713 is the textbook Luhn-valid example.
        assert!(luhn_valid("79927398713"));
        assert!(!luhn_valid("79927398710"));
    }

    #[test]
    fn luhn_rejects_off_by_one_and_non_digits() {
        assert!(!luhn_valid("4111111111111112"));
        assert!(!luhn_valid("4111-1111"));
        assert!(!luhn_valid("4"));
        assert!(!luhn_valid(""));
    }
}
