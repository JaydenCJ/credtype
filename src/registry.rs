//! The detector registry: run every recogniser over one candidate token,
//! rank the hits, and fall back to an entropy description when nothing matches.
//!
//! This is the heart of the "file(1) for secrets" behaviour — one input, a
//! ranked answer, and an honest fallback that never guesses.

use crate::charset::{describe_charset, shannon_entropy};
use crate::token::{Category, Confidence, Detection, Detector};
use crate::{aws, card, github, jwt, pem, uuid, vendors};

/// All detectors, in a stable order. Ranking (not order) decides the winner,
/// but order makes ties deterministic.
pub const DETECTORS: &[Detector] = &[
    github::detect,
    aws::detect,
    jwt::detect,
    pem::detect,
    vendors::detect,
    uuid::detect,
    card::detect,
];

/// The outcome of classifying one token: the best match plus any weaker
/// alternates that also fired.
#[derive(Debug, Clone)]
pub struct Classification {
    pub best: Detection,
    pub alternates: Vec<Detection>,
    /// True when nothing matched and `best` is the generic fallback.
    pub is_fallback: bool,
}

/// Classify a single token. The input is trimmed of surrounding whitespace
/// first (a common copy/paste artefact) but never otherwise altered.
pub fn classify(raw: &str) -> Classification {
    let token = raw.trim();

    let mut hits: Vec<Detection> = DETECTORS.iter().filter_map(|d| d(token)).collect();

    // Rank: highest confidence, then verified checksum, then structural pass.
    hits.sort_by_key(|d| std::cmp::Reverse(d.rank()));

    if let Some(best) = hits.first().cloned() {
        let alternates = hits.into_iter().skip(1).collect();
        Classification {
            best,
            alternates,
            is_fallback: false,
        }
    } else {
        Classification {
            best: generic(token),
            alternates: Vec::new(),
            is_fallback: true,
        }
    }
}

/// The generic fallback: describe an unrecognised blob without claiming to know
/// what it is. High entropy over a compact alphabet suggests a secret.
fn generic(token: &str) -> Detection {
    let charset = describe_charset(token);
    let entropy = shannon_entropy(token);
    let looks_secret = token.len() >= 16
        && entropy >= 3.0
        && matches!(charset, "hex" | "base32" | "base62" | "base64url");

    let mut d = Detection::new(
        "unknown",
        "Unrecognised token",
        Category::Generic,
        Confidence::Low,
    )
    .with_length(token.len())
    .detail("charset", charset)
    .detail("entropy_bits_per_char", format!("{entropy:.2}"));

    d.structural_ok = false;
    if looks_secret {
        d.note("no known format matched, but high entropy over a compact alphabet — plausibly a secret")
    } else {
        d.note("no known token format matched")
    }
}

/// Every detector's advertised (id, name, category) for `credtype list`. The
/// vendor table contributes many rows; here we surface the fixed families.
pub fn known_families() -> Vec<(&'static str, &'static str, Category)> {
    vec![
        (
            "github-*",
            "GitHub tokens (classic + fine-grained; CRC-32 checked)",
            Category::Vendor,
        ),
        (
            "aws-access-key-id",
            "AWS access key ID (account-id decode)",
            Category::Cloud,
        ),
        (
            "jwt",
            "JSON Web Token (header/claims decode)",
            Category::Jwt,
        ),
        (
            "payment-card",
            "Payment card PAN (Luhn checked)",
            Category::Card,
        ),
        (
            "uuid",
            "UUID / GUID (version + variant)",
            Category::Identifier,
        ),
        ("pem-*", "PEM / OpenSSH private keys", Category::PrivateKey),
        (
            "stripe-*",
            "Stripe secret / publishable / webhook keys",
            Category::Vendor,
        ),
        (
            "slack-token",
            "Slack bot / user / app tokens",
            Category::Vendor,
        ),
        ("google-api-key", "Google API key", Category::Vendor),
        ("sendgrid-api-key", "SendGrid API key", Category::Vendor),
        ("npm-token", "npm access token", Category::Vendor),
        ("pypi-token", "PyPI upload token", Category::Vendor),
        (
            "gitlab-pat",
            "GitLab personal access token",
            Category::Vendor,
        ),
        (
            "openai-key / anthropic-key",
            "LLM provider API keys",
            Category::Vendor,
        ),
        ("shopify-token", "Shopify access tokens", Category::Vendor),
        ("twilio-*", "Twilio account SID / API key", Category::Vendor),
        ("digitalocean-token", "DigitalOcean PAT", Category::Vendor),
        ("square-token", "Square access token", Category::Vendor),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::Checksum;

    #[test]
    fn github_token_beats_generic() {
        let tok = github::sign("ghp_", "abcdefghijklmnopqrstuvwxyz0123");
        let c = classify(&tok);
        assert_eq!(c.best.id, "github-pat");
        assert_eq!(c.best.checksum, Checksum::Valid);
        assert!(!c.is_fallback);
    }

    #[test]
    fn unknown_falls_back_to_generic() {
        let c = classify("just plain words here");
        assert!(c.is_fallback);
        assert_eq!(c.best.id, "unknown");
        assert_eq!(c.best.category, Category::Generic);
    }

    #[test]
    fn high_entropy_hex_flagged_as_plausible_secret() {
        let c = classify("9f8e7d6c5b4a39281706f5e4d3c2b1a0");
        assert!(c.is_fallback);
        assert!(c
            .best
            .notes
            .iter()
            .any(|n| n.contains("plausibly a secret")));
    }

    #[test]
    fn ranking_prefers_valid_checksum() {
        // A valid card outranks a same-shape generic; verify a valid-luhn PAN
        // is reported with a valid checksum and high confidence.
        let c = classify("4111111111111111");
        assert_eq!(c.best.id, "payment-card");
        assert_eq!(c.best.checksum, Checksum::Valid);
        assert_eq!(c.best.confidence, Confidence::High);
    }

    #[test]
    fn known_families_are_nonempty_and_unique() {
        let fams = known_families();
        assert!(fams.len() >= 15);
        let mut ids: Vec<&str> = fams.iter().map(|(id, _, _)| *id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len());
    }
}
