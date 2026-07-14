//! Prefix-anchored vendor API-key detector (table-driven).
//!
//! Many SaaS credentials are recognisable by a distinctive prefix plus a fixed
//! alphabet and length, but carry no self-contained checksum. credtype
//! recognises them structurally and reports [`Checksum::Absent`] honestly —
//! never pretending to validate something it cannot.
//!
//! Adding a vendor is one row in [`SPECS`]; each row is deliberately narrow to
//! avoid false positives.

use crate::charset::{is_base62, is_base64url, is_hex};
use crate::token::{Category, Checksum, Confidence, Detection};

/// Alphabet the body after the prefix must match.
#[derive(Clone, Copy)]
enum Body {
    Base62,
    Base64Url,
    Hex,
    /// Base62 plus `_` and `-` (segmented keys like `sk_live_…`, `sk-proj-…`).
    Base62Underscore,
    /// Any non-empty run (used where a vendor mixes separators).
    Any,
}

impl Body {
    fn accepts(self, s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        match self {
            Body::Base62 => is_base62(s),
            Body::Base64Url => is_base64url(s),
            Body::Hex => is_hex(s),
            Body::Base62Underscore => s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            Body::Any => true,
        }
    }
}

/// One vendor recognition rule.
struct Spec {
    id: &'static str,
    name: &'static str,
    category: Category,
    prefixes: &'static [&'static str],
    body: Body,
    /// Inclusive total-length bounds; `(0, 0)` means "unbounded".
    len: (usize, usize),
    note: &'static str,
}

/// The vendor table. Ordered roughly by how distinctive the prefix is.
const SPECS: &[Spec] = &[
    Spec {
        id: "stripe-secret-key",
        name: "Stripe secret key",
        category: Category::Vendor,
        prefixes: &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
        body: Body::Base62,
        len: (20, 255),
        note: "live keys grant full API access — rotate immediately if leaked",
    },
    Spec {
        id: "stripe-publishable-key",
        name: "Stripe publishable key",
        category: Category::Vendor,
        prefixes: &["pk_live_", "pk_test_"],
        body: Body::Base62,
        len: (20, 255),
        note: "publishable keys are client-side and low-sensitivity",
    },
    Spec {
        id: "stripe-webhook-secret",
        name: "Stripe webhook signing secret",
        category: Category::Vendor,
        prefixes: &["whsec_"],
        body: Body::Base62,
        len: (20, 255),
        note: "used to verify inbound webhook signatures",
    },
    Spec {
        id: "slack-token",
        name: "Slack token",
        category: Category::Vendor,
        prefixes: &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-"],
        body: Body::Any,
        len: (20, 255),
        note: "bot/user/app token; segments are dash-separated",
    },
    Spec {
        id: "google-api-key",
        name: "Google API key",
        category: Category::Vendor,
        prefixes: &["AIza"],
        body: Body::Base64Url,
        len: (39, 39),
        note: "39-char Google API key (AIza + 35 chars)",
    },
    Spec {
        id: "sendgrid-api-key",
        name: "SendGrid API key",
        category: Category::Vendor,
        prefixes: &["SG."],
        body: Body::Any,
        len: (60, 80),
        note: "SG.<22>.<43>; two dot-separated Base64url segments",
    },
    Spec {
        id: "npm-token",
        name: "npm access token",
        category: Category::Vendor,
        prefixes: &["npm_"],
        body: Body::Base62,
        len: (40, 40),
        note: "npm_ + 36 Base62 chars",
    },
    Spec {
        id: "pypi-token",
        name: "PyPI upload token",
        category: Category::Vendor,
        prefixes: &["pypi-"],
        body: Body::Base64Url,
        len: (20, 255),
        note: "pypi-AgEI…; Base64url-encoded macaroon",
    },
    Spec {
        id: "gitlab-pat",
        name: "GitLab personal access token",
        category: Category::Vendor,
        prefixes: &["glpat-"],
        body: Body::Base64Url,
        len: (26, 60),
        note: "glpat- + 20-char token",
    },
    // Anthropic must precede the OpenAI `sk-` rule: `sk-ant-` also starts `sk-`.
    Spec {
        id: "anthropic-key",
        name: "Anthropic API key",
        category: Category::Vendor,
        prefixes: &["sk-ant-"],
        body: Body::Base62Underscore,
        len: (20, 255),
        note: "sk-ant-… API key",
    },
    Spec {
        id: "openai-key",
        name: "OpenAI API key",
        category: Category::Vendor,
        prefixes: &["sk-proj-", "sk-"],
        body: Body::Base62Underscore,
        len: (20, 255),
        note: "legacy sk-/sk-proj- keys carry no self-contained checksum",
    },
    Spec {
        id: "shopify-token",
        name: "Shopify access token",
        category: Category::Vendor,
        prefixes: &["shpat_", "shpss_", "shpca_", "shppa_"],
        body: Body::Hex,
        len: (38, 38),
        note: "shp*_ + 32 hex chars",
    },
    Spec {
        id: "square-token",
        name: "Square access token",
        category: Category::Vendor,
        prefixes: &["sq0atp-", "sq0csp-", "EAAA"],
        body: Body::Any,
        len: (20, 255),
        note: "Square OAuth or personal access token",
    },
    Spec {
        id: "twilio-api-key",
        name: "Twilio API key SID",
        category: Category::Vendor,
        prefixes: &["SK"],
        body: Body::Hex,
        len: (34, 34),
        note: "SK + 32 hex chars",
    },
    Spec {
        id: "twilio-account-sid",
        name: "Twilio account SID",
        category: Category::Vendor,
        prefixes: &["AC"],
        body: Body::Hex,
        len: (34, 34),
        note: "AC + 32 hex chars",
    },
    Spec {
        id: "digitalocean-token",
        name: "DigitalOcean personal access token",
        category: Category::Vendor,
        prefixes: &["dop_v1_", "doo_v1_", "dor_v1_"],
        body: Body::Hex,
        len: (60, 80),
        note: "dop_v1_ + 64 hex chars",
    },
];

/// Recognise a vendor token by prefix, alphabet and length.
pub fn detect(token: &str) -> Option<Detection> {
    for spec in SPECS {
        let Some(prefix) = spec.prefixes.iter().find(|p| token.starts_with(**p)) else {
            continue;
        };
        let body = &token[prefix.len()..];
        let mut d = Detection::new(spec.id, spec.name, spec.category, Confidence::Medium)
            .with_length(token.len())
            .detail("prefix", *prefix)
            .detail("checksum", "none (structural recognition only)");

        let len_ok = spec.len == (0, 0) || (spec.len.0..=spec.len.1).contains(&token.len());
        let charset_ok = spec.body.accepts(body);
        if !len_ok || !charset_ok {
            d.structural_ok = false;
            let reason = if !len_ok {
                format!(
                    "length {} outside expected {}–{}",
                    token.len(),
                    spec.len.0,
                    spec.len.1
                )
            } else {
                "body characters outside the expected alphabet".to_string()
            };
            return Some(d.note(reason));
        }
        return Some(d.with_checksum(Checksum::Absent).note(spec.note));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripe_live_secret_recognised() {
        let tok = format!("sk_live_{}", "a".repeat(24));
        let d = detect(&tok).unwrap();
        assert_eq!(d.id, "stripe-secret-key");
        assert!(d.structural_ok);
        assert_eq!(d.checksum, Checksum::Absent);
    }

    #[test]
    fn slack_bot_token_recognised() {
        let tok = "xoxb-1234567890-abcdefghijklmnop";
        let d = detect(tok).unwrap();
        assert_eq!(d.id, "slack-token");
    }

    #[test]
    fn google_api_key_needs_exact_length() {
        let ok = format!("AIza{}", "a".repeat(35));
        assert!(detect(&ok).unwrap().structural_ok);
        let bad = format!("AIza{}", "a".repeat(30));
        assert!(!detect(&bad).unwrap().structural_ok);
    }

    #[test]
    fn shopify_requires_hex_body() {
        let ok = format!("shpat_{}", "0123456789abcdef".repeat(2));
        assert!(detect(&ok).unwrap().structural_ok);
        let bad = format!("shpat_{}", "z".repeat(32));
        assert!(!detect(&bad).unwrap().structural_ok);
    }

    #[test]
    fn openai_and_anthropic_disambiguated() {
        let ant = format!("sk-ant-{}", "a".repeat(40));
        assert_eq!(detect(&ant).unwrap().id, "anthropic-key");
        let oai = format!("sk-{}", "a".repeat(40));
        assert_eq!(detect(&oai).unwrap().id, "openai-key");
    }

    #[test]
    fn unrelated_token_is_none() {
        assert!(detect("just-some-text").is_none());
    }

    #[test]
    fn every_spec_id_is_unique() {
        // Guards against copy/paste duplicates in the table.
        let mut ids: Vec<&str> = SPECS.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate spec id in SPECS");
    }
}
