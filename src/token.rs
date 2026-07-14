//! Core value types shared by every detector: the classification result
//! ([`Detection`]), the strength of a checksum verdict ([`Checksum`]), the
//! broad family a token belongs to ([`Category`]) and the recogniser's
//! confidence ([`Confidence`]).
//!
//! A detector is a pure function `fn(&str) -> Option<Detection>` (see
//! [`Detector`]). It never performs I/O and never touches the network; it
//! only inspects the candidate string and reports what it can prove.

use std::fmt;

/// Verdict for a token's embedded integrity check.
///
/// The distinction between [`Checksum::Absent`] and [`Checksum::Invalid`] is
/// the whole point of credtype: "this family carries no checksum" is a very
/// different statement from "this string claims to be an X but its checksum
/// does not verify, so it is malformed or fabricated".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    /// A real checksum was present in the token and it verified.
    Valid,
    /// A real checksum was present and it did **not** verify.
    Invalid,
    /// This token family defines no self-contained checksum (verifying it
    /// would require a secret or a network call, which credtype never does).
    Absent,
}

impl Checksum {
    /// Human label used in text output.
    pub fn label(self) -> &'static str {
        match self {
            Checksum::Valid => "valid",
            Checksum::Invalid => "INVALID",
            Checksum::Absent => "none (no self-contained checksum)",
        }
    }

    /// Stable machine token used in JSON output.
    pub fn slug(self) -> &'static str {
        match self {
            Checksum::Valid => "valid",
            Checksum::Invalid => "invalid",
            Checksum::Absent => "absent",
        }
    }
}

/// Broad family a token belongs to, used for grouping in `credtype list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Cloud provider credential (AWS, GCP, Azure…).
    Cloud,
    /// SaaS / vendor API key (Stripe, Slack, GitHub…).
    Vendor,
    /// JSON Web Token / JOSE object.
    Jwt,
    /// Payment card primary account number.
    Card,
    /// Structured identifier (UUID, ULID…).
    Identifier,
    /// Private key material (PEM / OpenSSH).
    PrivateKey,
    /// Unrecognised high-or-low-entropy blob (the file(1) fallback).
    Generic,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Cloud => "cloud",
            Category::Vendor => "vendor",
            Category::Jwt => "jwt",
            Category::Card => "card",
            Category::Identifier => "identifier",
            Category::PrivateKey => "private-key",
            Category::Generic => "generic",
        }
    }
}

/// How sure the detector is that the token really is this kind.
///
/// Confidence drives ranking when several detectors fire on one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Weak signal — matched only by shape/entropy (the generic fallback).
    Low = 0,
    /// Distinctive format but no verifiable checksum.
    Medium = 1,
    /// Distinctive format **and** a verified embedded checksum.
    High = 2,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// One key/value fact extracted from the token (e.g. `("account_id", "…")`).
pub type Detail = (String, String);

/// The result of one detector recognising a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Stable slug, e.g. `"github-pat"`. Used by `--json` and `list`.
    pub id: &'static str,
    /// Human name, e.g. `"GitHub personal access token"`.
    pub name: &'static str,
    /// Broad family.
    pub category: Category,
    /// Recogniser confidence.
    pub confidence: Confidence,
    /// Whether prefix, alphabet and length all check out.
    pub structural_ok: bool,
    /// Verdict on the embedded checksum, if any.
    pub checksum: Checksum,
    /// Token length in characters.
    pub length: usize,
    /// Extracted facts (account id, JWT `alg`, card issuer, …).
    pub details: Vec<Detail>,
    /// Free-form advisory notes (honest caveats, e.g. "alg=none").
    pub notes: Vec<String>,
}

impl Detection {
    /// Start a detection with the mandatory identity fields; the builder
    /// methods below fill in the rest.
    pub fn new(
        id: &'static str,
        name: &'static str,
        category: Category,
        confidence: Confidence,
    ) -> Self {
        Detection {
            id,
            name,
            category,
            confidence,
            structural_ok: true,
            checksum: Checksum::Absent,
            length: 0,
            details: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn with_length(mut self, len: usize) -> Self {
        self.length = len;
        self
    }

    pub fn with_checksum(mut self, c: Checksum) -> Self {
        self.checksum = c;
        // A verified checksum is the strongest possible signal.
        if c == Checksum::Valid {
            self.confidence = Confidence::High;
        }
        self
    }

    pub fn detail(mut self, key: &str, value: impl Into<String>) -> Self {
        self.details.push((key.to_string(), value.into()));
        self
    }

    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// A ranking key: higher sorts first. Confidence dominates, then a
    /// verified checksum, then structural validity.
    pub fn rank(&self) -> (u8, u8, u8) {
        let conf = self.confidence as u8;
        let chk = match self.checksum {
            Checksum::Valid => 2,
            Checksum::Absent => 1,
            Checksum::Invalid => 0,
        };
        (conf, chk, self.structural_ok as u8)
    }
}

impl fmt::Display for Detection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.id)
    }
}

/// A detector: a pure recogniser over a candidate string.
pub type Detector = fn(&str) -> Option<Detection>;
