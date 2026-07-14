//! Rendering: turn a [`Classification`] into human text or machine JSON, and
//! redact the token safely for display.
//!
//! JSON is emitted by hand (std-only, no serde) with correct string escaping.
//! Redaction is the default so that piping credtype output into a log or a
//! terminal share does not itself leak the secret.

use crate::registry::Classification;
use crate::token::{Checksum, Detection};

/// Redact a token for display: reveal a short leading context and the last few
/// characters, mask the middle. Short tokens are fully masked.
pub fn redact(token: &str) -> String {
    let token = token.trim();
    let n = token.chars().count();
    // Revealing the first 8 and last 4 chars only makes sense when at least
    // 4 chars stay masked; anything shorter is masked in full so the
    // "redacted" form can never reconstruct the secret.
    if n < 16 {
        return "*".repeat(n);
    }
    // Reveal up to the first 8 chars (covers vendor prefixes) and last 4.
    let head: String = token.chars().take(8).collect();
    let tail: String = token.chars().skip(n - 4).collect();
    format!("{head}{}{tail}", "*".repeat(n - 12))
}

/// JSON-escape a string per RFC 8259.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Render a single detection as a JSON object (no trailing newline).
fn detection_json(d: &Detection, redacted: &str) -> String {
    let mut s = String::new();
    s.push('{');
    s.push_str(&format!("\"id\":\"{}\",", esc(d.id)));
    s.push_str(&format!("\"name\":\"{}\",", esc(d.name)));
    s.push_str(&format!("\"category\":\"{}\",", d.category.label()));
    s.push_str(&format!("\"confidence\":\"{}\",", d.confidence.label()));
    s.push_str(&format!("\"structural_ok\":{},", d.structural_ok));
    s.push_str(&format!("\"checksum\":\"{}\",", d.checksum.slug()));
    s.push_str(&format!("\"length\":{},", d.length));
    s.push_str(&format!("\"redacted\":\"{}\",", esc(redacted)));

    s.push_str("\"details\":{");
    for (i, (k, v)) in d.details.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("\"{}\":\"{}\"", esc(k), esc(v)));
    }
    s.push_str("},");

    s.push_str("\"notes\":[");
    for (i, note) in d.notes.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("\"{}\"", esc(note)));
    }
    s.push(']');
    s.push('}');
    s
}

/// Full JSON document for a classification (single line + newline).
pub fn to_json(c: &Classification, token: &str) -> String {
    let redacted = redact(token);
    let mut s = String::new();
    s.push('{');
    s.push_str(&format!(
        "\"input_length\":{},",
        token.trim().chars().count()
    ));
    s.push_str(&format!("\"is_fallback\":{},", c.is_fallback));
    s.push_str("\"best\":");
    s.push_str(&detection_json(&c.best, &redacted));
    s.push_str(",\"alternates\":[");
    for (i, alt) in c.alternates.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&detection_json(alt, &redacted));
    }
    s.push(']');
    s.push('}');
    s.push('\n');
    s
}

/// Human-readable report. `explain` adds alternates and every note; when
/// `reveal` is true the full token is shown instead of the redacted form.
pub fn to_text(c: &Classification, token: &str, explain: bool, reveal: bool) -> String {
    let redacted = if reveal {
        token.trim().to_string()
    } else {
        redact(token)
    };
    let d = &c.best;
    let mut out = String::new();

    let checkmark = match d.checksum {
        Checksum::Valid => "[checksum OK]",
        Checksum::Invalid => "[checksum FAILED]",
        Checksum::Absent => "[no checksum]",
    };
    out.push_str(&format!("{}  {}\n", d.name, checkmark));
    out.push_str(&format!("  id:         {}\n", d.id));
    out.push_str(&format!("  category:   {}\n", d.category.label()));
    out.push_str(&format!("  confidence: {}\n", d.confidence.label()));
    out.push_str(&format!(
        "  structure:  {}\n",
        if d.structural_ok {
            "valid"
        } else {
            "MALFORMED"
        }
    ));
    out.push_str(&format!("  checksum:   {}\n", d.checksum.label()));
    out.push_str(&format!("  token:      {redacted} ({} chars)\n", d.length));

    if !d.details.is_empty() {
        out.push_str("  details:\n");
        for (k, v) in &d.details {
            out.push_str(&format!("    {k}: {v}\n"));
        }
    }

    // In normal mode show the first note; --explain shows all.
    if explain {
        for note in &d.notes {
            out.push_str(&format!("  note: {note}\n"));
        }
    } else if let Some(note) = d.notes.first() {
        out.push_str(&format!("  note: {note}\n"));
    }

    if explain && !c.alternates.is_empty() {
        out.push_str("\nother candidates:\n");
        for alt in &c.alternates {
            out.push_str(&format!(
                "  - {} ({}, {})\n",
                alt.name,
                alt.id,
                alt.checksum.label()
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::classify;
    use crate::{card, github};

    #[test]
    fn redact_masks_middle_keeps_ends() {
        let r = redact("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");
        assert!(r.starts_with("ghp_AAAA"));
        assert!(r.ends_with("CPlr"));
        assert!(r.contains('*'));
        assert_eq!(r.len(), "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".len());
    }

    #[test]
    fn redact_fully_masks_short_tokens_without_panicking() {
        // Lengths 9..=15 used to underflow `n - 12` (panic) or reveal the
        // whole token; every length below 16 must come back fully masked.
        for n in 1..16 {
            let tok: String = "a".repeat(n);
            assert_eq!(redact(&tok), "*".repeat(n), "length {n}");
        }
    }

    #[test]
    fn json_has_expected_top_level_keys() {
        let tok = github::sign("ghp_", "abcdefghijklmnopqrstuvwxyz0123");
        let c = classify(&tok);
        let j = to_json(&c, &tok);
        assert!(j.contains("\"best\":"));
        assert!(j.contains("\"checksum\":\"valid\""));
        assert!(j.contains("\"is_fallback\":false"));
        assert!(j.ends_with('\n'));
    }

    #[test]
    fn json_escapes_quotes_in_details() {
        // Feed a note that would break naive JSON if unescaped.
        let d = Detection::new(
            "x",
            "X\"Y",
            crate::token::Category::Generic,
            crate::token::Confidence::Low,
        )
        .note("line\nbreak");
        let out = detection_json(&d, "****");
        assert!(out.contains("X\\\"Y"));
        assert!(out.contains("line\\nbreak"));
    }

    #[test]
    fn json_does_not_contain_raw_secret() {
        let tok = card_number();
        let c = classify(&tok);
        let j = to_json(&c, &tok);
        assert!(!j.contains(&tok), "raw token must not appear in JSON");
    }

    #[test]
    fn text_report_marks_checksum_verdicts() {
        let tok = github::sign("gho_", "abcdefghijklmnopqrstuvwxyz0123");
        let c = classify(&tok);
        let t = to_text(&c, &tok, false, false);
        assert!(t.contains("[checksum OK]"));
        assert!(t.contains("category:"));

        let bad = classify("4111111111111112"); // bad Luhn
        assert!(to_text(&bad, "4111111111111112", false, false).contains("[checksum FAILED]"));
    }

    fn card_number() -> String {
        let d = card::detect("4111111111111111").unwrap();
        assert_eq!(d.checksum, Checksum::Valid);
        "4111111111111111".to_string()
    }
}
