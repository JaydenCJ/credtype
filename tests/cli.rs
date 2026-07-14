//! End-to-end tests that exercise the compiled `credtype` binary: identifying
//! real token shapes, verifying embedded checksums, decoding structure, the
//! JSON and `list` surfaces, stdin input, redaction, and the scriptable exit
//! codes. Everything is offline and deterministic — tokens are built in-process
//! (never real secrets) via the library's own `github::sign` helper.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_credtype")
}

/// Run the binary with args and no stdin.
fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run credtype binary")
}

/// Run the binary feeding `input` on stdin.
fn run_stdin(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn credtype");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait credtype")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

/// A deterministic, structurally-valid classic GitHub token (never a real one).
fn github_token(prefix: &str) -> String {
    credtype::github::sign(prefix, "abcdefghijklmnopqrstuvwxyz0123")
}

#[test]
fn version_and_help() {
    let v = run(&["--version"]);
    assert!(v.status.success());
    assert_eq!(
        stdout(&v).trim(),
        format!("credtype {}", env!("CARGO_PKG_VERSION"))
    );

    let h = run(&["--help"]);
    assert!(h.status.success());
    let text = stdout(&h);
    assert!(text.contains("USAGE:"));
    assert!(text.contains("EXIT CODES:"));
    for cmd in ["--stdin", "--json", "list"] {
        assert!(text.contains(cmd), "help must mention {cmd}");
    }
}

#[test]
fn valid_github_token_identified_and_exits_zero() {
    let tok = github_token("ghp_");
    let out = run(&[&tok]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("GitHub personal access token"));
    assert!(text.contains("[checksum OK]"));
    // The raw secret must never appear in default (redacted) output.
    assert!(!text.contains(&tok));
}

#[test]
fn tampered_github_token_fails_checksum_and_exits_one() {
    let tok = github_token("ghs_");
    // Flip a body character so the embedded CRC-32 no longer matches.
    let flipped = if tok.as_bytes()[8] == b'z' { "a" } else { "z" };
    let tok = format!("{}{}{}", &tok[..8], flipped, &tok[9..]);
    let out = run(&[&tok]);
    assert_eq!(out.status.code(), Some(1), "failed checksum must exit 1");
    assert!(stdout(&out).contains("[checksum FAILED]"));
}

#[test]
fn json_output_carries_verdict_and_no_secret() {
    let tok = github_token("gho_");
    let out = run(&["--json", &tok]);
    assert_eq!(out.status.code(), Some(0));
    let j = stdout(&out);
    assert!(j.starts_with('{') && j.trim_end().ends_with('}'));
    assert!(j.contains("\"id\":\"github-oauth\""));
    assert!(j.contains("\"checksum\":\"valid\""));
    assert!(!j.contains(&tok), "JSON must not leak the raw token");
}

#[test]
fn aws_key_decodes_account_id() {
    let out = run(&["--json", "AKIAIOSFODNN7EXAMPLE"]);
    assert_eq!(out.status.code(), Some(0));
    let j = stdout(&out);
    assert!(j.contains("\"id\":\"aws-access-key-id\""));
    assert!(
        j.contains("\"account_id\":\""),
        "account id should be decoded"
    );
}

#[test]
fn jwt_alg_none_is_flagged_and_exits_one() {
    // header {"alg":"none"} . payload {"x":1} . (empty signature)
    let tok = "eyJhbGciOiJub25lIn0.eyJ4IjoxfQ.";
    let out = run(&["--explain", tok]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(text.contains("JSON Web Token"));
    assert!(text.contains("UNSIGNED"));
}

#[test]
fn payment_card_validates_luhn() {
    let ok = run(&["4111111111111111"]);
    assert_eq!(ok.status.code(), Some(0));
    assert!(stdout(&ok).contains("Payment card"));
    assert!(stdout(&ok).contains("[checksum OK]"));

    let bad = run(&["4111111111111112"]);
    assert_eq!(bad.status.code(), Some(1));
}

#[test]
fn unknown_token_exits_two() {
    let out = run(&["this is not a token at all"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stdout(&out).contains("Unrecognised"));
}

#[test]
fn list_command_enumerates_families() {
    let out = run(&["list"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("payment-card"));
    assert!(text.contains("aws-access-key-id"));
    assert!(text.contains("CRC-32"));
}

#[test]
fn reads_token_from_stdin() {
    let tok = github_token("ghp_");
    let out = run_stdin(&["--stdin"], &format!("{tok}\n"));
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("[checksum OK]"));
}

#[test]
fn no_redact_reveals_full_token() {
    let tok = github_token("ghp_");
    let out = run(&["--no-redact", &tok]);
    assert!(stdout(&out).contains(&tok));
}

#[test]
fn unknown_option_is_usage_error() {
    let out = run(&["--nope"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown option"));
}
