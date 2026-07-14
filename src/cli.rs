//! Command-line parsing and the top-level `run` entry point.
//!
//! credtype takes exactly one token (as an argument, or on stdin with `-` /
//! `--stdin`) and prints its classification. The exit code is scriptable:
//!
//! | Code | Meaning                                            |
//! |------|----------------------------------------------------|
//! | 0    | recognised, and the checksum is valid or absent    |
//! | 1    | recognised, but an embedded checksum FAILED        |
//! | 2    | not recognised (generic fallback)                  |
//! | 3    | usage error                                        |

use std::io::{Read, Write};

use crate::registry::{classify, known_families};
use crate::report;
use crate::token::Checksum;
use crate::VERSION;

/// Parsed command-line options.
struct Opts {
    token: Option<String>,
    from_stdin: bool,
    json: bool,
    explain: bool,
    reveal: bool,
    quiet: bool,
    list: bool,
}

impl Opts {
    fn empty() -> Self {
        Opts {
            token: None,
            from_stdin: false,
            json: false,
            explain: false,
            reveal: false,
            quiet: false,
            list: false,
        }
    }
}

const HELP: &str = "\
credtype — file(1) for secrets: identify and checksum-validate one token, offline.

USAGE:
    credtype [OPTIONS] <TOKEN>
    credtype [OPTIONS] --stdin
    credtype list

ARGS:
    <TOKEN>          The single token to classify. Use '-' to read from stdin.

OPTIONS:
    --stdin          Read the token from standard input (trailing newline trimmed).
    --json           Emit a single JSON object instead of text.
    -e, --explain    Show every note and all alternate candidates.
    --no-redact      Print the full token in the report (default: redacted).
    -q, --quiet      Print only the detected id (or 'unknown').
    -h, --help       Show this help.
    -V, --version    Show the version.

COMMANDS:
    list             List the token families credtype recognises.

EXIT CODES:
    0  recognised, checksum valid or absent
    1  recognised, checksum FAILED
    2  unrecognised
    3  usage error
";

/// Parse argv (excluding the program name) into [`Opts`], or an error message.
fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::empty();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-h" | "--help" => return Err("__help__".to_string()),
            "-V" | "--version" => return Err("__version__".to_string()),
            "--stdin" => o.from_stdin = true,
            "--json" => o.json = true,
            "-e" | "--explain" => o.explain = true,
            "--no-redact" => o.reveal = true,
            "-q" | "--quiet" => o.quiet = true,
            "list" if positional.is_empty() => o.list = true,
            "-" => o.from_stdin = true,
            s if s.starts_with("--") => return Err(format!("unknown option '{s}'")),
            s => positional.push(s.to_string()),
        }
        i += 1;
    }
    if positional.len() > 1 {
        return Err("expected a single token; pass one argument or use --stdin".to_string());
    }
    o.token = positional.into_iter().next();
    Ok(o)
}

/// Print the recognised families table for `credtype list`.
fn print_list(out: &mut impl Write) {
    let _ = writeln!(out, "credtype recognises these token families:\n");
    for (id, desc, cat) in known_families() {
        let _ = writeln!(out, "  {:<28} {:<12} {}", id, cat.label(), desc);
    }
    let _ = writeln!(
        out,
        "\nChecksum-validated families: github-* (CRC-32), payment-card (Luhn),\n\
         openssh-private (magic). Others are recognised structurally."
    );
}

/// Run credtype. `args` excludes the program name. Returns the process exit
/// code. All output goes through the provided writers so tests can capture it.
pub fn run(
    args: &[String],
    stdin: &mut impl Read,
    out: &mut impl Write,
    err: &mut impl Write,
) -> i32 {
    let opts = match parse(args) {
        Ok(o) => o,
        Err(msg) if msg == "__help__" => {
            let _ = write!(out, "{HELP}");
            return 0;
        }
        Err(msg) if msg == "__version__" => {
            let _ = writeln!(out, "credtype {VERSION}");
            return 0;
        }
        Err(msg) => {
            let _ = writeln!(err, "error: {msg}");
            let _ = writeln!(err, "run 'credtype --help' for usage");
            return 3;
        }
    };

    if opts.list {
        print_list(out);
        return 0;
    }

    // Resolve the token: `--stdin` (or `-`) reads standard input; otherwise
    // the positional argument is the token. Requiring one of the two keeps a
    // bare `credtype` from silently blocking on an interactive terminal.
    let token = if opts.from_stdin {
        let mut buf = String::new();
        if stdin.read_to_string(&mut buf).is_err() {
            let _ = writeln!(err, "error: could not read token from stdin");
            return 3;
        }
        if buf.trim().is_empty() {
            let _ = writeln!(err, "error: no token provided on stdin");
            let _ = writeln!(err, "run 'credtype --help' for usage");
            return 3;
        }
        buf
    } else if let Some(tok) = opts.token.clone() {
        tok
    } else {
        let _ = writeln!(
            err,
            "error: no token provided; pass one as an argument or use --stdin"
        );
        let _ = writeln!(err, "run 'credtype --help' for usage");
        return 3;
    };

    let classification = classify(&token);

    if opts.quiet {
        let _ = writeln!(out, "{}", classification.best.id);
    } else if opts.json {
        let _ = write!(out, "{}", report::to_json(&classification, &token));
    } else {
        let _ = write!(
            out,
            "{}",
            report::to_text(&classification, &token, opts.explain, opts.reveal)
        );
    }

    // Exit code from the verdict.
    if classification.is_fallback {
        2
    } else if classification.best.checksum == Checksum::Invalid {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github;
    use std::io::Cursor;

    fn call(args: &[&str], stdin: &str) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut input = Cursor::new(stdin.as_bytes().to_vec());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args, &mut input, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn version_flag() {
        let (code, out, _) = call(&["--version"], "");
        assert_eq!(code, 0);
        assert_eq!(out.trim(), format!("credtype {VERSION}"));
    }

    #[test]
    fn help_flag_lists_commands() {
        let (code, out, _) = call(&["--help"], "");
        assert_eq!(code, 0);
        assert!(out.contains("USAGE:"));
        assert!(out.contains("EXIT CODES:"));
    }

    #[test]
    fn valid_github_token_exits_zero() {
        let tok = github::sign("ghp_", "abcdefghijklmnopqrstuvwxyz0123");
        let (code, out, _) = call(&[&tok], "");
        assert_eq!(code, 0);
        assert!(out.contains("GitHub personal access token"));
        assert!(out.contains("[checksum OK]"));
    }

    #[test]
    fn failed_checksum_exits_one() {
        let (code, out, _) = call(&["4111111111111112"], "");
        assert_eq!(code, 1);
        assert!(out.contains("[checksum FAILED]"));
    }

    #[test]
    fn unknown_token_exits_two() {
        let (code, _, _) = call(&["hello world plain"], "");
        assert_eq!(code, 2);
    }

    #[test]
    fn no_arguments_is_usage_error_not_a_hang() {
        // A bare `credtype` must fail fast with usage guidance instead of
        // silently blocking on stdin (stdin is only read with --stdin / '-').
        let (code, _, err) = call(&[], "would-be-ignored");
        assert_eq!(code, 3);
        assert!(err.contains("--stdin"));
    }

    #[test]
    fn unknown_option_exits_three() {
        let (code, _, err) = call(&["--frobnicate"], "");
        assert_eq!(code, 3);
        assert!(err.contains("unknown option"));
    }

    #[test]
    fn default_output_is_redacted() {
        let tok = github::sign("ghp_", "abcdefghijklmnopqrstuvwxyz0123");
        let (_, out, _) = call(&[&tok], "");
        assert!(!out.contains(&tok), "raw token must not appear by default");
        assert!(out.contains('*'));
    }
}
