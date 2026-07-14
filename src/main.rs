//! credtype binary entry point: forward argv (minus the program name) to
//! [`credtype::cli::run`] and exit with the code it returns.

use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let stderr = io::stderr();
    let mut err = stderr.lock();

    let code = credtype::cli::run(&args, &mut input, &mut out, &mut err);
    let _ = out.flush();
    let _ = err.flush();
    ExitCode::from(code as u8)
}
