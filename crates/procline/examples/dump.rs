//! Prints the collected chain of a process as JSON.
//!
//! Usage: `cargo run -p procline --example dump -- [--digest] [--env] [<pid>]`
//!
//! Without a pid it collects its own parent. `--digest` hashes each executable; `--env` collects every environment variable (redacted with the default rules).

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use procline::{CollectOptions, EnvPolicy, Redaction, collect_pid};
    use std::process::ExitCode;

    let mut digest = false;
    let mut env = EnvPolicy::None;
    let mut pid = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--digest" => digest = true,
            "--env" => env = EnvPolicy::All,
            other => match other.parse::<i32>() {
                Ok(p) if pid.is_none() => pid = Some(p),
                _ => {
                    eprintln!(
                        "usage: dump [--digest] [--env] [<pid>]  (unexpected argument {other:?})"
                    );
                    return ExitCode::from(2);
                }
            },
        }
    }
    let pid = match pid {
        Some(pid) => pid,
        None => match i32::try_from(std::os::unix::process::parent_id()) {
            Ok(pid) => pid,
            Err(_) => {
                eprintln!("dump: the parent pid does not fit in a pid; pass a pid");
                return ExitCode::FAILURE;
            }
        },
    };
    let options = CollectOptions {
        env,
        redaction: Redaction::default(),
        icon: false,
        digest,
        max_ancestors: 64,
    };
    let chain = match collect_pid(pid, &options) {
        Ok(chain) => chain,
        Err(err) => {
            eprintln!("dump: {err}");
            return ExitCode::FAILURE;
        }
    };
    match serde_json::to_string_pretty(&chain) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("dump: cannot serialize the chain: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("dump: collecting is implemented for macOS only");
    std::process::ExitCode::FAILURE
}
