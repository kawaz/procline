//! `procline`: prints a process and its ancestors as JSON. `procline --help` lists the options.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use procline_cli::{Invocation, PROGRAM, UsageError, completion, help, parse};

/// The exit code of a command line that does not follow the grammar.
const USAGE_EXIT: u8 = 2;

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Help(page)) => print(&help(page)),
        Ok(Invocation::Version) => print(&format!("{PROGRAM} {}\n", env!("CARGO_PKG_VERSION"))),
        Ok(Invocation::Completion(shell)) => print(&completion(shell)),
        Ok(Invocation::Collect { pid, options }) => collect::run(pid, &options),
        Err(err) => usage_error(&err),
    }
}

fn usage_error(err: &UsageError) -> ExitCode {
    let page = match err.page() {
        procline_cli::HelpPage::Top => PROGRAM.to_owned(),
        procline_cli::HelpPage::Completion => format!("{PROGRAM} completion"),
    };
    eprintln!("{PROGRAM}: {err}\nRun `{page} --help` for the usage.");
    ExitCode::from(USAGE_EXIT)
}

fn print(text: &str) -> ExitCode {
    match std::io::stdout().lock().write_all(text.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{PROGRAM}: cannot write to the standard output: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "macos")]
mod collect {
    use std::process::ExitCode;

    use procline::{CollectError, CollectOptions, EnvPolicy, Redaction, collect_pid};
    use procline_cli::{CollectChoice, PROGRAM, escape_terminal_controls};

    pub(crate) fn run(pid: i32, choice: &CollectChoice) -> ExitCode {
        let options = CollectOptions {
            env: if choice.env {
                EnvPolicy::All
            } else {
                EnvPolicy::None
            },
            redaction: Redaction::default(),
            icon: false,
            digest: choice.digest,
            bundle: true,
            signature: choice.signature,
            signature_budget: None,
            all_names: choice.all_names,
            max_ancestors: choice.max_ancestors,
        };
        let chain = match collect_pid(pid, &options) {
            Ok(chain) => chain,
            Err(err) => {
                eprintln!("{PROGRAM}: {err}\n{}", next_step(&err));
                return ExitCode::FAILURE;
            }
        };
        match serde_json::to_string_pretty(&chain) {
            Ok(json) => super::print(&format!("{}\n", escape_terminal_controls(&json))),
            Err(err) => {
                eprintln!("{PROGRAM}: cannot write the chain as JSON: {err}");
                ExitCode::FAILURE
            }
        }
    }

    /// What to do about a failed collection.
    fn next_step(err: &CollectError) -> String {
        match err {
            CollectError::NoSuchProcess { pid } => {
                format!("Check that the process is running (`ps -p {pid}`) and pass its pid.")
            }
            CollectError::Unreadable { .. } => {
                "Check that the process may be inspected by this user, or run as root.".to_owned()
            }
            CollectError::IdentityChanged => "Run the command again.".to_owned(),
            CollectError::BootUuid(_) => {
                "The system did not answer as expected; run the command again, and report it if it keeps failing.".to_owned()
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod collect {
    use std::process::ExitCode;

    use procline_cli::{CollectChoice, PROGRAM};

    pub(crate) fn run(_pid: i32, _choice: &CollectChoice) -> ExitCode {
        eprintln!(
            "{PROGRAM}: collecting is implemented for macOS only; this OS is not supported yet"
        );
        ExitCode::FAILURE
    }
}
