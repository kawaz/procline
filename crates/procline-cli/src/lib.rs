//! The command line of the `procline` command: its grammar, the `--help` text and the shell completion, all built from the same tables.
//!
//! The binary (`src/main.rs`) runs what [`parse`] returns. This library exists so that the tests can read the tables the parser, the help and the completion share; it is not an API for other crates.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fmt;

/// The name of the command.
pub const PROGRAM: &str = "procline";

/// One option as the help and the completion show it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionSpec {
    /// The long name with the leading `--`.
    pub name: &'static str,
    /// The placeholder of the value, for an option that takes one.
    pub value: Option<&'static str>,
    pub description: &'static str,
}

/// One subcommand as the help and the completion show it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandSpec {
    pub name: &'static str,
    pub description: &'static str,
}

const ENV: &str = "--env";
const DIGEST: &str = "--digest";
const ALL_NAMES: &str = "--all-names";
const NO_SIGNATURE: &str = "--no-signature";
const MAX_ANCESTORS: &str = "--max-ancestors";
const HELP: &str = "--help";
const VERSION: &str = "--version";

/// The walk stops after this many ancestors unless `--max-ancestors` says otherwise.
pub const DEFAULT_MAX_ANCESTORS: usize = 64;

/// The options of collecting (`procline [options] <pid>`).
pub const COLLECT_OPTIONS: &[OptionSpec] = &[
    OptionSpec {
        name: ENV,
        value: None,
        description: "Collect every environment variable; values of secret-looking names are redacted (not collected by default)",
    },
    OptionSpec {
        name: DIGEST,
        value: None,
        description: "Hash the contents of each executable (sha256)",
    },
    OptionSpec {
        name: ALL_NAMES,
        value: None,
        description: "Fill in every user and group name of each id (reads the whole user and group databases, about 16 ms)",
    },
    OptionSpec {
        name: NO_SIGNATURE,
        value: None,
        description: "Skip verifying the code signatures (code_signing is null)",
    },
    OptionSpec {
        name: MAX_ANCESTORS,
        value: Some("<N>"),
        description: "Stop the walk after N ancestors (default 64)",
    },
];

/// The options every level accepts.
pub const GLOBAL_OPTIONS: &[OptionSpec] = &[
    OptionSpec {
        name: HELP,
        value: None,
        description: "Show this help",
    },
    OptionSpec {
        name: VERSION,
        value: None,
        description: "Show the version",
    },
];

const COMPLETION: &str = "completion";

/// The subcommands of the top level.
pub const COMMANDS: &[CommandSpec] = &[CommandSpec {
    name: COMPLETION,
    description: "Print the shell completion script",
}];

/// The shells `procline completion` prints a script for.
pub const COMPLETION_SHELLS: &[CommandSpec] = &[CommandSpec {
    name: "zsh",
    description: "Print the zsh completion script (load it with: source <(procline completion zsh))",
}];

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    Help(HelpPage),
    Version,
    Collect { pid: i32, options: CollectChoice },
    Completion(Shell),
}

/// A level of the command that has a help page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpPage {
    Top,
    Completion,
}

/// A shell `procline completion` prints a script for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Zsh,
}

/// The choices of collecting the command line makes; the binary turns them into the collect options of the OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectChoice {
    pub env: bool,
    pub digest: bool,
    pub all_names: bool,
    pub signature: bool,
    pub max_ancestors: usize,
}

impl Default for CollectChoice {
    fn default() -> Self {
        Self {
            env: false,
            digest: false,
            all_names: false,
            signature: true,
            max_ancestors: DEFAULT_MAX_ANCESTORS,
        }
    }
}

/// The command line does not follow the grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    NotUnicode,
    UnknownOption { page: HelpPage, option: String },
    UnexpectedValue { option: &'static str },
    MissingValue { option: &'static str },
    InvalidValue { option: &'static str, value: String },
    MissingPid,
    InvalidPid(String),
    ExtraArgument { page: HelpPage, argument: String },
    UnknownShell(String),
}

impl UsageError {
    /// The help page that explains what the command line should look like.
    pub fn page(&self) -> HelpPage {
        match self {
            Self::UnknownOption { page, .. } | Self::ExtraArgument { page, .. } => *page,
            Self::UnknownShell(_) => HelpPage::Completion,
            Self::NotUnicode
            | Self::UnexpectedValue { .. }
            | Self::MissingValue { .. }
            | Self::InvalidValue { .. }
            | Self::MissingPid
            | Self::InvalidPid(_) => HelpPage::Top,
        }
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUnicode => f.write_str("an argument is not valid UTF-8"),
            Self::UnknownOption { option, .. } => write!(f, "unknown option {option}"),
            Self::UnexpectedValue { option } => write!(f, "{option} takes no value"),
            Self::MissingValue { option } => write!(f, "{option} needs a value"),
            Self::InvalidValue { option, value } => {
                write!(f, "{option} needs a non-negative integer, not {value:?}")
            }
            Self::MissingPid => f.write_str("no pid given"),
            Self::InvalidPid(argument) => write!(
                f,
                "{argument:?} is neither a pid nor a command; pass the process id (e.g. `{PROGRAM} 1234`)"
            ),
            Self::ExtraArgument { argument, .. } => {
                write!(f, "unexpected argument {argument:?}")
            }
            Self::UnknownShell(shell) => write!(f, "no completion for the shell {shell:?}"),
        }
    }
}

/// Reads the arguments after the program name.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Invocation, UsageError> {
    let args = args
        .into_iter()
        .map(|arg| arg.into_string().map_err(|_| UsageError::NotUnicode))
        .collect::<Result<Vec<_>, _>>()?;
    match args.split_first() {
        None => Ok(Invocation::Help(HelpPage::Top)),
        Some((first, rest)) if first == COMPLETION => parse_completion(rest),
        Some(_) => parse_collect(&args),
    }
}

/// Design rationale: options may follow the pid (`procline 1234 --env`), and `--` ends the options. There is no parser crate: the grammar is a handful of long options, and the tables above drive the help and the completion, which a parser's own help would duplicate.
fn parse_collect(args: &[String]) -> Result<Invocation, UsageError> {
    let mut options = CollectChoice::default();
    let mut pid = None;
    let mut args = args.iter();
    let mut options_ended = false;
    while let Some(arg) = args.next() {
        if !options_ended && arg.starts_with('-') {
            let (name, inline) = match arg.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (arg.as_str(), None),
            };
            match name {
                "--" if inline.is_none() => options_ended = true,
                HELP => return no_value(HELP, inline).map(|()| Invocation::Help(HelpPage::Top)),
                VERSION => return no_value(VERSION, inline).map(|()| Invocation::Version),
                ENV => no_value(ENV, inline).map(|()| options.env = true)?,
                DIGEST => no_value(DIGEST, inline).map(|()| options.digest = true)?,
                ALL_NAMES => no_value(ALL_NAMES, inline).map(|()| options.all_names = true)?,
                NO_SIGNATURE => {
                    no_value(NO_SIGNATURE, inline).map(|()| options.signature = false)?
                }
                MAX_ANCESTORS => {
                    let value = match inline {
                        Some(value) => value,
                        None => args.next().ok_or(UsageError::MissingValue {
                            option: MAX_ANCESTORS,
                        })?,
                    };
                    options.max_ancestors =
                        value.parse().map_err(|_| UsageError::InvalidValue {
                            option: MAX_ANCESTORS,
                            value: value.to_owned(),
                        })?;
                }
                _ => {
                    return Err(UsageError::UnknownOption {
                        page: HelpPage::Top,
                        option: arg.clone(),
                    });
                }
            }
        } else if pid.is_some() {
            return Err(UsageError::ExtraArgument {
                page: HelpPage::Top,
                argument: arg.clone(),
            });
        } else {
            pid = Some(parse_pid(arg)?);
        }
    }
    let pid = pid.ok_or(UsageError::MissingPid)?;
    Ok(Invocation::Collect { pid, options })
}

fn no_value(option: &'static str, inline: Option<&str>) -> Result<(), UsageError> {
    match inline {
        None => Ok(()),
        Some(_) => Err(UsageError::UnexpectedValue { option }),
    }
}

/// A pid is the decimal digits of a non-negative `pid_t`.
fn parse_pid(arg: &str) -> Result<i32, UsageError> {
    if arg.is_empty() || !arg.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UsageError::InvalidPid(arg.to_owned()));
    }
    arg.parse()
        .map_err(|_| UsageError::InvalidPid(arg.to_owned()))
}

fn parse_completion(args: &[String]) -> Result<Invocation, UsageError> {
    let mut shell = None;
    for arg in args {
        match arg.as_str() {
            HELP => return Ok(Invocation::Help(HelpPage::Completion)),
            VERSION => return Ok(Invocation::Version),
            "zsh" if shell.is_none() => shell = Some(Shell::Zsh),
            option if option.starts_with('-') => {
                return Err(UsageError::UnknownOption {
                    page: HelpPage::Completion,
                    option: option.to_owned(),
                });
            }
            other if shell.is_some() => {
                return Err(UsageError::ExtraArgument {
                    page: HelpPage::Completion,
                    argument: other.to_owned(),
                });
            }
            other => return Err(UsageError::UnknownShell(other.to_owned())),
        }
    }
    Ok(shell.map_or(
        Invocation::Help(HelpPage::Completion),
        Invocation::Completion,
    ))
}

/// The `--help` text of a level: usage, subcommands, the options of the level, then the global options.
pub fn help(page: HelpPage) -> String {
    let (summary, usage, commands, options): (&str, &[&str], &[CommandSpec], &[OptionSpec]) =
        match page {
            HelpPage::Top => (
                "procline - print a process and its ancestors as JSON",
                &[
                    "procline [options] [--] <pid>",
                    "procline <command> [arguments]",
                ],
                COMMANDS,
                COLLECT_OPTIONS,
            ),
            HelpPage::Completion => (
                "procline completion - print the shell completion script",
                &["procline completion <shell>"],
                COMPLETION_SHELLS,
                &[],
            ),
        };
    let rows = |options: &[OptionSpec]| -> Vec<(String, &'static str)> {
        options
            .iter()
            .map(|option| (option_label(option), option.description))
            .collect()
    };
    let commands: Vec<(String, &str)> = commands
        .iter()
        .map(|command| (command.name.to_owned(), command.description))
        .collect();
    let options = rows(options);
    let globals = rows(GLOBAL_OPTIONS);
    let width = commands
        .iter()
        .chain(&options)
        .chain(&globals)
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);

    let mut text = format!("{summary}\n\nUsage:\n");
    for line in usage {
        text.push_str(&format!("  {line}\n"));
    }
    for (heading, rows) in [
        ("Commands", &commands),
        ("Options", &options),
        ("Global options", &globals),
    ] {
        if rows.is_empty() {
            continue;
        }
        text.push_str(&format!("\n{heading}:\n"));
        for (label, description) in rows {
            text.push_str(&format!("  {label:width$}  {description}\n"));
        }
    }
    text
}

fn option_label(option: &OptionSpec) -> String {
    match option.value {
        Some(value) => format!("{} {value}", option.name),
        None => option.name.to_owned(),
    }
}

/// The completion script of a shell.
pub fn completion(shell: Shell) -> String {
    match shell {
        Shell::Zsh => zsh_completion(),
    }
}

/// Builds the `_arguments` specs from the same tables as the help, so the completion offers exactly the options the parser takes.
fn zsh_completion() -> String {
    let global_specs: Vec<String> = GLOBAL_OPTIONS
        .iter()
        .map(|option| format!("'(- :){}'", zsh_option_spec(option)))
        .collect();
    let collect_specs: Vec<String> = COLLECT_OPTIONS
        .iter()
        .map(|option| format!("'{}'", zsh_option_spec(option)))
        .collect();
    let commands = zsh_describe_items(COMMANDS);
    let shells = zsh_describe_items(COMPLETION_SHELLS);
    let top = " \\\n    ";
    let nested = " \\\n      ";
    format!(
        r#"#compdef procline

_procline_pid_or_command() {{
  local -a commands
  commands=({commands})
  _describe -t commands 'command' commands
  _pids
}}

_procline() {{
  if [[ $words[2] == {COMPLETION} ]]; then
    shift words
    (( CURRENT-- ))
    local -a shells
    shells=({shells})
    _arguments{nested}{nested_globals}{nested}'1: :{{_describe -t shells shell shells}}'
    return
  fi
  _arguments -S{top}{globals}{top}{collects}{top}'1: :_procline_pid_or_command'
}}

if [[ $zsh_eval_context[-1] == loadautofunc ]]; then
  _procline "$@"
else
  compdef _procline procline
fi
"#,
        globals = global_specs.join(top),
        nested_globals = global_specs.join(nested),
        collects = collect_specs.join(top),
    )
}

/// The spec of an option for `_arguments`, to be put inside single quotes.
fn zsh_option_spec(option: &OptionSpec) -> String {
    let description = zsh_escape_description(option.description);
    match option.value {
        Some(value) => format!(
            "{}=[{description}]:{}: ",
            option.name,
            value.trim_matches(['<', '>'])
        ),
        None => format!("{}[{description}]", option.name),
    }
}

fn zsh_describe_items(items: &[CommandSpec]) -> String {
    items
        .iter()
        .map(|item| {
            format!(
                "'{}:{}'",
                item.name,
                item.description.replace('\'', r"'\''")
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Escapes a description for the `[...]` of an `_arguments` spec inside single quotes.
fn zsh_escape_description(description: &str) -> String {
    description
        .replace('\'', r"'\''")
        .replace('[', r"\[")
        .replace(']', r"\]")
        .replace(':', r"\:")
}
