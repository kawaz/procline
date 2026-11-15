//! Runs the built `procline` binary.
//!
//! The assertions never print the collected JSON or the standard error of a collection: the output can hold environment values of the test process.

use std::process::{Command, Output};

use procline_cli::{COLLECT_OPTIONS, COMMANDS, COMPLETION_SHELLS, GLOBAL_OPTIONS};

fn procline(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_procline"))
        .args(args)
        .output()
        .expect("the procline binary runs")
}

fn stdout(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).expect("the standard output is UTF-8")
}

fn stderr(output: &Output) -> &str {
    std::str::from_utf8(&output.stderr).expect("the standard error is UTF-8")
}

fn own_pid() -> String {
    std::process::id().to_string()
}

#[cfg(target_os = "macos")]
fn collect(args: &[&str]) -> serde_json::Value {
    let output = procline(args);
    assert!(
        output.status.success(),
        "procline {args:?} failed with {}",
        output.status
    );
    serde_json::from_slice(&output.stdout).expect("the standard output is JSON")
}

#[cfg(target_os = "macos")]
fn processes(chain: &serde_json::Value) -> &[serde_json::Value] {
    chain["processes"]
        .as_array()
        .expect("processes is an array")
}

// 自分の pid を渡すと、先頭がこのテストのプロセスの列が JSON で出る。env は --env を付けた時だけ集める。
#[cfg(target_os = "macos")]
#[test]
fn own_pid_prints_the_chain_without_env() {
    let pid = own_pid();
    let chain = collect(&[&pid]);
    let processes = processes(&chain);
    assert_eq!(
        processes[0]["identity"]["pid"].to_string(),
        pid,
        "the first process is the target"
    );
    assert!(processes.len() > 1, "the ancestors follow the target");
    assert!(
        chain["boot_uuid"]
            .as_str()
            .is_some_and(|uuid| !uuid.is_empty()),
        "the chain has the boot UUID"
    );
    for (index, process) in processes.iter().enumerate() {
        assert!(
            process["env"].is_null(),
            "process {index} has env although --env was not given"
        );
        assert!(
            process["code_signing"].is_object(),
            "process {index} has no code_signing although the signatures are verified by default"
        );
        assert!(
            process["digest"].is_null(),
            "process {index} has a digest although --digest was not given"
        );
    }
}

// --env はこのテストのプロセス (ad-hoc 署名で、環境を読める) の env を集める。値は見ない。
#[cfg(target_os = "macos")]
#[test]
fn env_option_collects_env() {
    let chain = collect(&["--env", &own_pid()]);
    let env = &processes(&chain)[0]["env"];
    assert!(
        env.as_object().is_some_and(|env| !env.is_empty()),
        "--env did not collect the env of the target"
    );
}

// オプションは pid の後ろにも置ける。--digest は実行ファイルの sha256 を入れ、--no-signature は検証を飛ばし、--max-ancestors 0 は対象だけで止める。
#[cfg(target_os = "macos")]
#[test]
fn options_after_the_pid_change_the_collection() {
    let chain = collect(&[
        &own_pid(),
        "--digest",
        "--no-signature",
        "--max-ancestors",
        "0",
    ]);
    let processes = processes(&chain);
    assert_eq!(processes.len(), 1);
    assert_eq!(chain["truncated"], "max_ancestors");
    assert!(processes[0]["code_signing"].is_null());
    assert!(
        processes[0]["digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );
}

// --all-names は uid / gid の全部の名前を入れる。値の形だけ見る。
#[cfg(target_os = "macos")]
#[test]
fn all_names_option_is_accepted() {
    let chain = collect(&["--all-names", "--max-ancestors=0", &own_pid()]);
    assert!(processes(&chain)[0]["credentials"].is_object());
}

// macOS の pid は PID_MAX (99999) より小さいので、i32::MAX のプロセスは存在しない。原因と次にどうするかを標準エラーに出し、0 でない終了コードで終わる。
#[cfg(target_os = "macos")]
#[test]
fn missing_pid_fails_with_the_cause() {
    let output = procline(&["2147483647"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("no process with pid 2147483647"),
        "{stderr}"
    );
    assert!(stderr.contains("ps -p 2147483647"), "{stderr}");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn collecting_is_not_implemented_on_this_os() {
    let output = procline(&[&own_pid()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("macOS only"));
}

// 数値でない引数、知らないオプション、値の要るオプションの値の欠け、pid の重複、pid の無い指定は、使い方の誤りとして終了コード 2 で終わり、--help を案内する。
#[test]
fn usage_errors_exit_with_2_and_point_to_help() {
    for (args, cause) in [
        (&["abc"][..], "\"abc\" is neither a pid nor a command"),
        (&["-1"][..], "unknown option -1"),
        (&["1", "--unknown"][..], "unknown option --unknown"),
        (&["-h"][..], "unknown option -h"),
        (
            &["1", "--max-ancestors"][..],
            "--max-ancestors needs a value",
        ),
        (
            &["1", "--max-ancestors=x"][..],
            "--max-ancestors needs a non-negative integer",
        ),
        (&["1", "--env=1"][..], "--env takes no value"),
        (&["1", "2"][..], "unexpected argument \"2\""),
        (&["--env"][..], "no pid given"),
        (&["2147483648"][..], "\"2147483648\" is neither a pid"),
    ] {
        let output = procline(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let stderr = stderr(&output);
        assert!(stderr.contains(cause), "{args:?}: {stderr}");
        assert!(
            stderr.contains("Run `procline --help`"),
            "{args:?}: {stderr}"
        );
    }
    let output = procline(&["completion", "fish"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("no completion for the shell \"fish\""));
    assert!(stderr(&output).contains("Run `procline completion --help`"));
}

// `--` の後ろは、- で始まっても pid として読む。
#[test]
fn double_dash_ends_the_options() {
    let output = procline(&["--", "--env"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("\"--env\" is neither a pid nor a command"));
}

// 引数が無ければ、どの段でも --help と同じものを出して成功で終わる。
#[test]
fn no_arguments_print_the_help() {
    for (bare, help) in [
        (&[][..], &["--help"][..]),
        (&["completion"][..], &["completion", "--help"][..]),
    ] {
        let bare = procline(bare);
        let help = procline(help);
        assert!(bare.status.success());
        assert!(help.status.success());
        assert_eq!(stdout(&bare), stdout(&help));
    }
}

fn option_label(name: &str, value: Option<&str>) -> String {
    match value {
        Some(value) => format!("{name} {value}"),
        None => name.to_owned(),
    }
}

// --help は、パーサが受け付ける全部のオプションとサブコマンドを、サブコマンド・その段のオプション・グローバルオプションの節に分けて載せる。
#[test]
fn help_lists_every_option_and_command() {
    let output = procline(&["--help"]);
    assert!(output.status.success());
    let help = stdout(&output);
    let commands = help.find("\nCommands:\n").expect("a Commands section");
    let options = help.find("\nOptions:\n").expect("an Options section");
    let globals = help
        .find("\nGlobal options:\n")
        .expect("a Global options section");
    assert!(commands < options && options < globals, "{help}");
    for command in COMMANDS {
        let at = help
            .find(&format!("\n  {} ", command.name))
            .expect(command.name);
        assert!(
            commands < at && at < options,
            "{} is not under Commands",
            command.name
        );
    }
    for option in COLLECT_OPTIONS {
        let label = option_label(option.name, option.value);
        let at = help.find(&format!("\n  {label} ")).expect(&label);
        assert!(options < at && at < globals, "{label} is not under Options");
        assert!(help.contains(option.description), "{label}");
    }
    for option in GLOBAL_OPTIONS {
        let at = help
            .find(&format!("\n  {} ", option.name))
            .expect(option.name);
        assert!(globals < at, "{} is not under Global options", option.name);
    }

    let output = procline(&["completion", "--help"]);
    assert!(output.status.success());
    let help = stdout(&output);
    for shell in COMPLETION_SHELLS {
        assert!(
            help.contains(&format!("\n  {} ", shell.name)),
            "{}",
            shell.name
        );
    }
    for option in GLOBAL_OPTIONS {
        assert!(
            help.contains(&format!("\n  {} ", option.name)),
            "{}",
            option.name
        );
    }
}

// --help に載るオプションは、全部パーサが受け付ける (値の要るものは値を付けて)。
#[test]
fn parser_accepts_every_listed_option() {
    for option in COLLECT_OPTIONS {
        let mut args = vec![option.name.to_owned()];
        if option.value.is_some() {
            args.push("1".to_owned());
        }
        args.push(own_pid());
        let parsed = procline_cli::parse(args.iter().map(Into::into));
        assert!(
            matches!(parsed, Ok(procline_cli::Invocation::Collect { .. })),
            "{}: {parsed:?}",
            option.name
        );
    }
    for option in GLOBAL_OPTIONS {
        for args in [vec![option.name], vec!["completion", option.name]] {
            let parsed = procline_cli::parse(args.iter().map(Into::into));
            assert!(
                matches!(
                    parsed,
                    Ok(procline_cli::Invocation::Help(_) | procline_cli::Invocation::Version)
                ),
                "{args:?}: {parsed:?}"
            );
        }
    }
}

// zsh の補完は、--help と同じオプション・サブコマンド・シェルを候補に持つ。
#[test]
fn zsh_completion_offers_every_option_and_command() {
    let output = procline(&["completion", "zsh"]);
    assert!(output.status.success());
    let script = stdout(&output);
    assert!(script.starts_with("#compdef procline\n"));
    for option in COLLECT_OPTIONS.iter().chain(GLOBAL_OPTIONS) {
        let spec = match option.value {
            Some(_) => format!("'{}=[", option.name),
            None => format!("{}[", option.name),
        };
        assert!(script.contains(&spec), "{}", option.name);
    }
    for item in COMMANDS.iter().chain(COMPLETION_SHELLS) {
        assert!(
            script.contains(&format!("'{}:", item.name)),
            "{}",
            item.name
        );
    }
}

#[test]
fn version_prints_the_package_version() {
    let output = procline(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        stdout(&output),
        format!("procline {}\n", env!("CARGO_PKG_VERSION"))
    );
}
