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

// 端末の状態・表示の向き・行を変える文字で、serde_json がエスケープしないもの: DEL、C1 の 32 個、bidi の制御文字 12 個、行と段落の区切り。argv やパスは他のプロセスが決める文字列なので、CLI はこれらを JSON の `\uXXXX` で書く (JSON として読んだ値は変わらない)。実装の集合とは別にここで列挙して、両方が一致することを確かめる。
fn terminal_controls() -> Vec<char> {
    let mut chars: Vec<char> = ('\u{80}'..='\u{9f}').collect();
    chars.push('\u{7f}');
    chars.extend(['\u{61c}', '\u{200e}', '\u{200f}']);
    chars.extend('\u{202a}'..='\u{202e}');
    chars.extend('\u{2066}'..='\u{2069}');
    chars.extend(['\u{2028}', '\u{2029}']);
    chars
}

/// A child whose argv ends with the given arguments, blocked reading its standard input. The value kills and reaps it when dropped, also on failure.
#[cfg(target_os = "macos")]
struct Holding(std::process::Child);

#[cfg(target_os = "macos")]
impl Holding {
    /// Returns once the child printed `ready`. `/bin/sh` may exec the shell it stands for, and `echo` runs in that last image, so the argv the collection reads no longer changes; the child ending before that fails the test instead of leaving it waiting.
    fn start(args: &[&str]) -> Self {
        use std::io::BufRead;
        let mut child = Command::new("/bin/sh")
            .args(["-c", "echo ready; read never", "sh"])
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("/bin/sh starts");
        let stdout = child.stdout.take().expect("the standard output is piped");
        let holding = Self(child);
        let mut line = String::new();
        std::io::BufReader::new(stdout)
            .read_line(&mut line)
            .expect("the child writes a line");
        assert_eq!(line, "ready\n", "the child ended before it was ready");
        holding
    }

    fn pid(&self) -> String {
        self.0.id().to_string()
    }
}

#[cfg(target_os = "macos")]
impl Drop for Holding {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The argv of the child as the CLI printed it, read as JSON, and the raw standard output. Only the child is collected (`--max-ancestors=0`), without env.
#[cfg(target_os = "macos")]
fn collect_argv(args: &[&str]) -> (Vec<String>, String) {
    let child = Holding::start(args);
    let output = procline(&["--max-ancestors=0", &child.pid()]);
    assert!(
        output.status.success(),
        "procline failed with {}",
        output.status
    );
    let text = stdout(&output).to_owned();
    let chain: serde_json::Value =
        serde_json::from_str(&text).expect("the standard output is JSON");
    let argv = processes(&chain)[0]["argv"]
        .as_array()
        .expect("the argv of the child is collected")
        .iter()
        .map(|arg| arg.as_str().expect("an argument is a string").to_owned())
        .collect();
    (argv, text)
}

// 対象の各グループから 1 文字ずつ (DEL、C1 の CSI U+009B、bidi の U+202E と U+2066、行の区切り U+2028) を argv に持つプロセスを実際に起こして CLI で集める。標準出力にはどの対象の文字も生のまま現れず、JSON として読んだ argv は元の文字列と同じ。NUL などの U+0000〜U+001F は argv に入れられない (C の文字列で NUL が終端になる) ので、ここでは使わない。
#[cfg(target_os = "macos")]
#[test]
fn control_characters_in_argv_are_escaped_in_the_output() {
    let args = [
        "a\u{7f}b",
        "c\u{9b}31m",
        "\u{202e}fdp.exe",
        "x\u{2066}y\u{2069}z",
        "line\u{2028}break",
    ];
    let (argv, text) = collect_argv(&args);
    for c in terminal_controls() {
        assert!(
            !text.contains(c),
            "the output holds U+{:04X} unescaped",
            u32::from(c)
        );
    }
    assert!(
        text.contains(r"c\u009b31m"),
        "U+009B is not written as \\u009b"
    );
    assert!(
        argv.ends_with(&args.map(str::to_owned)),
        "the argv read from the output differs from the arguments given"
    );
}

// 対象の外の非 ASCII (日本語) は \u にならず、そのままの文字で出る。エスケープは端末を操作する文字だけに絞り、読める値を読めないままにしない。
#[cfg(target_os = "macos")]
#[test]
fn japanese_in_argv_is_printed_as_it_is() {
    let args = ["日本語のパス"];
    let (argv, text) = collect_argv(&args);
    assert!(
        text.contains("\"日本語のパス\""),
        "the argument is not printed as it is"
    );
    assert!(argv.ends_with(&args.map(str::to_owned)));
}

fn escaped(value: &str) -> String {
    procline_cli::escape_terminal_controls(&serde_json::to_string(value).expect("a string is JSON"))
}

// 対象の全部の文字 (C1 の 32 個、DEL、bidi の 12 個、U+2028、U+2029) は、serde_json が U+0000〜U+001F に使うのと同じ形 (16 進 4 桁、小文字) の `\uXXXX` になり、JSON として読むと元の文字に戻る。
#[test]
fn every_terminal_control_becomes_a_unicode_escape() {
    let chars = terminal_controls();
    assert_eq!(chars.len(), 32 + 1 + 12 + 2);
    for c in chars {
        let json = escaped(&c.to_string());
        assert_eq!(json, format!("\"\\u{:04x}\"", u32::from(c)));
        let read: String = serde_json::from_str(&json).expect("the escaped text is JSON");
        assert_eq!(read, c.to_string());
    }
}

// 集合の端の隣 (U+007E、U+00A0、U+061B と U+061D、U+200D と U+2010、U+2027、U+202F、U+2065、U+206A) と日本語は、そのままの文字で出る。U+2029 と U+202A はどちらも対象で隣り合うので、その間に外の文字は無い。U+0000〜U+001F、`"`、`\` は serde_json の書き方のまま変わらない。整形 (インデント、キーの順) も変わらない: 書き換えるのは対象の文字だけ。
#[test]
fn characters_outside_the_set_are_kept() {
    for c in [
        '\u{7e}', '\u{a0}', '\u{61b}', '\u{61d}', '\u{200d}', '\u{2010}', '\u{2027}', '\u{202f}',
        '\u{2065}', '\u{206a}', '日',
    ] {
        assert_eq!(
            escaped(&c.to_string()),
            format!("\"{c}\""),
            "U+{:04X}",
            u32::from(c)
        );
    }
    let syntax: String = ('\u{0}'..='\u{1f}').chain(['"', '\\']).collect();
    let json = serde_json::to_string(&syntax).expect("a string is JSON");
    assert_eq!(procline_cli::escape_terminal_controls(&json), json);
    let pretty = serde_json::to_string_pretty(
        &serde_json::json!({"b": ["日本", 1, null], "a": {"c": true}}),
    )
    .expect("a value is JSON");
    assert_eq!(procline_cli::escape_terminal_controls(&pretty), pretty);
}
