//! Parsing the `KERN_PROCARGS2` area, and choosing and redacting the environment.

use std::collections::BTreeMap;

use procline_core::{EnvPolicy, Redaction};

/// argv and the environment of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcArgs {
    pub argv: Vec<String>,
    /// In the order of the area; a name may repeat. `None` when the kernel left the environment out of the area.
    pub env: Option<Vec<(String, String)>>,
}

/// Reads the NUL-terminated string at `*pos` and moves past its NUL. `None` at the end of the area or for a string the area cuts off.
fn take_string<'a>(area: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let rest = area.get(*pos..)?;
    let len = rest.iter().position(|&b| b == 0)?;
    *pos += len + 1;
    Some(&rest[..len])
}

/// Parses `KERN_PROCARGS2`: `argc` (native `int`), the exec path and its NUL padding, `argc` argument strings, the environment strings, then an empty string followed by the strings the kernel passes to dyld (`executable_path=…`, `ptr_munge=…`), which are not environment.
///
/// For platform binaries the kernel ends the area right after the arguments, leaving out the environment and the dyld strings (observed on macOS 26); the environment is then `None`, unlike an empty environment, which still has its terminating empty string.
///
/// The NUL padding after the exec path cannot be told apart from empty leading arguments, so an empty `argv[0]` is lost (as with `ps`). Strings that are not UTF-8 are decoded lossily.
pub(crate) fn parse(area: &[u8]) -> Option<ProcArgs> {
    let argc = i32::from_ne_bytes(area.get(..4)?.try_into().ok()?);
    let argc = usize::try_from(argc).ok()?;
    let mut pos = 4;
    take_string(area, &mut pos)?;
    pos += area[pos..]
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(area.len() - pos);
    let argv = (0..argc)
        .map(|_| take_string(area, &mut pos).map(lossy))
        .collect::<Option<Vec<_>>>()?;
    if pos >= area.len() {
        return Some(ProcArgs { argv, env: None });
    }
    let mut env = Vec::new();
    while let Some(entry) = take_string(area, &mut pos) {
        if entry.is_empty() {
            break;
        }
        let entry = lossy(entry);
        env.push(match entry.split_once('=') {
            Some((name, value)) => (name.to_owned(), value.to_owned()),
            None => (entry, String::new()),
        });
    }
    Some(ProcArgs {
        argv,
        env: Some(env),
    })
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Keeps the variables `policy` selects and redacts the values `redaction` marks secret. The first occurrence of a repeated name wins, as `getenv` does. `None` for `EnvPolicy::None`.
pub(crate) fn select_env(
    entries: Vec<(String, String)>,
    policy: &EnvPolicy,
    redaction: &Redaction,
) -> Option<BTreeMap<String, String>> {
    let selected: Box<dyn Fn(&str) -> bool> = match policy {
        EnvPolicy::None => return None,
        EnvPolicy::Allowlist(names) => Box::new(move |name| names.iter().any(|n| n == name)),
        EnvPolicy::All => Box::new(|_| true),
    };
    let mut env = BTreeMap::new();
    for (name, value) in entries {
        if !selected(&name) || env.contains_key(&name) {
            continue;
        }
        let value = if (redaction.is_secret)(&name) {
            (redaction.redact)(&name, &value)
        } else {
            value
        };
        env.insert(name, value);
    }
    Some(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// argc と文字列の並びから `KERN_PROCARGS2` の領域を組み立てる。`padding` は exec path の後の NUL の数 (カーネルは境界合わせのために足す)。
    fn area(argc: i32, exec_path: &str, padding: usize, strings: &[&str]) -> Vec<u8> {
        let mut out = argc.to_ne_bytes().to_vec();
        out.extend_from_slice(exec_path.as_bytes());
        out.extend(std::iter::repeat_n(0, padding));
        for s in strings {
            out.extend_from_slice(s.as_bytes());
            out.push(0);
        }
        out
    }

    // 実機の領域の形: exec path、NUL の詰め物、argv、env、空文字列、dyld 向けの文字列。env は空文字列で終わり、その後の `executable_path=` などを env に混ぜない (混ぜると伏せ字の対象外の値が env として表示される)。
    #[test]
    fn parses_argv_and_env_and_stops_env_at_the_empty_string() {
        let buf = area(
            2,
            "/bin/sleep",
            7,
            &[
                "sleep",
                "30",
                "A=1",
                "B=two=2",
                "",
                "",
                "executable_path=/bin/sleep",
                "ptr_munge=0x1",
            ],
        );
        let parsed = parse(&buf).unwrap();
        assert_eq!(parsed.argv, ["sleep", "30"]);
        assert_eq!(
            parsed.env,
            Some(vec![
                ("A".to_owned(), "1".to_owned()),
                ("B".to_owned(), "two=2".to_owned())
            ])
        );
    }

    // env が空のプロセス (`env -i`) は argv の直後に空文字列が来る。env を空の列として返し、dyld 向けの文字列を拾わない。
    #[test]
    fn empty_environment_is_empty() {
        let buf = area(
            1,
            "/bin/sleep",
            1,
            &["sleep", "", "executable_path=/bin/sleep"],
        );
        assert_eq!(parse(&buf).unwrap().env, Some(vec![]));
    }

    // platform binary の領域は、カーネルが argv の直後で終える (env も dyld 向けの文字列も入れない。macOS 26 の実機で観測)。この形は「env が空」ではなく「env を読めなかった」なので None にする (空にすると、env を持つプロセスを env なしと表示する)。
    #[test]
    fn area_ending_after_argv_has_no_environment() {
        let buf = area(2, "/bin/sleep", 6, &["/bin/sleep", "30"]);
        let parsed = parse(&buf).unwrap();
        assert_eq!(parsed.argv, ["/bin/sleep", "30"]);
        assert_eq!(parsed.env, None);
    }

    // `=` を持たない env の要素は、名前だけで値が空の変数として残す (捨てると表示から消え、何かが渡されていたことが分からなくなる)。
    #[test]
    fn entry_without_equals_keeps_the_name() {
        let buf = area(1, "/x", 1, &["x", "LONELY", ""]);
        assert_eq!(
            parse(&buf).unwrap().env,
            Some(vec![("LONELY".to_owned(), String::new())])
        );
    }

    // 領域が argc の数だけ文字列を持たない、または最後の文字列が NUL の前で切れているときは、壊れた領域とみなす。途中までの argv を返さない (少ない argv や切れた引数を本物として表示しない)。
    #[test]
    fn truncated_area_is_rejected() {
        let buf = area(3, "/x", 1, &["x", "a"]);
        assert_eq!(parse(&buf), None);
        let buf = area(2, "/x", 1, &["x", "a"]);
        assert_eq!(parse(&buf[..buf.len() - 1]), None);
        assert_eq!(parse(&[1, 0]), None);
    }

    // UTF-8 でない argv は置換文字で読み、収集全体を止めない。
    #[test]
    fn non_utf8_is_decoded_lossily() {
        let mut buf = 1i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/x\0\xff\0\0");
        assert_eq!(parse(&buf).unwrap().argv, ["\u{fffd}"]);
    }

    fn redaction() -> Redaction {
        Redaction {
            is_secret: Box::new(|name| name.contains("TOKEN")),
            redact: Box::new(|_, _| "***".to_owned()),
        }
    }

    fn entries() -> Vec<(String, String)> {
        [
            ("PATH", "/bin"),
            ("API_TOKEN", "s3cret"),
            ("PATH", "/second"),
        ]
        .into_iter()
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .collect()
    }

    // 方針 None (既定) は env を集めない。空の map でなく None にして、「集めなかった」と「空だった」を区別する。
    #[test]
    fn policy_none_collects_nothing() {
        assert_eq!(select_env(entries(), &EnvPolicy::None, &redaction()), None);
    }

    // All は全部を集めるが、伏せ字の判定に当たる値は必ず伏せる。同じ名前が複数あれば getenv と同じく先頭を採る。
    #[test]
    fn policy_all_redacts_secrets_and_keeps_the_first() {
        let env = select_env(entries(), &EnvPolicy::All, &redaction()).unwrap();
        assert_eq!(env.get("PATH").map(String::as_str), Some("/bin"));
        assert_eq!(env.get("API_TOKEN").map(String::as_str), Some("***"));
    }

    // Allowlist は列挙した名前だけを集め (完全一致)、列挙した名前でも伏せ字の判定は通す。
    #[test]
    fn allowlist_selects_exact_names_and_still_redacts() {
        let policy = EnvPolicy::Allowlist(vec!["API_TOKEN".to_owned(), "PAT".to_owned()]);
        let env = select_env(entries(), &policy, &redaction()).unwrap();
        assert_eq!(
            env.into_iter().collect::<Vec<_>>(),
            [("API_TOKEN".to_owned(), "***".to_owned())]
        );
    }
}
