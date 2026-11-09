//! The two places a subject holds alternatives (DR-0010): a list of values for one item (`MatchValue::AnyOf`) and several definitions of one tag name. Matching, the shape rules of a list, the strength (the weakest alternative), `resolve_subject` / `evaluate` with a list, and the `any_of` entry of the builders.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{BOOT, NOW, at, chain, named, process, signature, signed, vocabulary};
use procline_acl::{
    AllowConstraints, AncestorBuilder, AncestorMatch, BuildError, ConditionUse, Effect,
    EvalContext, Grant, Literal, MatchValue, PinSpec, Policy, ScopeOption, ScopeRequirement,
    Subject, SubjectBuilder, SubjectRef, Tag, TaggedChain, Target, Vocabulary,
};
use procline_core::{
    BinaryField, BinaryPin, Pinnable, ProcessChain, ProcessInfo, Strength, Truncated,
};

fn text(value: &str) -> MatchValue {
    MatchValue::Exact(Literal::Text(value.to_owned()))
}

fn regex(pattern: &str) -> MatchValue {
    MatchValue::Regex(pattern.to_owned())
}

fn any_of(values: Vec<MatchValue>) -> MatchValue {
    MatchValue::AnyOf(values)
}

/// A `binary` value on the Team ID alone.
fn team(team_id: &str) -> MatchValue {
    team_field(Pinnable::Value(team_id.to_owned()))
}

/// A `binary` value with a placeholder in the Team ID.
fn team_pin() -> MatchValue {
    team_field(Pinnable::Pin)
}

fn team_field(team_id: Pinnable<String>) -> MatchValue {
    MatchValue::Binary(BinaryPin {
        digest: None,
        team_id: Some(team_id),
        signing_id: None,
        bundle_id: None,
        cdhash: None,
    })
}

fn digest(value: &str) -> MatchValue {
    MatchValue::Binary(BinaryPin {
        digest: Some(Pinnable::Value(value.to_owned())),
        team_id: None,
        signing_id: None,
        bundle_id: None,
        cdhash: None,
    })
}

fn own(key: &str, value: MatchValue) -> Subject {
    Subject {
        r#match: BTreeMap::from([(key.to_owned(), value)]),
        ..Subject::default()
    }
}

fn tag(name: &str, subject: Subject) -> Tag {
    Tag {
        name: name.to_owned(),
        subject: SubjectRef::Inline(Box::new(subject)),
    }
}

fn inline(subject: Subject) -> SubjectRef {
    SubjectRef::Inline(Box::new(subject))
}

/// The example table of the design: Strong unrestricted, Medium within an epoch scope, Weak an epoch scope.
fn constraints() -> AllowConstraints {
    AllowConstraints {
        strong: ScopeRequirement::Unrestricted,
        medium: ScopeRequirement::AnyOf(vec![ScopeOption::Condition("app.unlock".to_owned())]),
        weak: ScopeRequirement::AnyOf(vec![ScopeOption::Condition("app.unlock".to_owned())]),
    }
}

fn policy(vocab: &Vocabulary, tags: Vec<Tag>) -> Policy<'_> {
    Policy::from_parts(
        vocab,
        Vec::new(),
        tags,
        Vec::new(),
        Vec::new(),
        constraints(),
        Effect::Deny,
    )
}

/// The tags carried by each process, as names.
fn carried<'t>(tagged: &'t TaggedChain<'_>) -> Vec<Vec<&'t str>> {
    tagged
        .tags
        .iter()
        .map(|tags| tags.iter().map(String::as_str).collect())
        .collect()
}

fn with_argv(process: ProcessInfo, argv: &[&str]) -> ProcessInfo {
    ProcessInfo {
        argv: Some(argv.iter().map(|arg| (*arg).to_owned()).collect()),
        ..process
    }
}

fn truncated(processes: Vec<ProcessInfo>) -> ProcessChain {
    ProcessChain::new(processes, BOOT.to_owned(), Some(Truncated::MaxAncestors))
}

fn invalid<T: std::fmt::Debug>(result: Result<T, BuildError>, key: &str) {
    assert!(
        matches!(&result, Err(BuildError::InvalidValue { key: k, .. }) if k == key),
        "{result:?}"
    );
}

// ---------- 値の列: 照合 ----------
//
// 1 つの key に値の列を書くと、その key について列のどれかの値に一致すれば真。列の外の項目とは AND のまま。

// 列のどれかの値 (完全一致の zsh か glob の ba*) に一致するプロセスに当たり、どれにも一致しないプロセス (sh、launchd) には当たらない。値の形は要素ごとに違ってよい。
#[test]
fn a_list_matches_when_one_of_its_values_does() {
    let vocab = Vocabulary::builtin();
    let shells = own(
        "name",
        any_of(vec![text("zsh"), MatchValue::Glob("ba*".to_owned())]),
    );
    let policy = policy(&vocab, vec![tag("shell", shells)]);
    let chain = chain(vec![
        named(4, "sh"),
        named(3, "bash"),
        named(2, "zsh"),
        named(1, "launchd"),
    ]);
    assert_eq!(
        carried(&policy.tag(&chain)),
        vec![vec![], vec!["shell"], vec!["shell"], vec![]]
    );
}

// 列は 1 つの key の中だけの OR で、同じ match の別の項目とは AND。名前が列に当たっても uid が違えば当たらない。
#[test]
fn a_list_is_anded_with_the_other_items() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        r#match: BTreeMap::from([
            ("name".to_owned(), any_of(vec![text("zsh"), text("bash")])),
            ("uid".to_owned(), MatchValue::Exact(Literal::Integer(501))),
        ]),
        ..Subject::default()
    };
    let policy = policy(&vocab, vec![tag("my-shell", subject)]);
    let chain = chain(vec![
        common::with_ids(named(3, "zsh"), 501, 20),
        common::with_ids(named(2, "bash"), 0, 0),
    ]);
    assert_eq!(carried(&policy.tag(&chain)), vec![vec!["my-shell"], vec![]]);
}

// argv の列は「どれかの要素 (正規表現) がどれかの引数に一致」。/opt/a.sh か /opt/b.sh を引数に持つプロセスに当たり、/opt/c.sh だけのプロセスには当たらない。
#[test]
fn an_argv_list_matches_when_one_regex_matches_one_argument() {
    let vocab = Vocabulary::builtin();
    let scripts = own(
        "argv",
        any_of(vec![regex("^/opt/a\\.sh$"), regex("^/opt/b\\.sh$")]),
    );
    let policy = policy(&vocab, vec![tag("script", scripts)]);
    let chain = chain(vec![
        with_argv(process(3), &["sh", "/opt/b.sh"]),
        with_argv(process(2), &["sh", "/opt/c.sh"]),
        with_argv(process(1), &["/opt/a.sh", "-x"]),
    ]);
    assert_eq!(
        carried(&policy.tag(&chain)),
        vec![vec!["script"], vec![], vec!["script"]]
    );
}

// 構造を持つ値も列にできる: `"binary": [{"team_id": "A"}, {"team_id": "B"}]` は Team ID が A か B の署名に当たる。
#[test]
fn a_list_of_binary_values_matches_either_team() {
    let vocab = Vocabulary::builtin();
    let teams = own("binary", any_of(vec![team("A"), team("B")]));
    let policy = policy(&vocab, vec![tag("team-ab", teams)]);
    let chain = chain(vec![
        signed(process(3), signature("A", "com.example.a")),
        signed(process(2), signature("C", "com.example.c")),
        signed(process(1), signature("B", "com.example.b")),
    ]);
    assert_eq!(
        carried(&policy.tag(&chain)),
        vec![vec!["team-ab"], vec![], vec!["team-ab"]]
    );
}

// grant の照合 (evaluate) も列のどれかで当たり、trace の項目は当たったものとして残る。列に無い名前の対象には当たらず既定の effect。
#[test]
fn a_grant_with_a_list_matches_on_evaluation() {
    let vocab = vocabulary();
    let mut policy = policy(&vocab, Vec::new());
    policy.add_grant(Grant {
        id: "g-1".to_owned(),
        rule_id: "r".to_owned(),
        effect: Effect::Allow,
        subject: own("name", any_of(vec![text("zsh"), text("bash")])),
        targets: Vec::new(),
        conditions: Vec::new(),
        created_at: at(NOW),
        created_from: None,
    });
    let ctx = EvalContext::new(at(NOW));
    let target = Target("key:k1".to_owned());
    let bash = chain(vec![named(2, "bash"), named(1, "launchd")]);
    let decision = policy.evaluate(&policy.tag(&bash), &target, &ctx);
    assert_eq!(decision.effect, Effect::Allow);
    assert!(
        decision
            .trace
            .entries
            .iter()
            .any(|entry| entry.key == "name" && entry.matched && entry.process == Some(0))
    );
    let sh = chain(vec![named(2, "sh"), named(1, "launchd")]);
    assert_eq!(
        policy.evaluate(&policy.tag(&sh), &target, &ctx).effect,
        Effect::Deny
    );
}

// ---------- 値の列: 形の規則 ----------
//
// 列の中は 1 段だけ、placeholder は入れられない (grant で 1 つに pin できない)、空は不正。要素はそれぞれ項目の規則で検査する。どれも RuleBuilder::build (Matcher::validate を呼ぶ側) が InvalidValue にする。

#[test]
fn nested_placeholder_and_empty_lists_are_rejected() {
    let vocab = vocabulary();
    let policy = policy(&vocab, Vec::new());
    let build = |key: &str, value: MatchValue| {
        policy
            .rule_builder("r", inline(own(key, value)))
            .deny()
            .build()
    };
    invalid(
        build(
            "name",
            any_of(vec![text("zsh"), any_of(vec![text("bash")])]),
        ),
        "name",
    );
    invalid(
        build("name", any_of(vec![text("zsh"), MatchValue::Pin])),
        "name",
    );
    invalid(
        build("process", any_of(vec![MatchValue::Process(Pinnable::Pin)])),
        "process",
    );
    invalid(build("binary", any_of(vec![team_pin()])), "binary");
    invalid(build("name", any_of(Vec::new())), "name");
    // 妥当な列は通る。
    assert!(build("name", any_of(vec![text("zsh"), text("bash")])).is_ok());
}

// 要素は項目の規則で検査する: cwd は絶対パス、argv は glob を取らない。列の中の 1 つでも違反すれば列ごと不正。
#[test]
fn each_value_of_a_list_is_checked_by_the_item() {
    let vocab = vocabulary();
    let policy = policy(&vocab, Vec::new());
    let build = |key: &str, value: MatchValue| {
        policy
            .rule_builder("r", inline(own(key, value)))
            .deny()
            .build()
    };
    invalid(
        build("cwd", any_of(vec![text("/Users/alice"), text("src/pj1")])),
        "cwd",
    );
    invalid(
        build(
            "argv",
            any_of(vec![regex("^-x$"), MatchValue::Glob("*.sh".to_owned())]),
        ),
        "argv",
    );
    // 祖先の要素の値も同じ規則。
    invalid(
        policy
            .rule_builder(
                "r",
                inline(Subject {
                    ancestors: vec![AncestorMatch {
                        r#match: BTreeMap::from([("name".to_owned(), any_of(Vec::new()))]),
                        tags: Vec::new(),
                    }],
                    ..Subject::default()
                }),
            )
            .deny()
            .build(),
        "name",
    );
}

// ---------- 値の列: 強さ ----------
//
// 列はどれでも通るので、クラスは要素のクラスのうち最も弱いもの。

// 署名由来の field (強) と digest だけ (中) の列は中。強だけの列は強。
#[test]
fn the_class_of_a_list_is_its_weakest_value() {
    let vocab = Vocabulary::builtin();
    let class = |value: MatchValue| vocab.class("binary", &value, None);
    assert_eq!(
        class(any_of(vec![team("A"), digest("sha256:00")])),
        Some(Strength::Medium)
    );
    assert_eq!(
        class(any_of(vec![team("A"), team("B")])),
        Some(Strength::Strong)
    );
}

// ルールの強さにも最弱が効く: 強と中の列を自身の条件に持つ allow は中の制約 (世代の scope) を求められる。
#[test]
fn a_list_lowers_the_strength_of_a_rule() {
    let vocab = vocabulary();
    let policy = policy(&vocab, Vec::new());
    let mixed = || inline(own("binary", any_of(vec![team("A"), digest("sha256:00")])));
    assert_eq!(
        policy.rule_builder("r", mixed()).allow().build().map(drop),
        Err(BuildError::ScopeTooWeak {
            class: Strength::Medium
        })
    );
    assert!(
        policy
            .rule_builder("r", mixed())
            .condition(ConditionUse::named("app.unlock"))
            .allow()
            .build()
            .is_ok()
    );
}

// ---------- 値の列: placeholder の解決 ----------

// 列は placeholder を持たないので、resolve_subject は列をそのまま残し、同じ要素の placeholder だけを埋める。祖先の要素では、列 (claude か codex) に当たる最も近い祖先の Team ID を pin する。
#[test]
fn resolve_keeps_a_list_and_fills_the_placeholders_beside_it() {
    let vocab = vocabulary();
    let policy = policy(&vocab, Vec::new());
    let agents = any_of(vec![text("claude"), text("codex")]);
    let subject = Subject {
        ancestors: vec![AncestorMatch {
            r#match: BTreeMap::from([
                ("name".to_owned(), agents.clone()),
                ("binary".to_owned(), team_pin()),
            ]),
            tags: Vec::new(),
        }],
        ..Subject::default()
    };
    let chain = chain(vec![
        named(4, "sh"),
        signed(named(3, "zsh"), signature("Z", "com.example.zsh")),
        signed(named(2, "codex"), signature("X", "com.example.codex")),
        signed(named(1, "claude"), signature("C", "com.example.claude")),
    ]);
    let tagged = policy.tag(&chain);
    let resolved = policy.resolve_subject(&inline(subject), &tagged).unwrap();
    assert_eq!(
        resolved.ancestors[0].r#match,
        BTreeMap::from([
            ("name".to_owned(), agents),
            ("binary".to_owned(), team("X")),
        ])
    );
}

// ---------- タグの複数定義 ----------
//
// 同じタグ名の定義を複数置くと、どれかの定義に当たればタグが付く。異なる項目にまたがる選択肢 (Terminal は path、iTerm2 は署名) を 1 つの名前に吸収する。

// Terminal の名前か iTerm2 の Team ID のどちらかに当たるプロセスに terminal-app が付く。どちらにも当たらないプロセスには付かない。
#[test]
fn a_tag_with_several_definitions_is_carried_when_one_matches() {
    let vocab = Vocabulary::builtin();
    let policy = policy(
        &vocab,
        vec![
            tag("terminal-app", own("name", text("Terminal"))),
            tag("terminal-app", own("binary", team("ITERM"))),
        ],
    );
    let chain = chain(vec![
        named(4, "zsh"),
        signed(
            named(3, "iTerm2"),
            signature("ITERM", "com.googlecode.iterm2"),
        ),
        named(2, "Terminal"),
        named(1, "launchd"),
    ]);
    let tagged = policy.tag(&chain);
    assert_eq!(
        carried(&tagged),
        vec![vec![], vec!["terminal-app"], vec!["terminal-app"], vec![]]
    );
    assert!(tagged.undecidable_tags.is_empty());
    // 同名のタグを要求する subject も、どちらの定義で付いたかを問わない。
    let in_terminal = Subject {
        ancestors: vec![AncestorMatch {
            r#match: BTreeMap::new(),
            tags: vec!["terminal-app".to_owned()],
        }],
        ..Subject::default()
    };
    let with_reference = Policy::from_parts(
        &vocab,
        Vec::new(),
        vec![
            tag("terminal-app", own("name", text("Terminal"))),
            tag("in-terminal", in_terminal),
            tag("terminal-app", own("binary", team("ITERM"))),
        ],
        Vec::new(),
        Vec::new(),
        constraints(),
        Effect::Deny,
    );
    assert_eq!(carried(&with_reference.tag(&chain))[0], vec!["in-terminal"]);
}

// 判定は三値のまま: どれかの定義が True なら True (他の定義が Unknown でも)、全部 False なら False、それ以外は Unknown。途切れた列 [sh, zsh] で、祖先に claude を要求する定義は判定できないが、sh は名前の定義で確かに付く。zsh はどちらでも付くと言えないので undecidable_tags に入る。
#[test]
fn several_definitions_combine_in_three_values() {
    let vocab = Vocabulary::builtin();
    let under_claude = Subject {
        ancestors: vec![AncestorMatch {
            r#match: BTreeMap::from([("name".to_owned(), text("claude"))]),
            tags: Vec::new(),
        }],
        ..Subject::default()
    };
    let policy = policy(
        &vocab,
        vec![
            tag("tool", under_claude),
            tag("tool", own("name", text("sh"))),
        ],
    );
    let cut = truncated(vec![named(2, "sh"), named(1, "zsh")]);
    let tagged = policy.tag(&cut);
    assert_eq!(carried(&tagged), vec![vec!["tool"], vec![]]);
    assert_eq!(tagged.undecidable_tags, BTreeSet::from(["tool".to_owned()]));
    // 完全な列なら claude がいないことは確定し、zsh には付かないと決まる。
    let complete = chain(vec![named(2, "sh"), named(1, "zsh")]);
    let tagged = policy.tag(&complete);
    assert_eq!(carried(&tagged), vec![vec!["tool"], vec![]]);
    assert!(tagged.undecidable_tags.is_empty());
}

// タグを条件にしたときの強さは定義のうち最も弱いもの。強 (署名) と中 (digest) の定義なら中、強と ancestors だけの定義なら弱 (その定義は自身を縛らずにタグを付ける)。強だけなら強。
#[test]
fn the_strength_of_a_tag_is_its_weakest_definition() {
    let vocab = vocabulary();
    let signed_app = || own("binary", team("A"));
    let strength = |second: Subject| {
        let policy = policy(&vocab, vec![tag("app", signed_app()), tag("app", second)]);
        let tagged = Subject {
            tags: vec!["app".to_owned()],
            ..Subject::default()
        };
        policy
            .rule_builder("r", inline(tagged))
            .allow()
            .build()
            .map(drop)
    };
    assert_eq!(
        strength(own("binary", digest("sha256:00"))),
        Err(BuildError::ScopeTooWeak {
            class: Strength::Medium
        })
    );
    assert_eq!(
        strength(Subject {
            ancestors: vec![AncestorMatch {
                r#match: BTreeMap::from([("name".to_owned(), text("claude"))]),
                tags: Vec::new(),
            }],
            ..Subject::default()
        }),
        Err(BuildError::ScopeTooWeak {
            class: Strength::Weak
        })
    );
    assert_eq!(strength(own("binary", team("B"))), Ok(()));
}

// ---------- builder の入口 ----------

// any_of は exact の列版で、key に値の列 (AnyOf) を置く。SubjectBuilder と AncestorBuilder の両方にある。
#[test]
fn any_of_puts_a_list_on_the_key() {
    let subject = SubjectBuilder::new()
        .any_of("name", [text("zsh"), text("bash")])
        .ancestor(
            AncestorBuilder::new()
                .any_of("binary", [team("A"), team("B")])
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    assert_eq!(
        subject.r#match["name"],
        any_of(vec![text("zsh"), text("bash")])
    );
    assert_eq!(
        subject.ancestors[0].r#match["binary"],
        any_of(vec![team("A"), team("B")])
    );
}

// 列も 1 つの値なので、同じ key への exact / pin とは合成せず Conflict (binary でも field 単位の合成はしない)。
#[test]
fn any_of_and_another_value_on_the_key_conflict() {
    let conflict = |key: &str| {
        Err(BuildError::Conflict {
            key: key.to_owned(),
            field: None,
        })
    };
    assert_eq!(
        SubjectBuilder::new()
            .any_of("name", [text("zsh")])
            .exact("name", text("bash"))
            .build()
            .map(drop),
        conflict("name")
    );
    assert_eq!(
        SubjectBuilder::new()
            .pin("binary", PinSpec::Binary(vec![BinaryField::TeamId]))
            .any_of("binary", [team("A")])
            .build()
            .map(drop),
        conflict("binary")
    );
}

// builder の build は語彙を持たずに列の形を検査する: 空、列の入れ子、placeholder 入り、binary の規則に反する要素 (team_id の無い signing_id) は InvalidValue。
#[test]
fn any_of_checks_the_shape_of_the_list() {
    invalid(SubjectBuilder::new().any_of("name", []).build(), "name");
    invalid(
        SubjectBuilder::new()
            .any_of("name", [any_of(vec![text("zsh")])])
            .build(),
        "name",
    );
    invalid(
        AncestorBuilder::new()
            .any_of("cwd", [MatchValue::Pin])
            .build(),
        "cwd",
    );
    invalid(
        SubjectBuilder::new().any_of("binary", [team_pin()]).build(),
        "binary",
    );
    let signing_id_only = MatchValue::Binary(BinaryPin {
        digest: None,
        team_id: None,
        signing_id: Some(Pinnable::Value("myapp".to_owned())),
        bundle_id: None,
        cdhash: None,
    });
    invalid(
        SubjectBuilder::new()
            .any_of("binary", [team("A"), signing_id_only])
            .build(),
        "binary",
    );
}
