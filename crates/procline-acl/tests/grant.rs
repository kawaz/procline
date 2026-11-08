//! `Policy::resolve_subject` (where each placeholder takes its value) and `Policy::grant` (pinning the conditions, `age` to `until`, `ValueUnavailable`, `Unobservable`, `ScopeTooWeak` at granting).

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::{BOOT, NOW, at, chain, named, process, signature, signed, vocabulary};
use procline_acl::{
    AllowConstraints, AncestorMatch, ConditionUse, Effect, EvalContext, GrantError, Literal,
    MatchValue, PinError, PinnedCondition, Policy, Rule, ScopeOption, ScopeRequirement, Subject,
    SubjectRef, Vocabulary,
};
use procline_core::{
    BinaryPin, PathMeta, Pinnable, ProcessChain, ProcessIdentity, ProcessInfo, Strength,
};
use serde_json::json;

const CLAUDE_TEAM: &str = "VWXYZ67890";
const ITERM_TEAM: &str = "H7V7XYVQ7D";

fn constraints() -> AllowConstraints {
    AllowConstraints {
        strong: ScopeRequirement::Unrestricted,
        medium: ScopeRequirement::AnyOf(vec![
            ScopeOption::UntilWithin(Duration::from_secs(7 * 86_400)),
            ScopeOption::Condition("app.unlock".to_owned()),
        ]),
        weak: ScopeRequirement::AnyOf(vec![ScopeOption::Condition("app.unlock".to_owned())]),
    }
}

fn policy_with(vocab: &Vocabulary, constraints: AllowConstraints) -> Policy<'_> {
    Policy::from_parts(
        vocab,
        vec![(
            "the-shell".to_owned(),
            Subject {
                r#match: BTreeMap::from([(
                    "name".to_owned(),
                    MatchValue::Exact(Literal::Text("sh".to_owned())),
                )]),
                ..Subject::default()
            },
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        constraints,
        Effect::Deny,
    )
}

fn policy(vocab: &Vocabulary) -> Policy<'_> {
    policy_with(vocab, constraints())
}

fn binary(team_id: Option<Pinnable<&str>>, signing_id: Option<Pinnable<&str>>) -> MatchValue {
    let owned = |field: Option<Pinnable<&str>>| {
        field.map(|field| match field {
            Pinnable::Pin => Pinnable::Pin,
            Pinnable::Value(value) => Pinnable::Value(value.to_owned()),
        })
    };
    MatchValue::Binary(BinaryPin {
        digest: None,
        team_id: owned(team_id),
        signing_id: owned(signing_id),
        bundle_id: None,
        cdhash: None,
    })
}

fn entry(key: &str, value: MatchValue) -> AncestorMatch {
    AncestorMatch {
        r#match: BTreeMap::from([(key.to_owned(), value)]),
        tags: Vec::new(),
    }
}

/// `sh` (the target, signed by `CLAUDE_TEAM` as `com.example.tool`) under claude-code, under iTerm2.
fn terminal_chain() -> ProcessChain {
    chain(vec![
        signed(named(4, "sh"), signature(CLAUDE_TEAM, "com.example.tool")),
        named(3, "zsh"),
        signed(
            named(2, "claude"),
            signature(CLAUDE_TEAM, "com.anthropic.claude-code"),
        ),
        signed(
            named(1, "iTerm2"),
            signature(ITERM_TEAM, "com.googlecode.iterm2"),
        ),
    ])
}

fn rule(effect: Effect, subject: Subject, conditions: Vec<ConditionUse>) -> Rule {
    Rule {
        id: "usual".to_owned(),
        effect,
        subject: SubjectRef::Inline(Box::new(subject)),
        targets: vec!["key:k1".to_owned()],
        conditions,
    }
}

// match の placeholder は対象 (列の先頭) の値で、ancestors の要素の placeholder はその要素が当たった祖先の値で埋まる。iTerm2 の要素は signing_id で見つかるので、より近い claude の値は使わない。
#[test]
fn placeholders_take_the_values_of_the_processes_they_matched() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    let subject = Subject {
        r#match: BTreeMap::from([(
            "binary".to_owned(),
            binary(Some(Pinnable::Pin), Some(Pinnable::Pin)),
        )]),
        ancestors: vec![
            entry("binary", binary(Some(Pinnable::Pin), None)),
            entry(
                "binary",
                binary(
                    Some(Pinnable::Pin),
                    Some(Pinnable::Value("com.googlecode.iterm2")),
                ),
            ),
        ],
        ..Subject::default()
    };
    let resolved = policy
        .resolve_subject(&SubjectRef::Inline(Box::new(subject)), &tagged)
        .unwrap();
    assert_eq!(
        resolved.r#match["binary"],
        binary(
            Some(Pinnable::Value(CLAUDE_TEAM)),
            Some(Pinnable::Value("com.example.tool"))
        )
    );
    assert_eq!(
        resolved.ancestors[0].r#match["binary"],
        binary(Some(Pinnable::Value(CLAUDE_TEAM)), None)
    );
    assert_eq!(
        resolved.ancestors[1].r#match["binary"],
        binary(
            Some(Pinnable::Value(ITERM_TEAM)),
            Some(Pinnable::Value("com.googlecode.iterm2"))
        )
    );
}

// include_self で対象自身に当たった要素は、対象自身の値で埋まる。
#[test]
fn an_entry_matching_the_target_itself_takes_its_values() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    let subject = Subject {
        ancestors: vec![entry("binary", binary(Some(Pinnable::Pin), None))],
        include_self: true,
        ..Subject::default()
    };
    let resolved = policy
        .resolve_subject(&SubjectRef::Inline(Box::new(subject)), &tagged)
        .unwrap();
    assert_eq!(
        resolved.ancestors[0].r#match["binary"],
        binary(Some(Pinnable::Value(CLAUDE_TEAM)), None)
    );
}

// process の placeholder は対象の個体の識別子と列の boot UUID を全部持つ値になる。
#[test]
fn the_process_placeholder_takes_every_identifier() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    let subject = Subject {
        r#match: BTreeMap::from([("process".to_owned(), MatchValue::Process(Pinnable::Pin))]),
        ..Subject::default()
    };
    let resolved = policy
        .resolve_subject(&SubjectRef::Inline(Box::new(subject)), &tagged)
        .unwrap();
    assert_eq!(
        resolved.r#match["process"],
        MatchValue::Process(Pinnable::Value(ProcessIdentity {
            boot_uuid: BOOT.to_owned(),
            unique_id: Some(10_004),
            pid: 4,
            start_time: chain.processes()[0].identity.start_time,
        }))
    );
}

// 名前で参照した subject は一覧の定義に展開され、一覧に無い名前は UnknownSubject。
#[test]
fn a_named_subject_is_expanded_from_the_list() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    let resolved = policy
        .resolve_subject(&SubjectRef::Named("the-shell".to_owned()), &tagged)
        .unwrap();
    assert_eq!(
        resolved.r#match["name"],
        MatchValue::Exact(Literal::Text("sh".to_owned()))
    );
    assert_eq!(
        policy.resolve_subject(&SubjectRef::Named("nope".to_owned()), &tagged),
        Err(GrantError::UnknownSubject {
            name: "nope".to_owned()
        })
    );
}

// 埋める値が無い placeholder は ValueUnavailable: 署名の無い対象の team_id、どの祖先も値を持たない要素の team_id。
#[test]
fn a_placeholder_without_a_value_is_unavailable() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let unsigned = chain(vec![named(2, "sh"), named(1, "launchd")]);
    let tagged = policy.tag(&unsigned);
    let unavailable = Err(GrantError::ValueUnavailable {
        key: "binary".to_owned(),
        field: Some("team_id".to_owned()),
    });
    let own = Subject {
        r#match: BTreeMap::from([("binary".to_owned(), binary(Some(Pinnable::Pin), None))]),
        ..Subject::default()
    };
    assert_eq!(
        policy
            .resolve_subject(&SubjectRef::Inline(Box::new(own.clone())), &tagged)
            .map(drop),
        unavailable
    );
    let ancestor = Subject {
        ancestors: vec![entry("binary", binary(Some(Pinnable::Pin), None))],
        ..Subject::default()
    };
    assert_eq!(
        policy
            .resolve_subject(&SubjectRef::Inline(Box::new(ancestor)), &tagged)
            .map(drop),
        unavailable
    );
    let ctx = EvalContext::new(at(NOW));
    assert_eq!(
        policy
            .grant(&rule(Effect::Deny, own, Vec::new()), &tagged, &ctx)
            .map(drop),
        unavailable
    );
}

// grant は subject を解決し、各 condition を pin する。age は until に直り (key も until、引数は持たない)、created_at は ctx の now。返すだけで Policy には入れない。
#[test]
fn grant_pins_each_condition() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let ctx = EvalContext::new(at(NOW)).with_observed("app.unlock", Ok(Some(json!(12))));
    let subject = Subject {
        r#match: BTreeMap::from([("cwd".to_owned(), MatchValue::Pin)]),
        ..Subject::default()
    };
    let chain_with_cwd = chain(vec![ProcessInfo {
        cwd: Some("/Users/alice/src/pj1".into()),
        ..named(4, "sh")
    }]);
    let tagged_cwd = policy.tag(&chain_with_cwd);
    let grant = policy
        .grant(
            &rule(
                Effect::Allow,
                subject,
                vec![
                    ConditionUse::named("app.unlock"),
                    ConditionUse::with_args("age", json!("1h")),
                    ConditionUse::with_args("uses", json!(3)),
                    ConditionUse::with_args(
                        "time.window",
                        json!({"days": ["mon"], "from": "09:00", "to": "18:00"}),
                    ),
                ],
            ),
            &tagged_cwd,
            &ctx,
        )
        .unwrap();
    assert_eq!(
        grant.subject.r#match["cwd"],
        MatchValue::Exact(Literal::Text("/Users/alice/src/pj1".to_owned()))
    );
    assert_eq!(
        grant.conditions,
        vec![
            PinnedCondition {
                key: "app.unlock".to_owned(),
                args: None,
                pinned: Some(json!(12)),
            },
            PinnedCondition {
                key: "until".to_owned(),
                args: None,
                pinned: Some(json!("2026-11-08T05:00:00Z")),
            },
            PinnedCondition {
                key: "uses".to_owned(),
                args: Some(json!(3)),
                pinned: Some(json!(3)),
            },
            PinnedCondition {
                key: "time.window".to_owned(),
                args: Some(json!({"days": ["mon"], "from": "09:00", "to": "18:00"})),
                pinned: None,
            },
        ]
    );
    assert_eq!(grant.rule_id, "usual");
    assert_eq!(grant.effect, Effect::Allow);
    assert_eq!(grant.targets, vec!["key:k1".to_owned()]);
    assert_eq!(grant.created_at, at(NOW));
    assert!(grant.id.starts_with("g-"));
    assert_eq!(policy.grants().count(), 0);
}

// 同じ rule から作った grant にも別々の id が付く。
#[test]
fn every_grant_gets_its_own_id() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    let ctx = EvalContext::new(at(NOW));
    let deny = rule(Effect::Deny, Subject::default(), Vec::new());
    let first = policy.grant(&deny, &tagged, &ctx).unwrap();
    let second = policy.grant(&deny, &tagged, &ctx).unwrap();
    assert_ne!(first.id, second.id);
}

// 寿命型の観測値が無ければ (Ok(None) も Err も) grant は作れない (Pin の Unobservable)。不正な引数は InvalidArgs。
#[test]
fn a_lifetime_condition_without_an_observation_cannot_be_pinned() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    let unlock = rule(
        Effect::Deny,
        Subject::default(),
        vec![ConditionUse::named("app.unlock")],
    );
    let unobservable = Err(GrantError::Pin {
        key: "app.unlock".to_owned(),
        error: PinError::Unobservable,
    });
    assert_eq!(
        policy
            .grant(&unlock, &tagged, &EvalContext::new(at(NOW)))
            .map(drop),
        unobservable
    );
    let failed = EvalContext::new(at(NOW)).with_observed(
        "app.unlock",
        Err(procline_acl::ObserveError {
            reason: "the vault is unreachable".to_owned(),
        }),
    );
    assert_eq!(
        policy.grant(&unlock, &tagged, &failed).map(drop),
        unobservable
    );
    let bad_age = rule(
        Effect::Deny,
        Subject::default(),
        vec![ConditionUse::with_args("age", json!("soon"))],
    );
    assert!(matches!(
        policy.grant(&bad_age, &tagged, &EvalContext::new(at(NOW))),
        Err(GrantError::Pin { key, error: PinError::InvalidArgs { .. } }) if key == "age"
    ));
}

/// The target with an executable path and its `PathMeta`.
fn at_path(meta: PathMeta) -> ProcessChain {
    chain(vec![ProcessInfo {
        path_meta: Some(meta),
        ..common::at_path(process(4), "/usr/local/bin/tool")
    }])
}

// path のクラスは grant でプロセスから決まる: root 所有で書けない場所なら強 (制限なし)、利用者が書ける場所なら中 (7 日以内の until が要る)。
#[test]
fn path_is_classed_by_the_process_when_granting() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let ctx = EvalContext::new(at(NOW));
    let path = Subject {
        r#match: BTreeMap::from([("path".to_owned(), MatchValue::Pin)]),
        ..Subject::default()
    };
    let unscoped = rule(Effect::Allow, path.clone(), Vec::new());
    let protected = at_path(PathMeta {
        owner_uid: 0,
        writable_by_user: false,
    });
    assert!(
        policy
            .grant(&unscoped, &policy.tag(&protected), &ctx)
            .is_ok()
    );
    let writable = at_path(PathMeta {
        owner_uid: 501,
        writable_by_user: true,
    });
    assert_eq!(
        policy
            .grant(&unscoped, &policy.tag(&writable), &ctx)
            .map(drop),
        Err(GrantError::ScopeTooWeak {
            class: Strength::Medium
        })
    );
}

// until の絶対時刻は grant を作る時点の now で判定する。7 日以内なら通り、それより先なら ScopeTooWeak (build は通っていても)。
#[test]
fn until_is_measured_from_the_time_of_granting() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let ctx = EvalContext::new(at(NOW));
    let writable = at_path(PathMeta {
        owner_uid: 501,
        writable_by_user: true,
    });
    let tagged = policy.tag(&writable);
    let path = Subject {
        r#match: BTreeMap::from([("path".to_owned(), MatchValue::Pin)]),
        ..Subject::default()
    };
    let until = |time: &str| {
        rule(
            Effect::Allow,
            path.clone(),
            vec![ConditionUse::with_args("until", json!(time))],
        )
    };
    assert!(
        policy
            .grant(&until("2026-11-15T04:00:00Z"), &tagged, &ctx)
            .is_ok()
    );
    assert_eq!(
        policy
            .grant(&until("2026-11-15T04:00:01Z"), &tagged, &ctx)
            .map(drop),
        Err(GrantError::ScopeTooWeak {
            class: Strength::Medium
        })
    );
}

// 制約に Condition("age") を書いても、grant では age が until に変わっているので満たされない。
#[test]
fn condition_age_is_never_met_by_a_grant() {
    let vocab = vocabulary();
    let policy = policy_with(
        &vocab,
        AllowConstraints {
            strong: ScopeRequirement::Unrestricted,
            medium: ScopeRequirement::Unrestricted,
            weak: ScopeRequirement::AnyOf(vec![ScopeOption::Condition("age".to_owned())]),
        },
    );
    let weak = Subject {
        r#match: BTreeMap::from([(
            "name".to_owned(),
            MatchValue::Exact(Literal::Text("sh".to_owned())),
        )]),
        ..Subject::default()
    };
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    let aged = rule(
        Effect::Allow,
        weak,
        vec![ConditionUse::with_args("age", json!("1h"))],
    );
    assert_eq!(
        policy
            .grant(&aged, &tagged, &EvalContext::new(at(NOW)))
            .map(drop),
        Err(GrantError::ScopeTooWeak {
            class: Strength::Weak
        })
    );
}
