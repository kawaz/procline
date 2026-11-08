//! `SubjectBuilder` / `AncestorBuilder` (merging `pin` and `exact`, `Conflict`, `Empty`) and `RuleBuilder::build` (the vocabulary, the list, the strength and `ScopeTooWeak`).

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::vocabulary;
use procline_acl::{
    AllowConstraints, AncestorBuilder, AncestorMatch, BuildError, ConditionUse, Effect, Literal,
    MatchValue, PinSpec, Policy, ScopeOption, ScopeRequirement, Subject, SubjectBuilder,
    SubjectRef, Tag, Vocabulary,
};
use procline_core::{BinaryField, BinaryPin, Pinnable, Strength};
use serde_json::json;

fn binary(
    team_id: Option<Pinnable<&str>>,
    signing_id: Option<Pinnable<&str>>,
    bundle_id: Option<Pinnable<&str>>,
) -> BinaryPin {
    let owned = |field: Option<Pinnable<&str>>| {
        field.map(|field| match field {
            Pinnable::Pin => Pinnable::Pin,
            Pinnable::Value(value) => Pinnable::Value(value.to_owned()),
        })
    };
    BinaryPin {
        digest: None,
        team_id: owned(team_id),
        signing_id: owned(signing_id),
        bundle_id: owned(bundle_id),
        cdhash: None,
    }
}

fn text(value: &str) -> MatchValue {
    MatchValue::Exact(Literal::Text(value.to_owned()))
}

// 選んだ field を placeholder にし、妥当性の規則が要る field も placeholder で足す (signing_id には team_id、bundle_id には team_id と signing_id)。
#[test]
fn pinned_binary_fields_bring_the_fields_they_need() {
    let subject = SubjectBuilder::new()
        .pin("binary", PinSpec::Binary(vec![BinaryField::BundleId]))
        .build()
        .unwrap();
    assert_eq!(
        subject.r#match["binary"],
        MatchValue::Binary(binary(
            Some(Pinnable::Pin),
            Some(Pinnable::Pin),
            Some(Pinnable::Pin)
        ))
    );
}

// 同じ binary への exact と pin は field 単位で 1 つの値に合成する (signing_id で見つけ、その Team ID を pin)。規則が要る field が exact にあれば placeholder を足さない。
#[test]
fn exact_and_pin_merge_field_by_field() {
    let entry = AncestorBuilder::new()
        .exact(
            "binary",
            MatchValue::Binary(binary(
                None,
                Some(Pinnable::Value("com.anthropic.claude-code")),
                None,
            )),
        )
        .pin("binary", PinSpec::Binary(vec![BinaryField::TeamId]))
        .build()
        .unwrap();
    assert_eq!(
        entry.r#match["binary"],
        MatchValue::Binary(binary(
            Some(Pinnable::Pin),
            Some(Pinnable::Value("com.anthropic.claude-code")),
            None
        ))
    );
    let subject = SubjectBuilder::new()
        .pin("binary", PinSpec::Binary(vec![BinaryField::SigningId]))
        .exact(
            "binary",
            MatchValue::Binary(binary(Some(Pinnable::Value("TEAM")), None, None)),
        )
        .build()
        .unwrap();
    assert_eq!(
        subject.r#match["binary"],
        MatchValue::Binary(binary(
            Some(Pinnable::Value("TEAM")),
            Some(Pinnable::Pin),
            None
        ))
    );
}

// 同じ field が pin と exact の両方にあれば Conflict で、どの field かを返す。
#[test]
fn a_binary_field_given_twice_is_a_conflict() {
    let result = SubjectBuilder::new()
        .exact(
            "binary",
            MatchValue::Binary(binary(Some(Pinnable::Value("TEAM")), None, None)),
        )
        .pin("binary", PinSpec::Binary(vec![BinaryField::TeamId]))
        .build();
    assert_eq!(
        result,
        Err(BuildError::Conflict {
            key: "binary".to_owned(),
            field: Some("team_id".to_owned()),
        })
    );
}

// 単純項目と process は値を 1 つしか持たないので、2 回目の pin / exact は Conflict (field なし)。
#[test]
fn a_simple_item_given_twice_is_a_conflict() {
    let conflict = |key: &str| {
        Err(BuildError::Conflict {
            key: key.to_owned(),
            field: None,
        })
    };
    assert_eq!(
        SubjectBuilder::new()
            .pin("cwd", PinSpec::All)
            .exact("cwd", text("/Users/alice"))
            .build()
            .map(drop),
        conflict("cwd")
    );
    assert_eq!(
        AncestorBuilder::new()
            .pin("process", PinSpec::All)
            .pin("process", PinSpec::All)
            .build()
            .map(drop),
        conflict("process")
    );
}

// PinSpec::All は単純項目では Pin、process と responsible では個体の placeholder (Process(Pin)) になる。
#[test]
fn pin_all_takes_the_placeholder_of_the_item() {
    let subject = SubjectBuilder::new()
        .pin("process", PinSpec::All)
        .pin("responsible", PinSpec::All)
        .pin("cwd", PinSpec::All)
        .build()
        .unwrap();
    assert_eq!(
        subject.r#match["process"],
        MatchValue::Process(Pinnable::Pin)
    );
    assert_eq!(
        subject.r#match["responsible"],
        MatchValue::Process(Pinnable::Pin)
    );
    assert_eq!(subject.r#match["cwd"], MatchValue::Pin);
}

// 条件が 1 つも無い subject と祖先の要素は Empty。include_self だけでは条件にならない。
#[test]
fn no_condition_is_empty() {
    assert_eq!(SubjectBuilder::new().build(), Err(BuildError::Empty));
    assert_eq!(
        SubjectBuilder::new().include_self().build(),
        Err(BuildError::Empty)
    );
    assert_eq!(AncestorBuilder::new().build(), Err(BuildError::Empty));
    assert!(SubjectBuilder::new().tag("terminal-app").build().is_ok());
    assert!(
        SubjectBuilder::new()
            .ancestor(AncestorBuilder::new().tag("terminal-app").build().unwrap())
            .include_self()
            .build()
            .is_ok_and(|subject| subject.include_self && subject.r#match.is_empty())
    );
}

// build が検査する値の妥当性: binary の規則 (exact だけの signing_id に team_id が無い)、PinSpec と key の組み合わせ、exact に placeholder を渡すこと。
#[test]
fn invalid_values_are_rejected() {
    let invalid = |result: Result<Subject, BuildError>, key: &str| {
        assert!(
            matches!(&result, Err(BuildError::InvalidValue { key: k, .. }) if k == key),
            "{result:?}"
        );
    };
    invalid(
        SubjectBuilder::new()
            .exact(
                "binary",
                MatchValue::Binary(binary(None, Some(Pinnable::Value("myapp")), None)),
            )
            .build(),
        "binary",
    );
    invalid(
        SubjectBuilder::new()
            .pin("binary", PinSpec::Binary(Vec::new()))
            .build(),
        "binary",
    );
    invalid(
        SubjectBuilder::new().pin("binary", PinSpec::All).build(),
        "binary",
    );
    invalid(
        SubjectBuilder::new()
            .pin("cwd", PinSpec::Binary(vec![BinaryField::TeamId]))
            .build(),
        "cwd",
    );
    invalid(
        SubjectBuilder::new().exact("cwd", MatchValue::Pin).build(),
        "cwd",
    );
}

/// The example table of the design: Strong unrestricted, Medium within 7 days or an epoch scope, Weak an epoch scope.
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

fn signed_app() -> BTreeMap<String, MatchValue> {
    BTreeMap::from([(
        "binary".to_owned(),
        MatchValue::Binary(binary(
            Some(Pinnable::Value("TEAM")),
            Some(Pinnable::Value("com.example.app")),
            None,
        )),
    )])
}

/// Tags: `signed-app` on the process itself (Strong), `under-signed-app` on an ancestor only (Weak), `via-signed-app` requiring `signed-app` (Strong through the tag). A named subject `named-weak` on the name only.
fn policy(vocab: &Vocabulary) -> Policy<'_> {
    let inline = |subject: Subject| SubjectRef::Inline(Box::new(subject));
    Policy::from_parts(
        vocab,
        vec![(
            "named-weak".to_owned(),
            Subject {
                r#match: BTreeMap::from([("name".to_owned(), text("zsh"))]),
                ..Subject::default()
            },
        )],
        vec![
            Tag {
                name: "signed-app".to_owned(),
                subject: inline(Subject {
                    r#match: signed_app(),
                    ..Subject::default()
                }),
            },
            Tag {
                name: "under-signed-app".to_owned(),
                subject: inline(Subject {
                    ancestors: vec![AncestorMatch {
                        r#match: signed_app(),
                        tags: Vec::new(),
                    }],
                    ..Subject::default()
                }),
            },
            Tag {
                name: "via-signed-app".to_owned(),
                subject: inline(Subject {
                    tags: vec!["signed-app".to_owned()],
                    ..Subject::default()
                }),
            },
        ],
        Vec::new(),
        Vec::new(),
        constraints(),
        Effect::Deny,
    )
}

fn inline(subject: Subject) -> SubjectRef {
    SubjectRef::Inline(Box::new(subject))
}

fn own(key: &str, value: MatchValue) -> Subject {
    Subject {
        r#match: BTreeMap::from([(key.to_owned(), value)]),
        ..Subject::default()
    }
}

fn tagged(name: &str) -> Subject {
    Subject {
        tags: vec![name.to_owned()],
        ..Subject::default()
    }
}

// rule は値を持ったまま返り、conditions は記号のまま (世代や時刻を記録しない)。
#[test]
fn build_returns_the_static_rule() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let rule = policy
        .rule_builder(
            "usual",
            inline(own(
                "binary",
                MatchValue::Binary(binary(Some(Pinnable::Pin), None, None)),
            )),
        )
        .targets(["key:k1"])
        .condition(ConditionUse::with_args("age", json!("1h")))
        .allow()
        .build()
        .unwrap();
    assert_eq!(rule.id, "usual");
    assert_eq!(rule.effect, Effect::Allow);
    assert_eq!(rule.targets, vec!["key:k1".to_owned()]);
    assert_eq!(
        rule.conditions,
        vec![ConditionUse::with_args("age", json!("1h"))]
    );
}

// 語彙との照合: 未登録の match の key と condition の key は UnknownItem、条件の項目を match に書くのも UnknownItem。
#[test]
fn unregistered_items_are_unknown() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let unknown = |key: &str| {
        Err(BuildError::UnknownItem {
            key: key.to_owned(),
        })
    };
    assert_eq!(
        policy
            .rule_builder("r", inline(own("app.nope", text("x"))))
            .deny()
            .build(),
        unknown("app.nope")
    );
    assert_eq!(
        policy
            .rule_builder("r", inline(own("until", text("x"))))
            .deny()
            .build(),
        unknown("until")
    );
    assert_eq!(
        policy
            .rule_builder("r", inline(own("name", text("zsh"))))
            .condition(ConditionUse::named("app.nope"))
            .deny()
            .build(),
        unknown("app.nope")
    );
}

// 一覧との照合: 定義の無いタグ名は UnknownTag (祖先の要素の中でも)、一覧に無い subject 名は UnknownSubject。名前付きの subject は一覧から解決される。
#[test]
fn names_are_checked_against_the_list() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    assert_eq!(
        policy
            .rule_builder(
                "r",
                inline(Subject {
                    ancestors: vec![AncestorMatch {
                        r#match: BTreeMap::new(),
                        tags: vec!["nope".to_owned()],
                    }],
                    ..Subject::default()
                })
            )
            .deny()
            .build(),
        Err(BuildError::UnknownTag {
            name: "nope".to_owned()
        })
    );
    assert_eq!(
        policy
            .rule_builder("r", SubjectRef::Named("nope".to_owned()))
            .deny()
            .build(),
        Err(BuildError::UnknownSubject {
            name: "nope".to_owned()
        })
    );
    let rule = policy
        .rule_builder("r", SubjectRef::Named("named-weak".to_owned()))
        .deny()
        .build()
        .unwrap();
    assert_eq!(rule.subject, SubjectRef::Named("named-weak".to_owned()));
}

// 値の妥当性: Matcher::validate (cwd は絶対パス)、Condition::validate_args (age の期間)、targets の glob。effect が無ければ MissingEffect。
#[test]
fn values_are_validated_by_their_items() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let invalid = |result: Result<_, BuildError>, key: &str| {
        assert!(
            matches!(&result, Err(BuildError::InvalidValue { key: k, .. }) if k == key),
            "{result:?}"
        );
    };
    invalid(
        policy
            .rule_builder("r", inline(own("cwd", text("src/pj1"))))
            .deny()
            .build(),
        "cwd",
    );
    invalid(
        policy
            .rule_builder("r", inline(own("name", text("zsh"))))
            .condition(ConditionUse::with_args("age", json!("1x")))
            .deny()
            .build(),
        "age",
    );
    invalid(
        policy
            .rule_builder("r", inline(own("name", text("zsh"))))
            .targets(["key:{a"])
            .deny()
            .build(),
        "targets",
    );
    assert_eq!(
        policy
            .rule_builder("r", inline(own("name", text("zsh"))))
            .build(),
        Err(BuildError::MissingEffect)
    );
}

// 強さは自身への条件のクラスの最強 (DR-0003)。署名由来の field (placeholder でも) を持つ binary は強なので制限なしの allow が通る。
#[test]
fn a_strong_own_condition_needs_no_scope() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let pinned = MatchValue::Binary(binary(Some(Pinnable::Pin), None, None));
    assert!(
        policy
            .rule_builder("r", inline(own("binary", pinned)))
            .allow()
            .build()
            .is_ok()
    );
}

// ancestors の条件は強さに数えない。祖先を強く特定しても自身は弱で、弱の制約 (世代の scope) が要る。
#[test]
fn ancestors_do_not_count_towards_the_strength() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let subject = Subject {
        ancestors: vec![AncestorMatch {
            r#match: signed_app(),
            tags: Vec::new(),
        }],
        include_self: true,
        ..Subject::default()
    };
    assert_eq!(
        policy
            .rule_builder("r", inline(subject.clone()))
            .allow()
            .build(),
        Err(BuildError::ScopeTooWeak {
            class: Strength::Weak
        })
    );
    assert!(
        policy
            .rule_builder("r", inline(subject))
            .condition(ConditionUse::named("app.unlock"))
            .allow()
            .build()
            .is_ok()
    );
}

// タグを条件にしたときの強さはタグの定義の自身の部分の強さ。自身への条件を持つ定義 (他のタグ経由でも) は強、ancestors だけの定義は弱。
#[test]
fn a_tag_counts_with_the_own_conditions_of_its_definition() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    for strong in ["signed-app", "via-signed-app"] {
        assert!(
            policy
                .rule_builder("r", inline(tagged(strong)))
                .allow()
                .build()
                .is_ok(),
            "{strong}"
        );
    }
    assert_eq!(
        policy
            .rule_builder("r", inline(tagged("under-signed-app")))
            .allow()
            .build(),
        Err(BuildError::ScopeTooWeak {
            class: Strength::Weak
        })
    );
}

// プロセスの無い build では path は中。中の制約 (UntilWithin 7 日) は age の長さで判定し、until は時刻を grant まで見ないので通す。
#[test]
fn medium_needs_a_short_enough_age_or_an_until() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let build = |condition: Option<ConditionUse>| {
        let builder = policy.rule_builder("r", inline(own("path", MatchValue::Pin)));
        match condition {
            Some(condition) => builder.condition(condition),
            None => builder,
        }
        .allow()
        .build()
    };
    let too_weak = Err(BuildError::ScopeTooWeak {
        class: Strength::Medium,
    });
    assert_eq!(build(None).map(drop), too_weak);
    assert!(build(Some(ConditionUse::with_args("age", json!("7d")))).is_ok());
    assert_eq!(
        build(Some(ConditionUse::with_args("age", json!("8d")))).map(drop),
        too_weak
    );
    assert!(
        build(Some(ConditionUse::with_args(
            "until",
            json!("2099-01-01T00:00:00Z")
        )))
        .is_ok()
    );
    assert!(build(Some(ConditionUse::named("app.unlock"))).is_ok());
}

// deny と ask には制約をかけない。弱い条件の拒否も scope なしで作れる。
#[test]
fn deny_and_ask_are_not_constrained() {
    let vocab = vocabulary();
    let policy = policy(&vocab);
    let weak = || inline(own("name", text("zsh")));
    assert!(policy.rule_builder("r", weak()).deny().build().is_ok());
    assert!(policy.rule_builder("r", weak()).ask().build().is_ok());
    assert_eq!(
        policy.rule_builder("r", weak()).allow().build().map(drop),
        Err(BuildError::ScopeTooWeak {
            class: Strength::Weak
        })
    );
}
