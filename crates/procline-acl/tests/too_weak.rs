//! The strength of an `allow` grant decided again from the target process when evaluating (DR-0012), for each shape a subject can take: a named subject, a tag (with own conditions, or with `ancestors` only), a list of values with alternatives of different classes, and conditions on the ancestors.
//!
//! Every expectation follows from two rules, not from the output of the implementation:
//!
//! - The strength of a subject is the strongest class among its conditions on the process itself: `match`, and the own conditions of the definitions of its tags (DR-0003). `ancestors` never count, in either direction: a protected ancestor does not make the rule stronger, an unprotected one does not make it weaker. A tag counts as its weakest definition, and a tag defined by `ancestors` alone adds nothing; a subject with no own condition is `Weak`. A list of values counts as its weakest value (DR-0010).
//! - The class of a signature field of `binary` is Strong / Medium / Weak for a process that is protected / opened by authorization / open; `digest` alone is Medium / Medium / Weak (DR-0012). Protected: hardened runtime, no relaxing entitlement. Opened by authorization: hardened runtime with `get-task-allow` only. Open: no hardened runtime.
//!
//! The constraint table of these tests: Strong is unrestricted, Medium needs an `until` within 7 days, Weak needs `app.unlock`. A grant whose strength at evaluation does not meet the table with its conditions is not adopted and is listed in `Decision.too_weak`; the default effect is `ask`.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::{NOW, at, chain, named, process, signature, signed, vocabulary};
use procline_acl::{
    AllowConstraints, AncestorMatch, ConditionUse, Decision, Effect, EvalContext, Grant,
    MatchValue, PinnedCondition, Policy, ScopeOption, ScopeRequirement, Subject, SubjectRef, Tag,
    Target, Vocabulary,
};
use procline_core::{BinaryPin, Pinnable, ProcessChain, ProcessInfo};
use serde_json::{Value, json};

const TEAM: &str = "VWXYZ67890";
const TOOL: &str = "com.example.tool";
const TERMINAL_TEAM: &str = "H7V7XYVQ7D";
const TERMINAL: &str = "com.example.terminal";
const GET_TASK_ALLOW: &str = "com.apple.security.get-task-allow";

fn constraints() -> AllowConstraints {
    AllowConstraints {
        strong: ScopeRequirement::Unrestricted,
        medium: ScopeRequirement::AnyOf(vec![ScopeOption::UntilWithin(Duration::from_secs(
            7 * 24 * 3600,
        ))]),
        weak: ScopeRequirement::AnyOf(vec![ScopeOption::Condition("app.unlock".to_owned())]),
    }
}

fn policy<'v>(
    vocab: &'v Vocabulary,
    subjects: Vec<(String, Subject)>,
    tags: Vec<Tag>,
) -> Policy<'v> {
    Policy::from_parts(
        vocab,
        subjects,
        tags,
        Vec::new(),
        Vec::new(),
        constraints(),
        Effect::Ask,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Build {
    Protected,
    Authorization,
    Open,
}

/// A process signed with the Team ID and identifier, as the build.
fn build(pid: i32, team: &str, id: &str, build: Build) -> ProcessInfo {
    let mut signature = signature(team, id);
    signature.runtime.hardened_runtime = build != Build::Open;
    if build == Build::Authorization {
        signature.entitlements = Some(
            [(GET_TASK_ALLOW.to_owned(), Value::Bool(true))]
                .into_iter()
                .collect(),
        );
    }
    signed(process(pid), signature)
}

/// The tool as the build, under the terminal as the build, under launchd.
fn tool_under_terminal(tool: Build, terminal: Build) -> ProcessChain {
    chain(vec![
        build(30, TEAM, TOOL, tool),
        build(20, TERMINAL_TEAM, TERMINAL, terminal),
        named(1, "launchd"),
    ])
}

fn signed_as(team: &str, id: &str) -> MatchValue {
    MatchValue::Binary(BinaryPin {
        digest: None,
        team_id: Some(Pinnable::Value(team.to_owned())),
        signing_id: Some(Pinnable::Value(id.to_owned())),
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

fn under(key: &str, value: MatchValue) -> AncestorMatch {
    AncestorMatch {
        r#match: BTreeMap::from([(key.to_owned(), value)]),
        tags: Vec::new(),
    }
}

/// An `allow` grant on the subject with the conditions, as stored and loaded again (the grant is not made here, so that a grant the constraints would reject when made can be evaluated too).
fn stored(id: &str, subject: Subject, conditions: Vec<PinnedCondition>) -> Grant {
    Grant {
        id: id.to_owned(),
        rule_id: format!("rule-{id}"),
        effect: Effect::Allow,
        subject,
        targets: Vec::new(),
        conditions,
        created_at: at(NOW),
        created_from: None,
    }
}

fn unlock(generation: u64) -> PinnedCondition {
    PinnedCondition {
        key: "app.unlock".to_owned(),
        args: None,
        pinned: Some(json!(generation)),
    }
}

fn evaluate(policy: &Policy<'_>, chain: &ProcessChain) -> Decision {
    let ctx = EvalContext::new(at(NOW)).with_observed("app.unlock", Ok(Some(json!(1))));
    policy.evaluate(&policy.tag(chain), &Target("key:k1".to_owned()), &ctx)
}

/// The grant was adopted (`Some(true)`), matched but was too weak (`Some(false)`), or did not take part.
fn adopted(decision: &Decision, id: &str) -> Option<bool> {
    if decision.grant_id.as_deref() == Some(id) {
        Some(true)
    } else if decision.too_weak.iter().any(|weak| weak == id) {
        Some(false)
    } else {
        None
    }
}

// rule が名前付きの subject を参照する: grant を作る時に subject は展開されて inline になるので、確かめ直しも展開した中身 (自身への binary の署名由来の field) で決まる。名前で参照したことで強さは変わらない。保護のあるビルドで作った制限なしの grant は、保護のあるビルドでは採用され、認可で開くビルド (中、until が無い) と開いているビルド (弱、app.unlock が無い) には当たるが採用されない。
#[test]
fn a_rule_on_a_named_subject() {
    let vocab = vocabulary();
    let policy = policy(
        &vocab,
        vec![("the-tool".to_owned(), own("binary", signed_as(TEAM, TOOL)))],
        Vec::new(),
    );
    let rule = policy
        .rule_builder("r", SubjectRef::Named("the-tool".to_owned()))
        .allow()
        .build()
        .unwrap();
    let protected = tool_under_terminal(Build::Protected, Build::Protected);
    let mut grant = policy
        .grant(&rule, &policy.tag(&protected), &EvalContext::new(at(NOW)))
        .unwrap();
    grant.id = "g".to_owned();
    let mut policy = policy;
    policy.add_grant(grant);
    for (tool, expected) in [
        (Build::Protected, Some(true)),
        (Build::Authorization, Some(false)),
        (Build::Open, Some(false)),
    ] {
        let decision = evaluate(&policy, &tool_under_terminal(tool, Build::Protected));
        assert_eq!(adopted(&decision, "g"), expected, "{tool:?}");
    }
}

// タグを条件にした rule で、タグの定義が自身への条件 (binary の署名由来の field) を持つ: タグの強さはその定義の自身への条件のクラスで、評価では照合したプロセス (タグが付いた対象自身) の保護で決め直す。期待は名前付きの subject と同じ (保護あり 強 → 採用、認可で開く 中 → 不採用、開いている 弱 → 不採用)。
#[test]
fn a_rule_on_a_tag_with_own_conditions() {
    let vocab = vocabulary();
    let tags = vec![Tag {
        name: "tool".to_owned(),
        subject: SubjectRef::Inline(Box::new(own("binary", signed_as(TEAM, TOOL)))),
    }];
    let mut policy = policy(&vocab, Vec::new(), tags);
    let subject = Subject {
        tags: vec!["tool".to_owned()],
        ..Subject::default()
    };
    policy.add_grant(stored("g", subject, Vec::new()));
    for (tool, expected) in [
        (Build::Protected, Some(true)),
        (Build::Authorization, Some(false)),
        (Build::Open, Some(false)),
    ] {
        let decision = evaluate(&policy, &tool_under_terminal(tool, Build::Protected));
        assert_eq!(adopted(&decision, "g"), expected, "{tool:?}");
    }
}

// タグの同名の定義が 2 つあり、1 つは自身への署名由来の field、1 つは ancestors だけ: タグの強さは定義のうち最も弱いもので、ancestors だけの定義は自身を縛らないので、タグは強さに何も足さない (弱)。対象自身も祖先も保護のあるビルドでも、制限なしの grant は採用されない。app.unlock を持つ grant (弱の制約を満たす) は採用される。
#[test]
fn a_rule_on_a_tag_defined_by_ancestors_alone() {
    let vocab = vocabulary();
    let tags = vec![
        Tag {
            name: "tool".to_owned(),
            subject: SubjectRef::Inline(Box::new(own("binary", signed_as(TEAM, TOOL)))),
        },
        Tag {
            name: "tool".to_owned(),
            subject: SubjectRef::Inline(Box::new(Subject {
                ancestors: vec![under("binary", signed_as(TERMINAL_TEAM, TERMINAL))],
                ..Subject::default()
            })),
        },
    ];
    let mut policy = policy(&vocab, Vec::new(), tags);
    let subject = Subject {
        tags: vec!["tool".to_owned()],
        ..Subject::default()
    };
    policy.add_grant(stored("unrestricted", subject.clone(), Vec::new()));
    policy.add_grant(stored("per-unlock", subject, vec![unlock(1)]));
    let decision = evaluate(
        &policy,
        &tool_under_terminal(Build::Protected, Build::Protected),
    );
    assert_eq!(adopted(&decision, "unrestricted"), Some(false));
    assert_eq!(adopted(&decision, "per-unlock"), Some(true));
}

// 値の列で、要素のクラスが違う (署名由来の field の値と digest だけの値): 列のクラスは要素の最弱。保護ありでは 強 と 中 の最弱で 中、認可で開くでは 中 と 中 で 中、開いているでは 弱 と 弱 で 弱。7 日以内の until を持つ grant は、中までは採用され、開いているビルドでは採用されない。列の中の強い要素 (署名由来の field) に当たっていても、列全体のクラスは最弱の要素で決まる。
#[test]
fn a_list_of_values_of_different_classes() {
    let vocab = vocabulary();
    let mut policy = policy(&vocab, Vec::new(), Vec::new());
    let list = MatchValue::AnyOf(vec![
        signed_as(TEAM, TOOL),
        MatchValue::Binary(BinaryPin {
            digest: Some(Pinnable::Value("sha256:00ff".to_owned())),
            team_id: None,
            signing_id: None,
            bundle_id: None,
            cdhash: None,
        }),
    ]);
    let rule = policy
        .rule_builder("r", SubjectRef::Inline(Box::new(own("binary", list))))
        .condition(ConditionUse::with_args("age", json!("1d")))
        .allow()
        .build()
        .unwrap();
    let protected = tool_under_terminal(Build::Protected, Build::Protected);
    let mut grant = policy
        .grant(&rule, &policy.tag(&protected), &EvalContext::new(at(NOW)))
        .unwrap();
    grant.id = "g".to_owned();
    policy.add_grant(grant);
    for (tool, expected) in [
        (Build::Protected, Some(true)),
        (Build::Authorization, Some(true)),
        (Build::Open, Some(false)),
    ] {
        let decision = evaluate(&policy, &tool_under_terminal(tool, Build::Protected));
        assert_eq!(adopted(&decision, "g"), expected, "{tool:?}");
    }
    // 中の列に制限なしの grant は、保護のあるビルドでも足りない (列の最弱が中)。
    let unrestricted = stored(
        "unrestricted",
        policy.grants().next().unwrap().subject.clone(),
        Vec::new(),
    );
    policy.add_grant(unrestricted);
    let decision = evaluate(&policy, &protected);
    assert_eq!(adopted(&decision, "unrestricted"), Some(false));
}

// ancestors の要素に署名由来の条件がある: 祖先への条件はルールの強さに数えないので、確かめ直しでも祖先の保護は効かない。(1) 自身への条件が名前だけ (弱) なら、祖先が保護のあるビルドでも制限なしの grant は採用されない。(2) 自身への条件が署名由来の field (保護ありで強) なら、祖先が開いているビルドでも制限なしの grant は採用される。
#[test]
fn conditions_on_the_ancestors_do_not_count() {
    let vocab = vocabulary();
    let mut policy = policy(&vocab, Vec::new(), Vec::new());
    let on_terminal = under("binary", signed_as(TERMINAL_TEAM, TERMINAL));
    policy.add_grant(stored(
        "named-under-terminal",
        Subject {
            r#match: BTreeMap::from([(
                "name".to_owned(),
                MatchValue::Exact(procline_acl::Literal::Text("tool".to_owned())),
            )]),
            ancestors: vec![on_terminal.clone()],
            ..Subject::default()
        },
        Vec::new(),
    ));
    policy.add_grant(stored(
        "signed-under-terminal",
        Subject {
            ancestors: vec![on_terminal],
            ..own("binary", signed_as(TEAM, TOOL))
        },
        Vec::new(),
    ));
    let mut protected_both = tool_under_terminal(Build::Protected, Build::Protected);
    let named_tool = ProcessInfo {
        name: Some("tool".to_owned()),
        ..protected_both.processes()[0].clone()
    };
    protected_both = chain(vec![
        named_tool,
        protected_both.processes()[1].clone(),
        protected_both.processes()[2].clone(),
    ]);
    let decision = evaluate(&policy, &protected_both);
    assert_eq!(adopted(&decision, "named-under-terminal"), Some(false));

    let decision = evaluate(&policy, &tool_under_terminal(Build::Protected, Build::Open));
    assert_eq!(adopted(&decision, "signed-under-terminal"), Some(true));
}
