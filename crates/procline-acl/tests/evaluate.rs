//! `Policy::evaluate` / `Policy::explain` (DR-0008): deny > allow > ask, the default effect, targets, the order of adoption, `uses` and `updated_grant`, `expired`, `undecidable`, and the trace.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{NOW, at, chain, named, vocabulary};
use procline_acl::{
    AllowConstraints, AncestorMatch, Condition, ConditionKind, Decision, Effect, EvalContext,
    Grant, Item, Literal, MatchValue, ObserveError, Observed, PinError, PinnedCondition, Policy,
    ScopeRequirement, Subject, SubjectRef, Tag, Target, TraceEntry, Vocabulary,
};
use procline_core::{ProcessChain, Truncated};
use serde_json::{Value, json};

fn constraints() -> AllowConstraints {
    AllowConstraints {
        strong: ScopeRequirement::Unrestricted,
        medium: ScopeRequirement::Unrestricted,
        weak: ScopeRequirement::Unrestricted,
    }
}

fn name_is(name: &str) -> BTreeMap<String, MatchValue> {
    BTreeMap::from([(
        "name".to_owned(),
        MatchValue::Exact(Literal::Text(name.to_owned())),
    )])
}

/// A subject on the name of the process itself.
fn own_name(name: &str) -> Subject {
    Subject {
        r#match: name_is(name),
        ..Subject::default()
    }
}

/// A subject on the name of the process itself and of an ancestor.
fn under(name: &str, ancestor: &str) -> Subject {
    Subject {
        r#match: name_is(name),
        ancestors: vec![AncestorMatch {
            r#match: name_is(ancestor),
            tags: Vec::new(),
        }],
        ..Subject::default()
    }
}

fn pinned(key: &str, args: Option<Value>, pinned: Option<Value>) -> PinnedCondition {
    PinnedCondition {
        key: key.to_owned(),
        args,
        pinned,
    }
}

fn uses(count: u64) -> PinnedCondition {
    pinned("uses", Some(json!(3)), Some(json!(count)))
}

fn grant(
    id: &str,
    effect: Effect,
    subject: Subject,
    conditions: Vec<PinnedCondition>,
    created_at: u64,
) -> Grant {
    Grant {
        id: id.to_owned(),
        rule_id: format!("rule-{id}"),
        effect,
        subject,
        targets: Vec::new(),
        conditions,
        created_at: at(created_at),
        created_from: None,
    }
}

fn policy_with<'v>(
    vocab: &'v Vocabulary,
    tags: Vec<Tag>,
    grants: Vec<Grant>,
    default_effect: Effect,
) -> Policy<'v> {
    Policy::from_parts(
        vocab,
        Vec::new(),
        tags,
        Vec::new(),
        grants,
        constraints(),
        default_effect,
    )
}

fn policy(vocab: &Vocabulary, grants: Vec<Grant>) -> Policy<'_> {
    policy_with(vocab, Vec::new(), grants, Effect::Deny)
}

/// `sh` under `zsh` under `launchd`, complete.
fn shell() -> ProcessChain {
    chain(vec![named(3, "sh"), named(2, "zsh"), named(1, "launchd")])
}

fn target() -> Target {
    Target("key:k1".to_owned())
}

fn evaluate(policy: &Policy<'_>, chain: &ProcessChain, ctx: &EvalContext) -> Decision {
    policy.evaluate(&policy.tag(chain), &target(), ctx)
}

fn now() -> EvalContext {
    EvalContext::new(at(NOW))
}

// deny が 1 つでも当たれば、当たった allow があっても拒否。採用した grant は deny のもの。
#[test]
fn deny_wins_over_allow() {
    let vocab = vocabulary();
    let policy = policy(
        &vocab,
        vec![
            grant("allow", Effect::Allow, own_name("sh"), Vec::new(), 1),
            grant("deny", Effect::Deny, own_name("sh"), Vec::new(), 2),
        ],
    );
    let decision = evaluate(&policy, &shell(), &now());
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.grant_id.as_deref(), Some("deny"));
}

// allow は ask より優先し、ask だけが当たれば Ask を返して grant_id はその ask の grant。
#[test]
fn allow_wins_over_ask_and_ask_is_returned() {
    let vocab = vocabulary();
    let both = policy(
        &vocab,
        vec![
            grant("ask", Effect::Ask, own_name("sh"), Vec::new(), 1),
            grant("allow", Effect::Allow, own_name("sh"), Vec::new(), 2),
        ],
    );
    let decision = evaluate(&both, &shell(), &now());
    assert_eq!(
        (decision.effect, decision.grant_id.as_deref()),
        (Effect::Allow, Some("allow"))
    );
    let ask = policy_with(
        &vocab,
        Vec::new(),
        vec![grant("ask", Effect::Ask, own_name("sh"), Vec::new(), 1)],
        Effect::Allow,
    );
    let decision = evaluate(&ask, &shell(), &now());
    assert_eq!(
        (decision.effect, decision.grant_id.as_deref()),
        (Effect::Ask, Some("ask"))
    );
}

// どの grant にも当たらなければ既定の effect で、grant_id は None。
#[test]
fn no_match_gives_the_default_effect() {
    let vocab = vocabulary();
    for default in [Effect::Deny, Effect::Ask, Effect::Allow] {
        let policy = policy_with(
            &vocab,
            Vec::new(),
            vec![grant(
                "bash",
                Effect::Allow,
                own_name("bash"),
                Vec::new(),
                1,
            )],
            default,
        );
        let decision = evaluate(&policy, &shell(), &now());
        assert_eq!((decision.effect, decision.grant_id), (default, None));
    }
}

// targets は対象の文字列への glob。対象は区切りを持たない文字列なので * は / も含めて何にでも当たる。空の targets は全対象に当たる。
#[test]
fn targets_are_globs_over_the_target() {
    let vocab = vocabulary();
    let scoped = |targets: &[&str]| Grant {
        targets: targets.iter().map(|target| (*target).to_owned()).collect(),
        ..grant("g", Effect::Allow, own_name("sh"), Vec::new(), 1)
    };
    let allowed = |grant: Grant, target: &str| {
        let policy = policy(&vocab, vec![grant]);
        let chain = shell();
        policy
            .evaluate(&policy.tag(&chain), &Target(target.to_owned()), &now())
            .effect
            == Effect::Allow
    };
    assert!(allowed(scoped(&["key:github/*"]), "key:github/token"));
    assert!(!allowed(scoped(&["key:github/*"]), "key:gitlab/token"));
    assert!(allowed(scoped(&["key:*"]), "key:github/token"));
    assert!(!allowed(scoped(&["key:?"]), "key:github/token"));
    assert!(allowed(
        scoped(&["other", "key:github/token"]),
        "key:github/token"
    ));
    assert!(allowed(scoped(&[]), "anything"));
}

// 当たった allow が複数なら、advance で変わらない (uses を持たない) grant を先に採用し、uses を減らさない。
#[test]
fn a_grant_that_does_not_advance_is_adopted_first() {
    let vocab = vocabulary();
    let policy = policy(
        &vocab,
        vec![
            grant("counted", Effect::Allow, own_name("sh"), vec![uses(3)], 1),
            grant("plain", Effect::Allow, own_name("sh"), Vec::new(), 2),
        ],
    );
    let decision = evaluate(&policy, &shell(), &now());
    assert_eq!(decision.grant_id.as_deref(), Some("plain"));
    assert_eq!(decision.updated_grant, None);
}

// 同順なら作成の古い順に採用する (メモリ上の並びによらない)。
#[test]
fn the_oldest_grant_is_adopted_among_equals() {
    let vocab = vocabulary();
    let policy = policy(
        &vocab,
        vec![
            grant("newer", Effect::Allow, own_name("sh"), Vec::new(), 20),
            grant("older", Effect::Allow, own_name("sh"), Vec::new(), 10),
        ],
    );
    assert_eq!(
        evaluate(&policy, &shell(), &now()).grant_id.as_deref(),
        Some("older")
    );
}

// uses は採用された grant の advance で 1 減り、新版が updated_grant に返る (同じ id)。メモリ上の grant は変わらず、add_grant で差し替えると次の評価はそれを見る。
#[test]
fn uses_is_consumed_through_updated_grant() {
    let vocab = vocabulary();
    let mut policy = policy(
        &vocab,
        vec![grant("g", Effect::Allow, own_name("sh"), vec![uses(2)], 1)],
    );
    let chain = shell();
    let first = evaluate(&policy, &chain, &now());
    assert_eq!(first.effect, Effect::Allow);
    let updated = first.updated_grant.expect("uses advanced");
    assert_eq!(updated.id, "g");
    assert_eq!(updated.conditions, vec![uses(1)]);
    assert_eq!(policy.grants().next().unwrap().conditions, vec![uses(2)]);

    policy.add_grant(updated);
    assert_eq!(policy.grants().count(), 1);
    let second = evaluate(&policy, &chain, &now());
    assert_eq!(second.effect, Effect::Allow);
    let updated = second.updated_grant.expect("uses advanced");
    assert_eq!(updated.conditions, vec![uses(0)]);

    policy.add_grant(updated);
    let third = evaluate(&policy, &chain, &now());
    assert_eq!(third.effect, Effect::Deny);
    assert_eq!(third.grant_id, None);
    assert_eq!(third.expired, vec!["g".to_owned()]);
    assert_eq!(
        policy.remove_grant("g").map(|grant| grant.id),
        Some("g".to_owned())
    );
    assert_eq!(policy.grants().count(), 0);
}

/// A state condition that counts the calls to `advance` and changes nothing.
struct CountingAdvance(Arc<AtomicUsize>);

impl Condition for CountingAdvance {
    fn kind(&self) -> ConditionKind {
        ConditionKind::State
    }
    fn observe(&self) -> Result<Option<Value>, ObserveError> {
        Ok(None)
    }
    fn validate_args(&self, _args: Option<&Value>) -> Result<(), String> {
        Ok(())
    }
    fn pin(
        &self,
        _args: Option<&Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<Value>, PinError> {
        Ok(None)
    }
    fn check(
        &self,
        _args: Option<&Value>,
        _pinned: Option<&Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        true
    }
    fn advance(&self, _pinned: Option<&Value>) -> Option<Value> {
        self.0.fetch_add(1, Ordering::SeqCst);
        None
    }
}

// advance は evaluate が採用した grant にだけかける。採用されなかった grant にも explain にもかけない。
#[test]
fn advance_is_called_only_on_the_adopted_grant_by_evaluate() {
    let mut vocab = vocabulary();
    let calls = Arc::new(AtomicUsize::new(0));
    vocab
        .register(Item::condition(
            "app.counted",
            CountingAdvance(Arc::clone(&calls)),
        ))
        .unwrap();
    let counted = || pinned("app.counted", None, None);
    let policy = policy(
        &vocab,
        vec![
            grant("a", Effect::Allow, own_name("sh"), vec![counted()], 1),
            grant("b", Effect::Allow, own_name("sh"), vec![counted()], 2),
        ],
    );
    let chain = shell();
    let tagged = policy.tag(&chain);
    let shown = policy.explain(&tagged, &target(), &now());
    assert_eq!(shown.grant_id.as_deref(), Some("a"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let decided = policy.evaluate(&tagged, &target(), &now());
    assert_eq!(decided.grant_id.as_deref(), Some("a"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// explain は advance しないので updated_grant は常に None。expired は載せる (アプリは削除に使わない)。
#[test]
fn explain_reports_without_advancing() {
    let vocab = vocabulary();
    let policy = policy(
        &vocab,
        vec![
            grant("counted", Effect::Allow, own_name("sh"), vec![uses(2)], 1),
            grant("spent", Effect::Allow, own_name("sh"), vec![uses(0)], 2),
        ],
    );
    let chain = shell();
    let shown = policy.explain(&policy.tag(&chain), &target(), &now());
    assert_eq!(shown.effect, Effect::Allow);
    assert_eq!(shown.grant_id.as_deref(), Some("counted"));
    assert_eq!(shown.updated_grant, None);
    assert_eq!(shown.expired, vec!["spent".to_owned()]);
    assert_eq!(policy.grants().count(), 2);
}

// 寿命型の check が偽の grant は失効が確定して expired に載り、効果の決定に使わない。targets や subject が当たらない grant でも、寿命が尽きていれば載る。
#[test]
fn a_false_lifetime_condition_expires_the_grant() {
    let vocab = vocabulary();
    let past = pinned("until", None, Some(json!("2026-11-08T03:59:59Z")));
    let future = pinned("until", None, Some(json!("2026-11-08T04:00:01Z")));
    let policy = policy(
        &vocab,
        vec![
            grant("past", Effect::Allow, own_name("sh"), vec![past.clone()], 1),
            grant("future", Effect::Allow, own_name("sh"), vec![future], 2),
            grant("elsewhere", Effect::Deny, own_name("bash"), vec![past], 3),
        ],
    );
    let decision = evaluate(&policy, &shell(), &now());
    assert_eq!(decision.grant_id.as_deref(), Some("future"));
    assert_eq!(
        decision.expired,
        vec!["past".to_owned(), "elsewhere".to_owned()]
    );
    assert!(decision.undecidable.is_empty());
}

// 世代の pin 値が今の観測値と違う (再起動・解錠し直し) か、観測値が無い (期間の外) なら失効が確定する。
#[test]
fn an_epoch_that_moved_on_expires_the_grant() {
    let vocab = vocabulary();
    let policy = policy(
        &vocab,
        vec![grant(
            "g",
            Effect::Allow,
            own_name("sh"),
            vec![pinned("app.unlock", None, Some(json!(12)))],
            1,
        )],
    );
    let chain = shell();
    let same = now().with_observed("app.unlock", Ok(Some(json!(12))));
    assert_eq!(evaluate(&policy, &chain, &same).effect, Effect::Allow);
    let moved = now().with_observed("app.unlock", Ok(Some(json!(13))));
    assert_eq!(
        evaluate(&policy, &chain, &moved).expired,
        vec!["g".to_owned()]
    );
    let outside = now().with_observed("app.unlock", Ok(None));
    assert_eq!(
        evaluate(&policy, &chain, &outside).expired,
        vec!["g".to_owned()]
    );
}

// 観測に失敗した condition を使う grant は判定できない: undecidable に載り、許可にも失効にもならない (寿命が尽きた別の条件があっても)。
#[test]
fn a_failed_observation_makes_the_grant_undecidable() {
    let vocab = vocabulary();
    let policy = policy(
        &vocab,
        vec![grant(
            "g",
            Effect::Allow,
            own_name("sh"),
            vec![
                pinned("app.unlock", None, Some(json!(12))),
                pinned("until", None, Some(json!("2026-11-08T03:00:00Z"))),
            ],
            1,
        )],
    );
    let failed = now().with_observed(
        "app.unlock",
        Err(ObserveError {
            reason: "the vault is unreachable".to_owned(),
        }),
    );
    let decision = evaluate(&policy, &shell(), &failed);
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.grant_id, None);
    assert_eq!(decision.undecidable, vec!["g".to_owned()]);
    assert!(decision.expired.is_empty());
}

// 状態型の check が偽の grant はそのときだけ当たらない (失効も判定不能にもしない)。
#[test]
fn a_false_state_condition_only_misses() {
    let vocab = vocabulary();
    // 2026-11-08 は日曜。
    let weekdays = pinned(
        "time.window",
        Some(json!({"days": ["mon", "tue", "wed", "thu", "fri"], "from": "00:00", "to": "24:00"})),
        None,
    );
    let policy = policy(
        &vocab,
        vec![grant("g", Effect::Allow, own_name("sh"), vec![weekdays], 1)],
    );
    let sunday = EvalContext::new(
        chrono::TimeZone::with_ymd_and_hms(&chrono::Local, 2026, 11, 8, 12, 0, 0)
            .single()
            .unwrap()
            .into(),
    );
    let decision = evaluate(&policy, &shell(), &sunday);
    assert_eq!(decision.effect, Effect::Deny);
    assert!(decision.expired.is_empty());
    assert!(decision.undecidable.is_empty());
}

fn truncated(processes: Vec<procline_core::ProcessInfo>) -> ProcessChain {
    ProcessChain::new(
        processes,
        common::BOOT.to_owned(),
        Some(Truncated::AncestorExited),
    )
}

// 途切れた列で、自身への条件は当たったのに祖先の要素が見つからない grant は判定できない (deny でも効果の決定に使わない)。
#[test]
fn a_missing_ancestor_on_a_truncated_chain_is_undecidable() {
    let vocab = vocabulary();
    let policy = policy_with(
        &vocab,
        Vec::new(),
        vec![
            grant("deny", Effect::Deny, under("sh", "claude"), Vec::new(), 1),
            grant("allow", Effect::Allow, own_name("sh"), Vec::new(), 2),
        ],
        Effect::Ask,
    );
    let cut = truncated(vec![named(3, "sh"), named(2, "zsh")]);
    let decision = evaluate(&policy, &cut, &now());
    assert_eq!(decision.undecidable, vec!["deny".to_owned()]);
    assert_eq!(decision.effect, Effect::Allow);
    assert_eq!(decision.grant_id.as_deref(), Some("allow"));
}

// 途切れた列でも、当たった grant は全列でも当たるので効果の決定に使う。自身への条件で外れた grant と、状態型の check が偽の grant は判定不能にしない。
#[test]
fn a_truncated_chain_decides_what_it_can() {
    let vocab = vocabulary();
    let never = pinned(
        "time.window",
        Some(json!({"days": ["mon"], "from": "00:00", "to": "00:01"})),
        None,
    );
    let policy = policy(
        &vocab,
        vec![
            grant("found", Effect::Allow, under("sh", "zsh"), Vec::new(), 1),
            grant(
                "not-self",
                Effect::Deny,
                under("bash", "claude"),
                Vec::new(),
                2,
            ),
            grant(
                "off-hours",
                Effect::Deny,
                under("sh", "claude"),
                vec![never],
                3,
            ),
        ],
    );
    let cut = truncated(vec![named(3, "sh"), named(2, "zsh")]);
    let sunday = EvalContext::new(
        chrono::TimeZone::with_ymd_and_hms(&chrono::Local, 2026, 11, 8, 12, 0, 0)
            .single()
            .unwrap()
            .into(),
    );
    let decision = evaluate(&policy, &cut, &sunday);
    assert_eq!(decision.effect, Effect::Allow);
    assert_eq!(decision.grant_id.as_deref(), Some("found"));
    assert!(
        decision.undecidable.is_empty(),
        "{:?}",
        decision.undecidable
    );
}

fn tag(name: &str, subject: Subject) -> Tag {
    Tag {
        name: name.to_owned(),
        subject: SubjectRef::Inline(Box::new(subject)),
    }
}

// 祖先への条件をタグの定義に持つ grant も、途切れた列で対象のタグが判定できなければ判定不能。タグが別のプロセスでだけ判定できず、対象では外れているなら判定不能にしない。
#[test]
fn a_tag_with_ancestors_is_undecidable_only_where_it_is() {
    let vocab = vocabulary();
    let tags = vec![
        tag("in-claude", under("sh", "claude")),
        tag("zsh-in-claude", under("zsh", "claude")),
    ];
    let tagged_subject = |name: &str| Subject {
        tags: vec![name.to_owned()],
        ..Subject::default()
    };
    let policy = policy_with(
        &vocab,
        tags,
        vec![
            grant(
                "sh",
                Effect::Deny,
                tagged_subject("in-claude"),
                Vec::new(),
                1,
            ),
            grant(
                "zsh",
                Effect::Deny,
                tagged_subject("zsh-in-claude"),
                Vec::new(),
                2,
            ),
        ],
        Effect::Allow,
    );
    let cut = truncated(vec![named(3, "sh"), named(2, "zsh")]);
    let tagged = policy.tag(&cut);
    // zsh-in-claude は zsh (index 1) で判定できないが、対象 (sh) では自身の条件で外れる。
    assert!(tagged.undecidable_tags.contains("zsh-in-claude"));
    let decision = policy.evaluate(&tagged, &target(), &now());
    assert_eq!(decision.undecidable, vec!["sh".to_owned()]);
    assert_eq!(decision.effect, Effect::Allow);
}

// trace は grant ごとに各項目の一致を記録する: 寿命型、targets、match の項目 (対象の index)、ancestors の要素 (当たった祖先の index)、状態型。
#[test]
fn the_trace_records_each_item() {
    let vocab = vocabulary();
    let policy = policy(
        &vocab,
        vec![grant(
            "g",
            Effect::Allow,
            under("sh", "launchd"),
            vec![
                pinned("until", None, Some(json!("2026-11-09T00:00:00Z"))),
                pinned(
                    "time.window",
                    Some(json!({"days": ["mon"], "from": "00:00", "to": "00:01"})),
                    None,
                ),
            ],
            1,
        )],
    );
    let decision = evaluate(&policy, &shell(), &now());
    let entry = |key: &str, process: Option<usize>, matched: bool| TraceEntry {
        grant_id: "g".to_owned(),
        key: key.to_owned(),
        process,
        matched,
    };
    // 2026-11-08T04:00Z はどのタイムゾーンでも月曜 00:00 台ではないので、time.window は偽で当たらない。
    assert_eq!(
        decision.trace.entries,
        [
            entry("until", None, true),
            entry("targets", None, true),
            entry("name", Some(0), true),
            entry("ancestors[0]", Some(2), true),
            entry("time.window", None, false),
        ]
    );
    assert_eq!(decision.effect, Effect::Deny);
}
