//! `Policy::tag`: attaching tags to a synthetic chain, the subsequence matching of `ancestors`, tags that require other tags, and `undecidable_tags` on a truncated chain.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{BOOT, chain, named};
use procline_acl::{
    AllowConstraints, AncestorMatch, Effect, Literal, MatchValue, Policy, ScopeRequirement,
    Subject, SubjectRef, Tag, TaggedChain, Vocabulary,
};
use procline_core::{ProcessChain, ProcessInfo, Truncated};

fn constraints() -> AllowConstraints {
    AllowConstraints {
        strong: ScopeRequirement::Unrestricted,
        medium: ScopeRequirement::Unrestricted,
        weak: ScopeRequirement::Unrestricted,
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
        Effect::Deny,
    )
}

fn name_is(name: &str) -> BTreeMap<String, MatchValue> {
    BTreeMap::from([(
        "name".to_owned(),
        MatchValue::Exact(Literal::Text(name.to_owned())),
    )])
}

/// An `ancestors` entry on the process name.
fn ancestor_named(name: &str) -> AncestorMatch {
    AncestorMatch {
        r#match: name_is(name),
        tags: Vec::new(),
    }
}

/// An `ancestors` entry on a tag.
fn ancestor_tagged(tag: &str) -> AncestorMatch {
    AncestorMatch {
        r#match: BTreeMap::new(),
        tags: vec![tag.to_owned()],
    }
}

fn tag(name: &str, subject: Subject) -> Tag {
    Tag {
        name: name.to_owned(),
        subject: SubjectRef::Inline(Box::new(subject)),
    }
}

/// The tags carried by each process, as names.
fn carried<'t>(tagged: &'t TaggedChain<'_>) -> Vec<Vec<&'t str>> {
    tagged
        .tags
        .iter()
        .map(|tags| tags.iter().map(String::as_str).collect())
        .collect()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// `[sh, direnv, claude, zsh, Terminal, launchd]`: a shell started by claude-code through direnv, in a terminal tab. Complete (it reaches launchd).
fn terminal_chain() -> ProcessChain {
    chain(vec![
        named(900, "sh"),
        named(800, "direnv"),
        named(700, "claude"),
        named(600, "zsh"),
        named(500, "Terminal"),
        named(1, "launchd"),
    ])
}

fn truncated(processes: Vec<ProcessInfo>) -> ProcessChain {
    ProcessChain::new(processes, BOOT.to_owned(), Some(Truncated::MaxAncestors))
}

// ---------- match ----------

// match だけのタグは、列の各プロセスを自身の項目で照合し、当たったプロセスすべてに付く。結果は chain の processes と index が揃う。
#[test]
fn tag_on_match_attaches_to_each_matching_process() {
    let vocab = Vocabulary::builtin();
    let shell = Subject {
        r#match: BTreeMap::from([("name".to_owned(), MatchValue::Glob("*sh".to_owned()))]),
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("shell", shell)]);
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    assert_eq!(
        carried(&tagged),
        vec![vec!["shell"], vec![], vec![], vec!["shell"], vec![], vec![]]
    );
    assert!(tagged.undecidable_tags.is_empty());
}

// match の項目と tags はすべて AND。片方だけ満たすプロセスには付かない。
#[test]
fn match_and_ancestors_are_anded() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        r#match: name_is("zsh"),
        ancestors: vec![ancestor_named("Terminal")],
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("terminal-zsh", subject)]);
    let chain = terminal_chain();
    // sh も Terminal の下にいるが zsh ではない。zsh だけに付く。
    assert_eq!(
        carried(&policy.tag(&chain)),
        vec![vec![], vec![], vec![], vec!["terminal-zsh"], vec![], vec![]]
    );
}

// ---------- ancestors: 部分列 ----------
//
// ancestors は祖先への条件の順序付きの列で、近い方から。各要素は前の要素が当たった祖先より上のどこかに当たればよく、間に別の祖先が挟まってよい。direnv やラッパの有無で深さは安定しないので、「間に何も挟まらない」は区別しない。

// claude の上に (zsh を挟んで) Terminal がいるプロセスに付く。sh と claude の間に direnv が挟まっても当たる。
#[test]
fn ancestors_match_as_a_subsequence_with_gaps() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        ancestors: vec![ancestor_named("claude"), ancestor_named("Terminal")],
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("claude-in-terminal", subject)]);
    let chain = terminal_chain();
    // sh と direnv の祖先には claude → Terminal の順で現れる。claude 自身は自分を祖先に数えない (include_self なし) ので付かない。
    assert_eq!(
        carried(&policy.tag(&chain)),
        vec![
            vec!["claude-in-terminal"],
            vec!["claude-in-terminal"],
            vec![],
            vec![],
            vec![],
            vec![]
        ]
    );
}

// 列の順は近い方からで、逆順に書いた要素は当たらない (Terminal の上に claude はいない)。
#[test]
fn ancestors_in_the_wrong_order_do_not_match() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        ancestors: vec![ancestor_named("Terminal"), ancestor_named("claude")],
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("reversed", subject)]);
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    assert!(tagged.tags.iter().all(BTreeSet::is_empty));
    // 列は完全なので、当たらないことは確定している。
    assert!(tagged.undecidable_tags.is_empty());
}

// 同じ祖先を 2 つの要素で使い回さない: 要素 2 は要素 1 が当たった祖先より上から探す。zsh が 1 つしかいない列で [zsh, zsh] は当たらない。
#[test]
fn each_entry_takes_a_distinct_ancestor() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        ancestors: vec![ancestor_named("zsh"), ancestor_named("zsh")],
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("nested-zsh", subject)]);
    let single = terminal_chain();
    assert!(policy.tag(&single).tags.iter().all(BTreeSet::is_empty));
    let nested = chain(vec![named(3, "sh"), named(2, "zsh"), named(1, "zsh")]);
    assert_eq!(
        carried(&policy.tag(&nested)),
        vec![vec!["nested-zsh"], vec![], vec![]]
    );
}

// include_self は ancestors の列の照合を自身から始めてよいことを表す (「自身か子孫」のタグ)。claude 自身にも付く。include_self が無ければ claude 自身には付かない (上の ancestors_match_as_a_subsequence_with_gaps)。
#[test]
fn include_self_lets_the_first_entry_match_the_process_itself() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        ancestors: vec![ancestor_named("claude")],
        include_self: true,
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("claude-or-below", subject)]);
    let chain = terminal_chain();
    assert_eq!(
        carried(&policy.tag(&chain)),
        vec![
            vec!["claude-or-below"],
            vec!["claude-or-below"],
            vec!["claude-or-below"],
            vec![],
            vec![],
            vec![]
        ]
    );
}

// ---------- タグの連鎖 ----------
//
// タグの定義は別のタグを参照してよい (自身の tags にも ancestors の要素の tags にも)。参照先のタグは定義の並び順によらず先に決まる。

// 自身の tags で別のタグを要求する定義。参照する側を先に並べても結果は同じ。
#[test]
fn tag_requiring_a_tag_on_the_process_itself() {
    let vocab = Vocabulary::builtin();
    let under_claude = Subject {
        ancestors: vec![ancestor_named("claude")],
        ..Subject::default()
    };
    let claude_shell = Subject {
        r#match: name_is("sh"),
        tags: vec!["under-claude".to_owned()],
        ..Subject::default()
    };
    let policy = policy(
        &vocab,
        Vec::new(),
        vec![
            tag("claude-shell", claude_shell),
            tag("under-claude", under_claude),
        ],
    );
    let chain = terminal_chain();
    assert_eq!(
        carried(&policy.tag(&chain)),
        vec![
            vec!["claude-shell", "under-claude"],
            vec!["under-claude"],
            vec![],
            vec![],
            vec![],
            vec![]
        ]
    );
}

// ancestors の要素の tags で、祖先に付いたタグを要求する定義 (`{"ancestors": [{"tags": ["terminal-app"]}]}`)。
#[test]
fn tag_requiring_a_tag_on_an_ancestor() {
    let vocab = Vocabulary::builtin();
    let in_terminal = Subject {
        ancestors: vec![ancestor_tagged("terminal-app")],
        ..Subject::default()
    };
    let terminal_app = Subject {
        r#match: name_is("Terminal"),
        ..Subject::default()
    };
    let policy = policy(
        &vocab,
        Vec::new(),
        vec![
            tag("in-terminal", in_terminal),
            tag("terminal-app", terminal_app),
        ],
    );
    let chain = terminal_chain();
    assert_eq!(
        carried(&policy.tag(&chain)),
        vec![
            vec!["in-terminal"],
            vec!["in-terminal"],
            vec!["in-terminal"],
            vec!["in-terminal"],
            vec!["terminal-app"],
            vec![]
        ]
    );
}

// タグの定義の subject は名前付きの subject を参照してよく、一覧の subject に解決して照合する。
#[test]
fn tag_defined_by_a_named_subject() {
    let vocab = Vocabulary::builtin();
    let subjects = vec![(
        "the-terminal".to_owned(),
        Subject {
            r#match: name_is("Terminal"),
            ..Subject::default()
        },
    )];
    let terminal_app = Tag {
        name: "terminal-app".to_owned(),
        subject: SubjectRef::Named("the-terminal".to_owned()),
    };
    let policy = policy(&vocab, subjects, vec![terminal_app]);
    let chain = terminal_chain();
    assert_eq!(
        carried(&policy.tag(&chain)),
        vec![vec![], vec![], vec![], vec![], vec!["terminal-app"], vec![]]
    );
}

// 定義の無いタグ名を要求する subject はどのプロセスにも当たらない (未定義のタグはどのプロセスにも付いていない)。読み込みは参照先の無いタグ名をエラーにするので、ここは防御。
#[test]
fn undefined_tag_is_carried_by_no_process() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        tags: vec!["nowhere".to_owned()],
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("needs-nowhere", subject)]);
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    assert!(tagged.tags.iter().all(BTreeSet::is_empty));
    assert!(tagged.undecidable_tags.is_empty());
}

// 循環するタグの定義は読み込み時に弾かれる前提だが、照合側に届いても再帰が止まり、どちらのタグも付けない。付いているとも付いていないとも言えないので undecidable_tags に入れる (付いていない扱いにすると、そのタグを条件にした deny が黙って効かなくなる)。
#[test]
fn tag_cycle_stops_and_is_undecidable() {
    let vocab = Vocabulary::builtin();
    let a = Subject {
        tags: vec!["b".to_owned()],
        ..Subject::default()
    };
    let b = Subject {
        tags: vec!["a".to_owned()],
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("a", a), tag("b", b)]);
    let chain = terminal_chain();
    let tagged = policy.tag(&chain);
    assert!(tagged.tags.iter().all(BTreeSet::is_empty));
    assert_eq!(tagged.undecidable_tags, set(&["a", "b"]));
}

// ---------- 途切れた列と undecidable_tags ----------
//
// subject の条件はすべて肯定条件で、列を延ばしても「当たった」は「当たらない」に変わらない (単調)。よって途切れた列で当たったタグは全列でも当たるので付ける。祖先への条件を持つ (直接、または要求するタグを通じて) タグが、足りない祖先のせいで当たらなかったときは、有無を判定できないので undecidable_tags に入れ、承認画面が「付いていない」と区別して見せられるようにする。

// 途切れた列 [sh, zsh] (zsh より上は取れていない)。claude は取れた範囲にいないので、claude を祖先に要求するタグは判定できない。
#[test]
fn unmatched_ancestor_tag_on_a_truncated_chain_is_undecidable() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        ancestors: vec![ancestor_named("claude")],
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("under-claude", subject)]);
    let chain = truncated(vec![named(2, "sh"), named(1, "zsh")]);
    let tagged = policy.tag(&chain);
    assert!(tagged.tags.iter().all(BTreeSet::is_empty));
    assert_eq!(tagged.undecidable_tags, set(&["under-claude"]));
    // 同じタグでも完全な列なら、当たらないことは確定している。
    let complete = chain_of(&chain);
    assert!(policy.tag(&complete).undecidable_tags.is_empty());
}

fn chain_of(truncated: &ProcessChain) -> ProcessChain {
    chain(truncated.processes().to_vec())
}

// 途切れた列でも、取れた範囲で当たったタグは付け、判定できなかったとは扱わない。自身の条件 (name が sh) が確かに偽のプロセス (zsh) では、祖先が足りなくても全列で当たることはないので、そこも判定できている。
#[test]
fn matched_or_self_failing_tag_on_a_truncated_chain_is_decided() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        r#match: name_is("sh"),
        ancestors: vec![ancestor_named("zsh")],
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("sh-in-zsh", subject)]);
    let chain = truncated(vec![named(2, "sh"), named(1, "zsh")]);
    let tagged = policy.tag(&chain);
    assert_eq!(carried(&tagged), vec![vec!["sh-in-zsh"], vec![]]);
    assert!(tagged.undecidable_tags.is_empty());
}

// 祖先への条件を持たないタグは、列が途切れていても取れた範囲だけで決まる。当たらなくても判定できなかったことにはならない。
#[test]
fn tag_without_ancestors_is_decided_on_a_truncated_chain() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        r#match: name_is("bash"),
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("bash", subject)]);
    let chain = truncated(vec![named(2, "sh"), named(1, "zsh")]);
    let tagged = policy.tag(&chain);
    assert!(tagged.tags.iter().all(BTreeSet::is_empty));
    assert!(tagged.undecidable_tags.is_empty());
}

// 祖先への条件は推移的に辿る: 自身の条件が ancestors を持たなくても、判定できないタグを要求するタグは判定できない。自身の条件が確かに偽のプロセスでは、要求するタグによらず判定できている。
#[test]
fn undecidable_propagates_through_required_tags() {
    let vocab = Vocabulary::builtin();
    let under_claude = Subject {
        ancestors: vec![ancestor_named("claude")],
        ..Subject::default()
    };
    let claude_shell = Subject {
        r#match: name_is("sh"),
        tags: vec!["under-claude".to_owned()],
        ..Subject::default()
    };
    let in_claude_terminal = Subject {
        ancestors: vec![ancestor_tagged("under-claude")],
        ..Subject::default()
    };
    let policy = policy(
        &vocab,
        Vec::new(),
        vec![
            tag("claude-shell", claude_shell),
            tag("under-claude", under_claude),
            tag("ancestor-under-claude", in_claude_terminal),
        ],
    );
    let chain = truncated(vec![named(2, "sh"), named(1, "zsh")]);
    let tagged = policy.tag(&chain);
    assert!(tagged.tags.iter().all(BTreeSet::is_empty));
    assert_eq!(
        tagged.undecidable_tags,
        set(&["ancestor-under-claude", "claude-shell", "under-claude"])
    );
}

// 祖先の列の照合で、取れた範囲の祖先に当たって条件が満たされたタグは、途切れていても付く (要素がすべて取れた範囲で当たった)。
#[test]
fn ancestors_found_within_a_truncated_chain_match() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        r#match: name_is("sh"),
        ancestors: vec![ancestor_named("direnv"), ancestor_named("claude")],
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("sh-under-claude", subject)]);
    let chain = truncated(vec![named(3, "sh"), named(2, "direnv"), named(1, "claude")]);
    let tagged = policy.tag(&chain);
    assert_eq!(
        carried(&tagged),
        vec![vec!["sh-under-claude"], vec![], vec![]]
    );
    assert!(tagged.undecidable_tags.is_empty());
}

// ---------- 境界 ----------

// 空の列にはどのタグも付かず、tags も空 (index が揃う)。
#[test]
fn empty_chain_has_no_tags() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        ancestors: vec![ancestor_named("claude")],
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("under-claude", subject)]);
    let chain = chain(Vec::new());
    let tagged = policy.tag(&chain);
    assert!(tagged.tags.is_empty());
    assert!(tagged.undecidable_tags.is_empty());
}

// 登録されていない key を match に持つタグはどのプロセスにも付かない (読み込みは未登録の項目をエラーにするので、ここは防御)。
#[test]
fn unregistered_key_never_matches() {
    let vocab = Vocabulary::builtin();
    let subject = Subject {
        r#match: BTreeMap::from([(
            "app.unknown".to_owned(),
            MatchValue::Exact(Literal::Text("x".to_owned())),
        )]),
        ..Subject::default()
    };
    let policy = policy(&vocab, Vec::new(), vec![tag("unknown", subject)]);
    let chain = terminal_chain();
    assert!(policy.tag(&chain).tags.iter().all(BTreeSet::is_empty));
}
