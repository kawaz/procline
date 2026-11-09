//! Matching a subject against one process of a chain, and attaching tags to a chain.

use std::collections::{BTreeMap, BTreeSet};

use procline_core::ProcessChain;

use crate::policy::TaggedChain;
use crate::subject::{AncestorMatch, MatchValue, Subject, SubjectRef, Tag};
use crate::vocabulary::{ItemKind, MatchTarget, Vocabulary};

/// The result of a condition on a possibly truncated chain, in three-valued (Kleene) logic.
///
/// The conditions of a subject only add requirements, so a subject that matches a truncated chain also matches the whole chain (`True` is final). A failure that the missing part of the chain could have turned into a match is `Unknown`, not `False`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Truth {
    False,
    Unknown,
    True,
}

impl Truth {
    /// Kleene AND: `False` wins over `Unknown`, which wins over `True`.
    fn and(self, other: Self) -> Self {
        self.min(other)
    }
}

/// How the values of a subject are matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placeholders {
    /// The values are concrete (a grant, a tag definition, a named subject). A placeholder never matches.
    Reject,
    /// The inline subject of a rule, before a grant fills in its placeholders: a value matches a process when the item can resolve it from that process and the resolved value matches. An entry made only of placeholders matches the nearest process that has the values.
    Fill,
}

/// Whether a process of the chain carries a tag.
pub(crate) trait TagLookup {
    fn tag(&mut self, name: &str, index: usize) -> Truth;
}

/// The outcome of matching a subject at one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubjectMatch {
    pub truth: Truth,
    /// The chain index each `ancestors` entry matched, in the order of the entries; filled only when `truth` is `True`. The placeholders of an entry are filled in from this process.
    pub ancestors: Vec<usize>,
}

impl SubjectMatch {
    fn unmatched(truth: Truth) -> Self {
        Self {
            truth,
            ancestors: Vec::new(),
        }
    }
}

/// What matching a subject needs besides the tags: the vocabulary, the chain, and how to treat placeholders.
#[derive(Clone, Copy)]
pub(crate) struct Matching<'a> {
    pub vocab: &'a Vocabulary,
    pub chain: &'a ProcessChain,
    pub placeholders: Placeholders,
}

impl Matching<'_> {
    /// Matches the subject at the process at `index` of the chain: `match` and `tags` against the process itself, and `ancestors` as a subsequence of the processes above it (from the process itself with `include_self`).
    ///
    /// The entries of `ancestors` are matched greedily from the near side: each entry takes the nearest process that matches it above the process the previous entry took, so the process whose values fill in an entry's placeholders is unique. When an entry finds no process, the result is `Unknown` on a truncated chain (the missing ancestors could match it) and `False` otherwise.
    pub fn subject(
        &self,
        subject: &Subject,
        index: usize,
        tags: &mut dyn TagLookup,
    ) -> SubjectMatch {
        if index >= self.chain.processes().len() {
            return SubjectMatch::unmatched(Truth::False);
        }
        let own = self.own(&subject.r#match, &subject.tags, index, tags);
        if own == Truth::False {
            return SubjectMatch::unmatched(Truth::False);
        }
        let start = if subject.include_self {
            index
        } else {
            index + 1
        };
        let (ancestors, hits) = self.ancestors(&subject.ancestors, start, tags);
        let truth = own.and(ancestors);
        if truth == Truth::True {
            SubjectMatch {
                truth,
                ancestors: hits,
            }
        } else {
            SubjectMatch::unmatched(truth)
        }
    }

    /// `match` (every item) and `tags` (every tag) against one process.
    fn own(
        &self,
        entries: &BTreeMap<String, MatchValue>,
        names: &[String],
        index: usize,
        tags: &mut dyn TagLookup,
    ) -> Truth {
        if !entries
            .iter()
            .all(|(key, value)| self.item(key, value, index))
        {
            return Truth::False;
        }
        let mut truth = Truth::True;
        for name in names {
            truth = truth.and(tags.tag(name, index));
            if truth == Truth::False {
                break;
            }
        }
        truth
    }

    /// The `ancestors` entries as a subsequence of the processes from `start` on. Returns the truth and the chain index each entry matched, in order; when an entry finds no process, the indexes of the entries before it.
    pub fn ancestors(
        &self,
        entries: &[AncestorMatch],
        start: usize,
        tags: &mut dyn TagLookup,
    ) -> (Truth, Vec<usize>) {
        let len = self.chain.processes().len();
        let mut hits = Vec::with_capacity(entries.len());
        let mut next = start;
        let mut saw_unknown = false;
        for entry in entries {
            let mut found = None;
            for candidate in next..len {
                match self.own(&entry.r#match, &entry.tags, candidate, tags) {
                    Truth::True => {
                        found = Some(candidate);
                        break;
                    }
                    Truth::Unknown => saw_unknown = true,
                    Truth::False => {}
                }
            }
            let Some(hit) = found else {
                let truth = if saw_unknown || self.chain.truncated.is_some() {
                    Truth::Unknown
                } else {
                    Truth::False
                };
                return (truth, hits);
            };
            hits.push(hit);
            next = hit + 1;
        }
        (Truth::True, hits)
    }

    /// One `match` entry against one process. A key that is not a registered matcher item never matches; loading rejects such keys.
    fn item(&self, key: &str, value: &MatchValue, index: usize) -> bool {
        let Some(ItemKind::Matcher(matcher)) = self.vocab.get(key).map(|item| item.kind()) else {
            return false;
        };
        let target = MatchTarget {
            info: &self.chain.processes()[index],
            boot_uuid: &self.chain.boot_uuid,
        };
        match self.placeholders {
            Placeholders::Reject => matcher.matches(target, value),
            Placeholders::Fill => matcher
                .resolve(value, target)
                .is_ok_and(|resolved| matcher.matches(target, &resolved)),
        }
    }
}

/// Attaches the tags to each process of the chain.
///
/// A tag may require other tags, on the process itself or on its ancestors, so the tags are computed on demand and memoized per (tag, process). Loading rejects cycles among the definitions; should one reach here, the tag being computed counts as `Unknown` where the cycle closes, which ends the recursion.
///
/// A tag that is `Unknown` at some process (the chain is truncated and the missing ancestors could make it match) goes into `undecidable_tags`.
pub(crate) fn tag_chain<'c>(
    vocab: &'c Vocabulary,
    subjects: &[(String, Subject)],
    definitions: &[Tag],
    chain: &'c ProcessChain,
) -> TaggedChain<'c> {
    let len = chain.processes().len();
    let mut tagger = Tagger::new(vocab, subjects, definitions, chain);
    let names: Vec<&str> = tagger.index.keys().copied().collect();
    let mut tags = vec![BTreeSet::new(); len];
    let mut undecidable_tags = BTreeSet::new();
    for name in names {
        for (process, carried) in tags.iter_mut().enumerate() {
            match tagger.tag(name, process) {
                Truth::True => {
                    carried.insert(name.to_owned());
                }
                Truth::Unknown => {
                    undecidable_tags.insert(name.to_owned());
                }
                Truth::False => {}
            }
        }
    }
    TaggedChain {
        vocab,
        chain,
        tags,
        undecidable_tags,
    }
}

#[derive(Debug, Clone, Copy)]
enum TagState {
    Pending,
    InProgress,
    Done(Truth),
}

struct Tagger<'a> {
    matching: Matching<'a>,
    definitions: &'a [Tag],
    subjects: &'a [(String, Subject)],
    /// Tag name to the position of its definition; the first definition of a name wins.
    index: BTreeMap<&'a str, usize>,
    /// `[definition][process]`.
    states: Vec<Vec<TagState>>,
}

impl<'a> Tagger<'a> {
    fn new(
        vocab: &'a Vocabulary,
        subjects: &'a [(String, Subject)],
        definitions: &'a [Tag],
        chain: &'a ProcessChain,
    ) -> Self {
        let mut index = BTreeMap::new();
        for (position, tag) in definitions.iter().enumerate() {
            index.entry(tag.name.as_str()).or_insert(position);
        }
        Self {
            matching: Matching {
                vocab,
                chain,
                placeholders: Placeholders::Reject,
            },
            definitions,
            subjects,
            index,
            states: vec![vec![TagState::Pending; chain.processes().len()]; definitions.len()],
        }
    }

    /// The subject of the definition at `position`, with a named subject resolved; `None` when the name is not in the list.
    fn subject(&self, position: usize) -> Option<&'a Subject> {
        let definitions: &'a [Tag] = self.definitions;
        match &definitions[position].subject {
            SubjectRef::Inline(subject) => Some(subject),
            SubjectRef::Named(name) => {
                let subjects: &'a [(String, Subject)] = self.subjects;
                subjects
                    .iter()
                    .find(|(candidate, _)| candidate == name)
                    .map(|(_, subject)| subject)
            }
        }
    }
}

impl TagLookup for Tagger<'_> {
    /// A tag that is not defined is carried by no process; loading rejects references to such tags.
    fn tag(&mut self, name: &str, index: usize) -> Truth {
        let Some(&position) = self.index.get(name) else {
            return Truth::False;
        };
        match self.states[position][index] {
            TagState::Done(truth) => return truth,
            TagState::InProgress => return Truth::Unknown,
            TagState::Pending => {}
        }
        self.states[position][index] = TagState::InProgress;
        let truth = match self.subject(position) {
            Some(subject) => {
                let matching = self.matching;
                matching.subject(subject, index, self).truth
            }
            None => Truth::False,
        };
        self.states[position][index] = TagState::Done(truth);
        truth
    }
}

/// The tags of a tagged chain, for matching a grant or a rule against it.
///
/// A tag a process carries is `True` and a tag that is not in `undecidable_tags` is `False`, as `TaggedChain` says. A tag in `undecidable_tags` is decided again at the asked process, since the set does not say at which processes it was undecidable: a tag that is `False` at the target is `False` there even when it was undecidable at another process.
pub(crate) struct ChainTags<'a> {
    tags: &'a [BTreeSet<String>],
    undecidable: &'a BTreeSet<String>,
    tagger: Tagger<'a>,
}

impl<'a> ChainTags<'a> {
    pub fn new(
        vocab: &'a Vocabulary,
        subjects: &'a [(String, Subject)],
        definitions: &'a [Tag],
        tagged: &'a TaggedChain<'_>,
    ) -> Self {
        Self {
            tags: &tagged.tags,
            undecidable: &tagged.undecidable_tags,
            tagger: Tagger::new(vocab, subjects, definitions, tagged.chain),
        }
    }
}

impl TagLookup for ChainTags<'_> {
    fn tag(&mut self, name: &str, index: usize) -> Truth {
        if self
            .tags
            .get(index)
            .is_some_and(|carried| carried.contains(name))
        {
            Truth::True
        } else if self.undecidable.contains(name) {
            self.tagger.tag(name, index)
        } else {
            Truth::False
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use procline_core::{
        CodeSigning, Identity, Pinnable, ProcessChain, ProcessInfo, Signature, SignatureValidity,
        Truncated,
    };

    use super::{Matching, Placeholders, SubjectMatch, TagLookup, Truth};
    use crate::subject::{AncestorMatch, Literal, MatchValue, Subject};
    use crate::vocabulary::Vocabulary;

    /// No process carries any tag.
    struct NoTags;

    impl TagLookup for NoTags {
        fn tag(&mut self, _name: &str, _index: usize) -> Truth {
            Truth::False
        }
    }

    fn process(pid: i32, name: &str) -> ProcessInfo {
        ProcessInfo {
            identity: Identity {
                audit_token: None,
                unique_id: None,
                parent_unique_id: None,
                pid,
                start_time: None,
                asid: None,
            },
            credentials: None,
            code_signing: None,
            path: None,
            path_meta: None,
            digest: None,
            bundle: None,
            responsible: None,
            name: Some(name.to_owned()),
            argv: None,
            cwd: None,
            tty: None,
            env: None,
            icon_png: None,
        }
    }

    fn signed(pid: i32, name: &str, team_id: &str, signing_id: &str) -> ProcessInfo {
        ProcessInfo {
            code_signing: Some(CodeSigning::Signed(Signature {
                validity: SignatureValidity::Valid,
                signing_id: Some(signing_id.to_owned()),
                team_id: Some(team_id.to_owned()),
                bundle_id: None,
                cdhash: None,
                certificates: Vec::new(),
                adhoc: false,
                hardened_runtime: true,
                platform: false,
                entitlements: None,
                notarized: Some(true),
                apple_anchored: Some(true),
            })),
            ..process(pid, name)
        }
    }

    fn chain(processes: Vec<ProcessInfo>, truncated: Option<Truncated>) -> ProcessChain {
        ProcessChain::new(processes, "BOOT".to_owned(), truncated)
    }

    fn named(name: &str) -> AncestorMatch {
        AncestorMatch {
            r#match: BTreeMap::from([(
                "name".to_owned(),
                MatchValue::Exact(Literal::Text(name.to_owned())),
            )]),
            tags: Vec::new(),
        }
    }

    fn binary(team_id: Pinnable<String>, signing_id: Option<&str>) -> AncestorMatch {
        AncestorMatch {
            r#match: BTreeMap::from([(
                "binary".to_owned(),
                MatchValue::Binary(procline_core::BinaryPin {
                    digest: None,
                    team_id: Some(team_id),
                    signing_id: signing_id.map(|id| Pinnable::Value(id.to_owned())),
                    bundle_id: None,
                    cdhash: None,
                }),
            )]),
            tags: Vec::new(),
        }
    }

    fn ancestors(entries: Vec<AncestorMatch>) -> Subject {
        Subject {
            ancestors: entries,
            ..Subject::default()
        }
    }

    fn run(
        vocab: &Vocabulary,
        chain: &ProcessChain,
        placeholders: Placeholders,
        subject: &Subject,
        index: usize,
    ) -> SubjectMatch {
        Matching {
            vocab,
            chain,
            placeholders,
        }
        .subject(subject, index, &mut NoTags)
    }

    // 貪欲に近い側から決める: 当たる祖先が複数あれば、要素は最も近い祖先に当たる。これで要素の placeholder をどの祖先の値で埋めるかが一意に決まる。
    #[test]
    fn entry_takes_the_nearest_matching_ancestor() {
        let vocab = Vocabulary::builtin();
        let chain = chain(
            vec![
                process(4, "sh"),
                process(3, "zsh"),
                process(2, "zsh"),
                process(1, "launchd"),
            ],
            None,
        );
        let outcome = run(
            &vocab,
            &chain,
            Placeholders::Reject,
            &ancestors(vec![named("zsh")]),
            0,
        );
        assert_eq!(outcome.truth, Truth::True);
        assert_eq!(outcome.ancestors, vec![1]);
    }

    // 各要素は前の要素が当たった祖先より上から探すので、要素の並びと祖先の並びが対応する。間に挟まった祖先 (direnv) は読み飛ばす。
    #[test]
    fn later_entries_search_above_the_previous_hit() {
        let vocab = Vocabulary::builtin();
        let chain = chain(
            vec![
                process(5, "sh"),
                process(4, "zsh"),
                process(3, "direnv"),
                process(2, "zsh"),
                process(1, "launchd"),
            ],
            None,
        );
        let subject = ancestors(vec![named("zsh"), named("zsh"), named("launchd")]);
        let outcome = run(&vocab, &chain, Placeholders::Reject, &subject, 0);
        assert_eq!(outcome.truth, Truth::True);
        assert_eq!(outcome.ancestors, vec![1, 3, 4]);
    }

    // include_self なら最初の要素は自身にも当たり、そのときの当たり先は自身の index。
    #[test]
    fn include_self_hit_is_the_process_itself() {
        let vocab = Vocabulary::builtin();
        let chain = chain(vec![process(2, "zsh"), process(1, "zsh")], None);
        let subject = Subject {
            include_self: true,
            ..ancestors(vec![named("zsh")])
        };
        assert_eq!(
            run(&vocab, &chain, Placeholders::Reject, &subject, 0).ancestors,
            vec![0]
        );
        // include_self が無ければ、自身を飛ばして親から探す。
        let without = ancestors(vec![named("zsh")]);
        assert_eq!(
            run(&vocab, &chain, Placeholders::Reject, &without, 0).ancestors,
            vec![1]
        );
    }

    // 具体値の無い要素 ({"binary": {"team_id": true}} だけ) は、grant を作る前の rule の subject では「その値を持つ最も近い祖先」に当たる。間の未署名の祖先は値を持たないので飛ばし、さらに上の署名済みの祖先 (iTerm) には届かない。
    #[test]
    fn placeholder_only_entry_takes_the_nearest_ancestor_with_the_value() {
        let vocab = Vocabulary::builtin();
        let chain = chain(
            vec![
                process(5, "sh"),
                process(4, "zsh"),
                signed(3, "claude", "VWXYZ67890", "com.anthropic.claude-code"),
                signed(2, "iTerm2", "H7V7XYVQ7D", "com.googlecode.iterm2"),
                process(1, "launchd"),
            ],
            None,
        );
        let subject = ancestors(vec![binary(Pinnable::Pin, None)]);
        let outcome = run(&vocab, &chain, Placeholders::Fill, &subject, 0);
        assert_eq!(outcome.truth, Truth::True);
        assert_eq!(outcome.ancestors, vec![2]);
    }

    // 具体値と placeholder を混ぜた要素 (signing_id で見つけ、その Team ID を pin) は、具体値に当たる祖先に当たる。より近い署名済みの祖先 (claude) は signing_id が違うので飛ばす。
    #[test]
    fn mixed_entry_is_found_by_its_concrete_fields() {
        let vocab = Vocabulary::builtin();
        let chain = chain(
            vec![
                process(4, "sh"),
                signed(3, "claude", "VWXYZ67890", "com.anthropic.claude-code"),
                signed(2, "iTerm2", "H7V7XYVQ7D", "com.googlecode.iterm2"),
                process(1, "launchd"),
            ],
            None,
        );
        let subject = ancestors(vec![binary(Pinnable::Pin, Some("com.googlecode.iterm2"))]);
        assert_eq!(
            run(&vocab, &chain, Placeholders::Fill, &subject, 0).ancestors,
            vec![2]
        );
    }

    // grant とタグの定義の照合 (Reject) では placeholder は当たらない。placeholder が残った値で照合すると「どのプロセスでもよい」になるため。
    #[test]
    fn placeholder_never_matches_when_rejected() {
        let vocab = Vocabulary::builtin();
        let chain = chain(
            vec![
                process(2, "sh"),
                signed(1, "claude", "VWXYZ67890", "com.anthropic.claude-code"),
            ],
            None,
        );
        let subject = ancestors(vec![binary(Pinnable::Pin, None)]);
        assert_eq!(
            run(&vocab, &chain, Placeholders::Reject, &subject, 0).truth,
            Truth::False
        );
    }

    // 要素が当たらないとき、完全な列なら当たらないことが確定 (False)、途切れた列なら足りない祖先が当たり得るので Unknown。自身の条件が偽なら、途切れていても False。
    #[test]
    fn missing_ancestor_is_unknown_only_on_a_truncated_chain() {
        let vocab = Vocabulary::builtin();
        let processes = vec![process(2, "sh"), process(1, "zsh")];
        let subject = ancestors(vec![named("claude")]);
        let complete = chain(processes.clone(), None);
        assert_eq!(
            run(&vocab, &complete, Placeholders::Reject, &subject, 0).truth,
            Truth::False
        );
        let cut = chain(processes, Some(Truncated::AncestorExited));
        assert_eq!(
            run(&vocab, &cut, Placeholders::Reject, &subject, 0).truth,
            Truth::Unknown
        );
        let self_fails = Subject {
            r#match: named("bash").r#match,
            ..ancestors(vec![named("claude")])
        };
        assert_eq!(
            run(&vocab, &cut, Placeholders::Reject, &self_fails, 0).truth,
            Truth::False
        );
    }

    // 当たらなかったときは当たり先を返さない (部分的に当たった要素の index を placeholder の解決に使わせない)。
    #[test]
    fn unmatched_subject_has_no_hits() {
        let vocab = Vocabulary::builtin();
        let chain = chain(
            vec![process(3, "sh"), process(2, "zsh"), process(1, "launchd")],
            None,
        );
        let subject = ancestors(vec![named("zsh"), named("claude")]);
        let outcome = run(&vocab, &chain, Placeholders::Reject, &subject, 0);
        assert_eq!(outcome.truth, Truth::False);
        assert!(outcome.ancestors.is_empty());
    }

    // ancestors も match も tags も無い subject は自身への条件も祖先への条件も無いので、どのプロセスにも当たる。列の外の index には当たらない。
    #[test]
    fn empty_subject_matches_and_out_of_range_does_not() {
        let vocab = Vocabulary::builtin();
        let chain = chain(vec![process(1, "launchd")], None);
        assert_eq!(
            run(&vocab, &chain, Placeholders::Reject, &Subject::default(), 0).truth,
            Truth::True
        );
        assert_eq!(
            run(&vocab, &chain, Placeholders::Reject, &Subject::default(), 1).truth,
            Truth::False
        );
    }

    // Kleene の AND: False は Unknown より、Unknown は True より強い。
    #[test]
    fn truth_and_is_kleene() {
        use Truth::{False, True, Unknown};
        assert_eq!(True.and(True), True);
        assert_eq!(True.and(Unknown), Unknown);
        assert_eq!(Unknown.and(False), False);
        assert_eq!(True.and(False), False);
        assert_eq!(Unknown.and(Unknown), Unknown);
    }
}
