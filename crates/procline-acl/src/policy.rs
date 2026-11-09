use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use globset::GlobBuilder;
use procline_core::{ProcessChain, ProcessInfo, Strength};

use crate::builder::RuleBuilder;
use crate::conditions::{age_args, parse_time};
use crate::constraints::{AllowConstraints, ScopeOption};
use crate::context::{EvalContext, Observed};
use crate::matching::{ChainTags, Matching, Placeholders, TagLookup, Truth, tag_chain};
use crate::rule::{ConditionUse, Effect, Grant, PinnedCondition, Rule, Target};
use crate::subject::{AncestorMatch, MatchValue, Subject, SubjectRef, Tag};
use crate::vocabulary::{
    Condition, ConditionKind, MatchTarget, PinError, ResolveError, Vocabulary, resolve_value,
    validate_value, value_matches,
};

/// The key a grant stores an `age` under: `Policy::grant` turns its pin value into the time it ends.
const AGE: &str = "age";
const UNTIL: &str = "until";
/// The consumable condition: a grant with it changes when adopted, so others are adopted first.
const USES: &str = "uses";

/// Numbers the grants made by this process, so two grants made at the same instant get distinct ids.
static GRANT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The verified list of subjects, tags and rules, and the grants evaluation looks at.
#[expect(dead_code, reason = "rules are read once loading is implemented")]
pub struct Policy<'v> {
    vocab: &'v Vocabulary,
    constraints: AllowConstraints,
    /// The effect when no grant is adopted.
    default_effect: Effect,
    subjects: Vec<(String, Subject)>,
    tags: Vec<Tag>,
    rules: Vec<Rule>,
    grants: Vec<Grant>,
}

/// Verifies the signature over serialized bytes (the list, or one grant).
pub trait PolicyVerifier {
    /// `kind` tells what the bytes are, so a signature made for one kind does not verify as the other.
    fn verify(&self, kind: SignedKind, bytes: &[u8], signature: &[u8]) -> bool;
}

/// What signed bytes are: the list or one grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignedKind {
    List,
    Grant,
}

impl<'v> Policy<'v> {
    /// Verifies the signature (as `SignedKind::List`), then parses and checks the list against the vocabulary (unknown items, validity of the values), the names of tags and subjects, and the `allow` rules against `constraints`. `default_effect` is the effect when no grant is adopted.
    ///
    /// A rule becomes a permanent grant when it has no lifetime or consumable condition, no placeholder, and no condition whose pin needs the chain or an observed value (`os.login_session` and the like); any other rule becomes a grant only through approval (`grant`). A placeholder outside the inline subject of a rule is `InvalidValue`.
    ///
    /// After loading the list again, check the stored grants again with `load_grant`: a changed tag definition can lower their strength.
    pub fn load_verified(
        _bytes: &[u8],
        _signature: &[u8],
        _verifier: &dyn PolicyVerifier,
        _vocab: &'v Vocabulary,
        _constraints: AllowConstraints,
        _default_effect: Effect,
    ) -> Result<Self, LoadError> {
        todo!()
    }

    /// A policy assembled from parts that are already parsed and checked, without a signature: for tests and for applications that build the list in code. Nothing is checked here (unknown items, values, tag cycles, constraints); the caller is responsible for what `load_verified` would reject.
    pub fn from_parts(
        vocab: &'v Vocabulary,
        subjects: Vec<(String, Subject)>,
        tags: Vec<Tag>,
        rules: Vec<Rule>,
        grants: Vec<Grant>,
        constraints: AllowConstraints,
        default_effect: Effect,
    ) -> Self {
        Self {
            vocab,
            constraints,
            default_effect,
            subjects,
            tags,
            rules,
            grants,
        }
    }

    /// Starts a rule with the given id and subject; `RuleBuilder::build` checks it against this policy's vocabulary, list and `AllowConstraints`.
    pub fn rule_builder(&self, id: impl Into<String>, subject: SubjectRef) -> RuleBuilder<'_> {
        RuleBuilder::new(self, id.into(), subject)
    }

    /// Verifies the signature of one stored grant (as `SignedKind::Grant`), then parses and checks it against the vocabulary (unknown items, validity of the values), the tag names, and an `allow` grant against the `AllowConstraints`. A `ScopeOption::UntilWithin` is measured from the grant's `created_at`. Does not add it; call `add_grant`.
    pub fn load_grant(
        &self,
        _bytes: &[u8],
        _signature: &[u8],
        _verifier: &dyn PolicyVerifier,
    ) -> Result<Grant, LoadError> {
        todo!()
    }

    /// Adds a grant to the ones evaluation looks at, replacing the grant with the same id. Call it once the application has stored the grant (a new one from `grant`, an `updated_grant`, or one read back by `load_grant`).
    pub fn add_grant(&mut self, grant: Grant) {
        match self.grants.iter_mut().find(|held| held.id == grant.id) {
            Some(held) => *held = grant,
            None => self.grants.push(grant),
        }
    }

    /// Removes the grant with the id, for example one listed in `Decision.expired`. Returns the removed grant.
    pub fn remove_grant(&mut self, id: &str) -> Option<Grant> {
        let position = self.grants.iter().position(|grant| grant.id == id)?;
        Some(self.grants.remove(position))
    }

    /// Every grant evaluation looks at, for cleanup.
    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.iter()
    }

    /// Fills in the placeholders of the rule's subject from `tagged` (via `resolve_subject`), checks an `allow` rule against the `AllowConstraints`, pins the conditions, and returns the resulting grant without adding it. The application signs and stores it, then calls `add_grant`.
    ///
    /// Each condition is pinned with the time and its observed value from `ctx`; an `age` becomes an `until` (its key too, without the arguments). The strength is decided from the target process (`path` is `Strong` or `Medium` by its `PathMeta`), and a `ScopeOption::UntilWithin` is measured from `ctx.now()`, which is also `created_at`.
    ///
    /// The id is `g-<nanoseconds since the epoch>-<sequence>`, from the clock when the grant is made and a counter of this process, and differs from the ids of the grants in the policy.
    pub fn grant(
        &self,
        rule: &Rule,
        tagged: &TaggedChain<'_>,
        ctx: &EvalContext,
    ) -> Result<Grant, GrantError> {
        let subject = self.resolve_subject(&rule.subject, tagged)?;
        let mut conditions = Vec::with_capacity(rule.conditions.len());
        for ConditionUse { key, args } in &rule.conditions {
            let condition = self
                .vocab
                .condition(key)
                .ok_or_else(|| GrantError::UnknownItem { key: key.clone() })?;
            let obs = Observed {
                now: ctx.now(),
                value: ctx.observed(key),
            };
            let pinned = condition
                .pin(args.as_ref(), &obs, tagged.chain)
                .map_err(|error| GrantError::Pin {
                    key: key.clone(),
                    error,
                })?;
            conditions.push(if key == AGE {
                PinnedCondition {
                    key: UNTIL.to_owned(),
                    args: None,
                    pinned,
                }
            } else {
                PinnedCondition {
                    key: key.clone(),
                    args: args.clone(),
                    pinned,
                }
            });
        }
        if rule.effect == Effect::Allow {
            let class = self.own_class(&subject, tagged.chain.processes().first());
            let met = self
                .constraints
                .requirement(class)
                .is_met(|option| grant_meets(&conditions, ctx.now(), option));
            if !met {
                return Err(GrantError::ScopeTooWeak { class });
            }
        }
        Ok(Grant {
            id: self.new_grant_id(),
            rule_id: rule.id.clone(),
            effect: rule.effect,
            subject,
            targets: rule.targets.clone(),
            conditions,
            created_at: ctx.now(),
            created_from: None,
        })
    }

    /// Resolves a name to the subject in the list, then replaces every placeholder with the actual value: those of `match` from the target (the first process of the chain), those of an `ancestors` entry from the ancestor the entry matched. Lets an approval screen show what will be pinned before the user approves.
    ///
    /// An entry of `ancestors` with a placeholder takes the ancestor `Policy::tag`'s matching would give it (nearest first, greedily; from the target itself with `include_self`), its placeholders counting as matching a process that has the values. When no ancestor matches such an entry, its placeholder has no value: `ValueUnavailable` with the key of its first placeholder. Entries without a placeholder are kept as written, matched or not.
    ///
    /// The resolved values are checked with `Matcher::validate` (`InvalidValue`).
    pub fn resolve_subject(
        &self,
        subject: &SubjectRef,
        tagged: &TaggedChain<'_>,
    ) -> Result<Subject, GrantError> {
        let subject = self
            .expand(subject)
            .map_err(|name| GrantError::UnknownSubject { name })?;
        let chain = tagged.chain;
        let r#match = self.resolve_entries(&subject.r#match, chain, Some(0))?;
        let ancestors = if subject
            .ancestors
            .iter()
            .any(|entry| entry.r#match.values().any(MatchValue::has_placeholder))
        {
            let matching = Matching {
                vocab: self.vocab,
                chain,
                placeholders: Placeholders::Fill,
            };
            let mut tags = ChainTags::new(self.vocab, &self.subjects, &self.tags, tagged);
            let start = usize::from(!subject.include_self);
            let (_, hits) = matching.ancestors(&subject.ancestors, start, &mut tags);
            subject
                .ancestors
                .iter()
                .enumerate()
                .map(|(position, entry)| {
                    Ok(AncestorMatch {
                        r#match: self.resolve_entries(
                            &entry.r#match,
                            chain,
                            hits.get(position).copied(),
                        )?,
                        tags: entry.tags.clone(),
                    })
                })
                .collect::<Result<_, GrantError>>()?
        } else {
            for entry in &subject.ancestors {
                self.resolve_entries(&entry.r#match, chain, None)?;
            }
            subject.ancestors.clone()
        };
        Ok(Subject {
            r#match,
            tags: subject.tags.clone(),
            ancestors,
            include_self: subject.include_self,
        })
    }

    /// Attaches the tags each process of the chain carries. The result borrows the vocabulary and the chain, not the policy.
    ///
    /// A tag whose definition requires other tags is decided after them, whatever the order of the definitions. On a truncated chain, a tag with conditions on the ancestors (directly, or through the tags it requires) that does not match a process for want of the missing ancestors goes into `undecidable_tags`; a tag that matches is attached, since it also matches the whole chain.
    pub fn tag<'c>(&self, chain: &'c ProcessChain) -> TaggedChain<'c>
    where
        'v: 'c,
    {
        tag_chain(self.vocab, &self.subjects, &self.tags, chain)
    }

    /// Decides the effect for the target and advances the adopted grant. Memory is not changed: the application stores `updated_grant` and replaces it with `add_grant`, and removes the grants in `expired`.
    ///
    /// The application serializes `evaluate`, storing and `add_grant`: evaluations running at once can consume a `uses` beyond its limit.
    pub fn evaluate(
        &self,
        tagged: &TaggedChain<'_>,
        target: &Target,
        ctx: &EvalContext,
    ) -> Decision {
        self.decide(tagged, target, ctx, Advance::Adopted)
    }

    /// Decides the effect for the target without advancing any grant; `updated_grant` is always `None`.
    ///
    /// `expired` is filled in but does not make expiry final: the application does not remove grants because of it.
    pub fn explain(
        &self,
        tagged: &TaggedChain<'_>,
        target: &Target,
        ctx: &EvalContext,
    ) -> Decision {
        self.decide(tagged, target, ctx, Advance::Never)
    }

    pub(crate) fn vocab(&self) -> &'v Vocabulary {
        self.vocab
    }

    pub(crate) fn constraints(&self) -> &AllowConstraints {
        &self.constraints
    }

    /// A tag of this name is defined in the list.
    pub(crate) fn has_tag(&self, name: &str) -> bool {
        self.tags.iter().any(|tag| tag.name == name)
    }

    /// The subject an inline subject is, or a name refers to; `Err` with the name when the list has no subject of it.
    pub(crate) fn expand<'s>(&'s self, subject: &'s SubjectRef) -> Result<&'s Subject, String> {
        match subject {
            SubjectRef::Inline(subject) => Ok(subject),
            SubjectRef::Named(name) => self
                .subjects
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, subject)| subject)
                .ok_or_else(|| name.clone()),
        }
    }

    /// The strength of a subject (DR-0003): the strongest class among its conditions on the process itself, `match` and the own conditions of the definitions of its `tags` (following tags that require tags). `ancestors` and `include_self` do not count. A subject with no condition on the process itself is `Weak`.
    ///
    /// The alternatives count on the weak side (DR-0010): a list in `match` has the weakest class of its values, and a tag with several definitions the weakest of its definitions.
    ///
    /// `process` is the target when granting and `None` when building or loading; an item whose class depends on the process (`path`) takes the weaker class without it.
    pub(crate) fn own_class(&self, subject: &Subject, process: Option<&ProcessInfo>) -> Strength {
        self.own_class_of(subject, process, &mut BTreeSet::new())
            .unwrap_or(Strength::Weak)
    }

    fn own_class_of(
        &self,
        subject: &Subject,
        process: Option<&ProcessInfo>,
        visiting: &mut BTreeSet<String>,
    ) -> Option<Strength> {
        let items = subject
            .r#match
            .iter()
            .filter_map(|(key, value)| self.vocab.class(key, value, process))
            .max();
        let tags = subject
            .tags
            .iter()
            .filter_map(|name| self.tag_class(name, process, visiting))
            .max();
        items.max(tags)
    }

    /// The strength of a tag: the weakest among its definitions, since any of them attaches it. `None` for a tag without a definition, or when one of its definitions has no own conditions (that definition attaches the tag without pinning down the process itself). A definition that refers back to a tag being decided (a cycle, which loading rejects) adds nothing.
    fn tag_class(
        &self,
        name: &str,
        process: Option<&ProcessInfo>,
        visiting: &mut BTreeSet<String>,
    ) -> Option<Strength> {
        if !visiting.insert(name.to_owned()) {
            return None;
        }
        let class = self
            .tags
            .iter()
            .filter(|tag| tag.name == name)
            .map(|definition| {
                self.expand(&definition.subject)
                    .ok()
                    .and_then(|subject| self.own_class_of(subject, process, visiting))
            })
            .min()
            .flatten();
        visiting.remove(name);
        class
    }

    /// Replaces the placeholders of the entries with the values of the process at `index` and validates the results. Without a process (`None`), a placeholder has no value.
    fn resolve_entries(
        &self,
        entries: &BTreeMap<String, MatchValue>,
        chain: &ProcessChain,
        index: Option<usize>,
    ) -> Result<BTreeMap<String, MatchValue>, GrantError> {
        let process = index.and_then(|index| chain.processes().get(index));
        entries
            .iter()
            .map(|(key, value)| {
                let matcher = self
                    .vocab
                    .matcher(key)
                    .ok_or_else(|| GrantError::UnknownItem { key: key.clone() })?;
                let resolved = match process {
                    Some(process) => resolve_value(
                        matcher,
                        value,
                        MatchTarget {
                            info: process,
                            boot_uuid: &chain.boot_uuid,
                        },
                    )
                    .map_err(|ResolveError::ValueUnavailable { field }| {
                        GrantError::ValueUnavailable {
                            key: key.clone(),
                            field,
                        }
                    })?,
                    None if value.has_placeholder() => {
                        return Err(GrantError::ValueUnavailable {
                            key: key.clone(),
                            field: value.placeholder_field().map(str::to_owned),
                        });
                    }
                    None => value.clone(),
                };
                validate_value(matcher, &resolved).map_err(|reason| GrantError::InvalidValue {
                    key: key.clone(),
                    reason,
                })?;
                Ok((key.clone(), resolved))
            })
            .collect()
    }

    fn new_grant_id(&self) -> String {
        loop {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos());
            let sequence = GRANT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let id = format!("g-{nanos}-{sequence}");
            if self.grants.iter().all(|grant| grant.id != id) {
                return id;
            }
        }
    }

    /// The steps of DR-0008: judge each grant, decide the effect (deny > allow > ask), and advance the adopted grant when asked.
    fn decide(
        &self,
        tagged: &TaggedChain<'_>,
        target: &Target,
        ctx: &EvalContext,
        advance: Advance,
    ) -> Decision {
        let mut tags = ChainTags::new(self.vocab, &self.subjects, &self.tags, tagged);
        let mut trace = Trace::default();
        let mut expired = Vec::new();
        let mut undecidable = Vec::new();
        let mut matched: Vec<&Grant> = Vec::new();
        for grant in &self.grants {
            match self.judge(grant, tagged, target, ctx, &mut tags, &mut trace) {
                Verdict::Expired => expired.push(grant.id.clone()),
                Verdict::Undecidable => undecidable.push(grant.id.clone()),
                Verdict::Unmatched => {}
                Verdict::Matched => matched.push(grant),
            }
        }
        let adopted = [Effect::Deny, Effect::Allow, Effect::Ask]
            .into_iter()
            .find_map(|effect| {
                matched
                    .iter()
                    .copied()
                    .filter(|grant| grant.effect == effect)
                    .min_by_key(|grant| (consumes(grant), grant.created_at))
            });
        let updated_grant = match (adopted, advance) {
            (Some(grant), Advance::Adopted) => self.advanced(grant),
            _ => None,
        };
        Decision {
            effect: adopted.map_or(self.default_effect, |grant| grant.effect),
            grant_id: adopted.map(|grant| grant.id.clone()),
            trace,
            updated_grant,
            expired,
            undecidable,
        }
    }

    /// Judges one grant in the order of DR-0008, recording each checked item in the trace: a failed observation (or an unregistered condition) makes it undecidable; a false lifetime condition expires it; then the targets, the subject at the target, and the state conditions. A subject that is `Unknown` on a truncated chain makes it undecidable unless the targets or a state condition already rule it out.
    fn judge(
        &self,
        grant: &Grant,
        tagged: &TaggedChain<'_>,
        target: &Target,
        ctx: &EvalContext,
        tags: &mut ChainTags<'_>,
        trace: &mut Trace,
    ) -> Verdict {
        let chain = tagged.chain;
        let mut record = |key: String, process: Option<usize>, matched: bool| {
            trace.entries.push(TraceEntry {
                grant_id: grant.id.clone(),
                key,
                process,
                matched,
            });
        };

        let mut conditions = Vec::with_capacity(grant.conditions.len());
        let mut unobservable = false;
        for pinned in &grant.conditions {
            let condition = self.vocab.condition(&pinned.key);
            match (condition, ctx.observed(&pinned.key)) {
                (Some(condition), Ok(value)) => conditions.push((
                    pinned,
                    condition,
                    Observed {
                        now: ctx.now(),
                        value: Ok(value),
                    },
                )),
                _ => {
                    record(pinned.key.clone(), None, false);
                    unobservable = true;
                }
            }
        }
        if unobservable {
            return Verdict::Undecidable;
        }
        let check =
            |(pinned, condition, obs): &(&PinnedCondition, &dyn Condition, Observed<'_>)| {
                condition.check(pinned.args.as_ref(), pinned.pinned.as_ref(), obs, chain)
            };

        let mut alive = true;
        for entry in conditions
            .iter()
            .filter(|(_, condition, _)| condition.kind() == ConditionKind::Lifetime)
        {
            let holds = check(entry);
            record(entry.0.key.clone(), None, holds);
            alive &= holds;
        }
        if !alive {
            return Verdict::Expired;
        }

        let on_target = targets_match(&grant.targets, target);
        record("targets".to_owned(), None, on_target);
        if !on_target {
            return Verdict::Unmatched;
        }

        let matching = Matching {
            vocab: self.vocab,
            chain,
            placeholders: Placeholders::Reject,
        };
        let outcome = matching.subject(&grant.subject, 0, tags);
        if let Some(process) = chain.processes().first() {
            let own = MatchTarget {
                info: process,
                boot_uuid: &chain.boot_uuid,
            };
            for (key, value) in &grant.subject.r#match {
                let hit = self
                    .vocab
                    .matcher(key)
                    .is_some_and(|matcher| value_matches(matcher, own, value));
                record(key.clone(), hit.then_some(0), hit);
            }
        }
        for name in &grant.subject.tags {
            let hit = tags.tag(name, 0) == Truth::True;
            record(format!("tag:{name}"), hit.then_some(0), hit);
        }
        for position in 0..grant.subject.ancestors.len() {
            let hit = outcome.ancestors.get(position).copied();
            record(format!("ancestors[{position}]"), hit, hit.is_some());
        }

        let mut state = true;
        for entry in conditions
            .iter()
            .filter(|(_, condition, _)| condition.kind() == ConditionKind::State)
        {
            let holds = check(entry);
            record(entry.0.key.clone(), None, holds);
            state &= holds;
        }

        match outcome.truth {
            Truth::False => Verdict::Unmatched,
            _ if !state => Verdict::Unmatched,
            Truth::Unknown => Verdict::Undecidable,
            Truth::True => Verdict::Matched,
        }
    }

    /// The grant with each pin value replaced by its condition's `advance`; `None` when no pin value changed.
    fn advanced(&self, grant: &Grant) -> Option<Grant> {
        let mut changed = false;
        let conditions = grant
            .conditions
            .iter()
            .map(|pinned| {
                let next = self
                    .vocab
                    .condition(&pinned.key)
                    .and_then(|condition| condition.advance(pinned.pinned.as_ref()));
                match next {
                    Some(value) => {
                        changed = true;
                        PinnedCondition {
                            pinned: Some(value),
                            ..pinned.clone()
                        }
                    }
                    None => pinned.clone(),
                }
            })
            .collect();
        changed.then(|| Grant {
            conditions,
            ..grant.clone()
        })
    }
}

/// Whether the adopted grant is advanced: `evaluate` does, `explain` never.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Advance {
    Adopted,
    Never,
}

/// What judging one grant concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// A lifetime condition is false.
    Expired,
    /// An observation failed, or the subject could not be decided on a truncated chain.
    Undecidable,
    Unmatched,
    Matched,
}

/// The grant changes when adopted: it has a `uses`.
///
/// Design rationale: DR-0008 adopts first the grants that `advance` leaves unchanged. Calling `advance` to find them out would call it on grants that are not adopted, which the `Condition` contract rules out, and the trait does not say which conditions consume; so the built-in consumable `uses` is what marks a grant as changing. A consumable condition an application adds is not seen here.
fn consumes(grant: &Grant) -> bool {
    grant.conditions.iter().any(|pinned| pinned.key == USES)
}

/// The target matches one of the globs, or the globs are empty. A glob that does not compile matches nothing.
fn targets_match(globs: &[String], target: &Target) -> bool {
    globs.is_empty()
        || globs.iter().any(|glob| {
            target_glob(glob).is_ok_and(|glob| glob.compile_matcher().is_match(&target.0))
        })
}

/// A glob of `targets`. A target is an opaque string of the application's vocabulary, so no character separates components: `*` matches any characters, `/` included (`key:*` matches `key:github/token`).
pub(crate) fn target_glob(glob: &str) -> Result<globset::Glob, globset::Error> {
    GlobBuilder::new(glob).literal_separator(false).build()
}

/// Whether a scope option holds for the conditions of a rule, at building or loading: a condition with the key, or for `UntilWithin` an `age` no longer than it. An `until` is let through here, since its time is measured when granting.
pub(crate) fn rule_meets(conditions: &[ConditionUse], option: &ScopeOption) -> bool {
    match option {
        ScopeOption::Condition(key) => conditions.iter().any(|condition| condition.key == *key),
        ScopeOption::UntilWithin(limit) => {
            conditions
                .iter()
                .any(|condition| match condition.key.as_str() {
                    AGE => {
                        age_args(condition.args.as_ref()).is_ok_and(|duration| duration <= *limit)
                    }
                    UNTIL => true,
                    _ => false,
                })
        }
    }
}

/// Whether a scope option holds for the pinned conditions of a grant made at `from`: a condition with the key, or for `UntilWithin` an `until` no later than `from` plus it.
fn grant_meets(conditions: &[PinnedCondition], from: SystemTime, option: &ScopeOption) -> bool {
    match option {
        ScopeOption::Condition(key) => conditions.iter().any(|condition| condition.key == *key),
        ScopeOption::UntilWithin(limit) => {
            let Some(deadline) = from.checked_add(*limit) else {
                return conditions.iter().any(|condition| condition.key == UNTIL);
            };
            conditions.iter().any(|condition| {
                condition.key == UNTIL
                    && condition
                        .pinned
                        .as_ref()
                        .and_then(|value| parse_time(value).ok())
                        .is_some_and(|until| until <= deadline)
            })
        }
    }
}

/// A chain with the tags of each process, index-aligned with `chain.processes()`.
pub struct TaggedChain<'a> {
    pub vocab: &'a Vocabulary,
    pub chain: &'a ProcessChain,
    pub tags: Vec<BTreeSet<String>>,
    /// The tags whose presence could not be decided because the chain is truncated. An approval screen shows them apart from the tags a process does not carry.
    pub undecidable_tags: BTreeSet<String>,
}

/// Result of an evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub effect: Effect,
    /// The adopted grant; `None` when the default effect of the policy applied.
    pub grant_id: Option<String>,
    /// For display to the user; not for the peer, since it shows which condition failed.
    pub trace: Trace,
    /// The new version of the adopted grant when `advance` changed it. The application signs and stores it before handing out the value.
    pub updated_grant: Option<Grant>,
    /// Ids of the grants whose lifetime condition was false in this evaluation. From `evaluate`, expiry is final and the application removes them; from `explain`, it is not.
    pub expired: Vec<String>,
    /// Ids of the grants that could not be decided in this evaluation, neither allowed nor expired. They did not take part in deciding the effect.
    ///
    /// A grant is listed when the chain is truncated, the grant has conditions on the ancestors (`ancestors`, or a tag whose definition has them, following tags that reference other tags), and it did not match: the conditions of a subject only add requirements, so a grant that matches the truncated chain also matches the whole chain and takes part. A grant is also listed when `observe` of one of its conditions failed.
    pub undecidable: Vec<String>,
}

/// Why each grant matched or did not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trace {
    pub entries: Vec<TraceEntry>,
}

/// One checked item of one grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEntry {
    pub grant_id: String,
    /// What was checked: a condition key (false also when its observation failed), `targets`, a `match` key of the subject (at the target), `tag:<name>` for a tag of the subject (at the target), or `ancestors[<n>]` for the n-th entry of `ancestors`.
    pub key: String,
    /// Index into the chain of the process the item matched, if any.
    pub process: Option<usize>,
    pub matched: bool,
}

/// Loading the list or a grant failed.
#[derive(Debug)]
pub enum LoadError {
    InvalidSignature,
    Parse(serde_json::Error),
    /// A `match` key, scope or condition is not in the vocabulary.
    UnknownItem {
        key: String,
    },
    /// A tag name is not defined in the list.
    UnknownTag {
        name: String,
    },
    /// A rule references a subject name that is not defined in the list.
    UnknownSubject {
        name: String,
    },
    TagCycle {
        tags: Vec<String>,
    },
    /// The value of an item breaks the item's validity rules, or a placeholder is written where none is allowed (a grant, a tag definition, a named subject, a rule that becomes a permanent grant).
    InvalidValue {
        key: String,
        reason: String,
    },
    /// The conditions of an `allow` rule or grant do not satisfy the `AllowConstraints` for the class of its strength.
    ScopeTooWeak {
        rule_id: String,
        class: Strength,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => f.write_str("the signature does not verify"),
            Self::Parse(err) => write!(f, "cannot parse: {err}"),
            Self::UnknownItem { key } => {
                write!(
                    f,
                    "{key:?} is not registered in the vocabulary; register it before loading"
                )
            }
            Self::UnknownTag { name } => {
                write!(
                    f,
                    "no tag named {name:?} in the list; define it in the list"
                )
            }
            Self::UnknownSubject { name } => {
                write!(
                    f,
                    "no subject named {name:?} in the list; define it in the list"
                )
            }
            Self::TagCycle { tags } => {
                write!(f, "tag definitions form a cycle: {}", tags.join(" -> "))
            }
            Self::InvalidValue { key, reason } => {
                write!(f, "the value of {key:?} is not valid: {reason}")
            }
            Self::ScopeTooWeak { rule_id, class } => write!(
                f,
                "the allow rule {rule_id:?} of class {class:?} lacks the scope the constraints require for that class; add a scope they accept"
            ),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(err) => Some(err),
            _ => None,
        }
    }
}

/// Making a grant from a rule failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    UnknownItem {
        key: String,
    },
    /// The subject is referenced by a name that is not in the list.
    UnknownSubject {
        name: String,
    },
    /// The arguments or value of a condition break the item's validity rules.
    InvalidValue {
        key: String,
        reason: String,
    },
    /// A condition could not be pinned.
    Pin {
        key: String,
        error: PinError,
    },
    /// A placeholder of the subject has no actual value to fill in (for example `team_id: true` on an unsigned process); `field` names the field of a structured value.
    ValueUnavailable {
        key: String,
        field: Option<String>,
    },
    /// The `allow` rule does not satisfy the `AllowConstraints` for the class of its strength, decided from the matched process (`path`) or by an `until` beyond the allowed time from now.
    ScopeTooWeak {
        class: Strength,
    },
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownItem { key } => write!(f, "{key:?} is not registered in the vocabulary"),
            Self::UnknownSubject { name } => write!(f, "no subject named {name:?} in the list"),
            Self::InvalidValue { key, reason } => {
                write!(f, "the value of {key:?} is not valid: {reason}")
            }
            Self::Pin { key, error } => write!(f, "cannot pin {key:?}: {error}"),
            Self::ValueUnavailable { key, field: None } => {
                write!(
                    f,
                    "the process has no value for {key:?}; choose another item"
                )
            }
            Self::ValueUnavailable {
                key,
                field: Some(field),
            } => write!(
                f,
                "the process has no value for {field:?} of {key:?}; choose another field"
            ),
            Self::ScopeTooWeak { class } => write!(
                f,
                "an allow rule of class {class:?} lacks the scope the constraints require for that class; add a scope they accept"
            ),
        }
    }
}

impl std::error::Error for GrantError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pin { error, .. } => Some(error),
            _ => None,
        }
    }
}
