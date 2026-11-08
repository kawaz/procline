# Collecting Information About the Connecting Process and ACL Design

## Overview

A set of crates for collecting information about a process and its ancestors, and for defining and evaluating access control (ACL) over that information. pam-passkey's approval UI and cw's ACL matching and after-the-fact allow rules need the same thing, so it is carved out of both into a shared component. The main entry point for collection is the peer of a UNIX domain socket (its audit token), but the center is the process itself, and nothing depends on it being a peer.

**Consumers and how they use it**

- **pam-passkey**: collects the calling process and its ancestors and shows them in the approval UI. It does not use matching.
- **cw**: collects the peer and decides allow, deny, or re-authentication via a per-key ACL. It creates rules after the fact from the approval UI.

**Design pillars**

1. **Identify by something stronger than pid**: the peer is identified by its audit token and ancestors by a per-process unique ID, so pid reuse cannot cause a mix-up.
2. **Display and matching share the same types**: a rule can be built directly from the information shown on screen.
3. **Every item has a strength**: items that a process with the same uid can forge (name, cwd, argv) and items it cannot (code signature) are distinguished by strength when the item is registered, and allows based only on weak conditions are restricted.
4. **Apps can extend the vocabulary**: matcher items, scopes (grant lifetimes), and conditions can be registered by an app in the same form as the built-in vocabulary.

**Scope**

macOS is implemented first, in a form that Linux can be added to later. Linux collection (`SO_PEERCRED`, pidfd, `/proc`) is added the same way on top of the same types.

## Structure

Collection is implemented in per-OS crates, while the types and matching live in an OS-independent core. Apps use only the entry crate procline, which pulls in the per-OS crate for the build target (`[target.'cfg(target_os = "macos")'.dependencies]`). The core itself is not the entry point because the per-OS crates depend on the core's types, so having the core load them would create a cycle. The ACL depends only on the types, so it works unchanged when Linux collection is added. The name comes from process lineage (a process and the sequence of its ancestors) (decision record: [DR-0001](decisions/DR-0001-crate-naming.md)).

| crate | Contents | Depends on |
| --- | --- | --- |
| procline | Entry point. Re-exports the core types and the collect of the build target's OS | core, a per-OS crate (only one, per target) |
| procline-core | Types for collection results, the strength class type (`Strength`), signature trust evaluation, sanitization for display, env policy and redaction, the JSON shape | none (OS-independent) |
| procline-macos | Collection of the peer and ancestors, code signature verification, icons, OS epochs (boot, sleep, screen lock, etc.) | core, Security framework, AppKit |
| procline-acl | Types for rules and grants, evaluation, the vocabulary (matcher items, scopes, conditions) and its registration, rule creation and grant issuance | core |

Apps (cw, pam-passkey) use only what they need. pam-passkey uses only collection; cw uses everything. cw-specific vocabulary (`app.unlock` and so on) is defined on the cw side and registered into procline-acl under `app.` names.

## Collected Information

The collection result is a sequence that starts with the target process (usually the peer) followed by its ancestors up to launchd. Each process has the items below; items that could not be obtained are left empty. The "Strength" column in the tables is the item's class, determined by "can a process with the same uid forge this value?".

### Identifiers

| Item | How to obtain (macOS) | Strength | Notes |
| --- | --- | --- | --- |
| audit token (peer) | `getsockopt(LOCAL_PEERTOKEN)` | Strong | Public API. Contains pid, pidversion, uid, asid |
| unique\_id / parent\_unique\_id | `p_uniqueid` and `p_puniqueid` from `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` | Strong | 64-bit ID unique per launch. Lets ancestors be traced reliably. It is an SPI under `#ifdef PRIVATE`, so if unavailable, fall back to the pair of pid and start time |
| pid, start time | `proc_pidinfo(PROC_PIDTBSDINFO)` | Strong (as a pair) | Together they form an identifier (identification when unique\_id is unavailable) |
| asid (audit session ID) | audit token | Strong | Distinct per login or ssh session. Used for the pinned value of `os.login_session` |

These identifiers are an internal classification of collection: in the rule vocabulary, the audit token, unique\_id, and pid with start time are folded into the single item `process` that identifies the individual process ("matcher"), and the asid is used only internally as the pinned value of `os.login_session` and does not appear in the vocabulary.

### Process Attributes

| Item | How to obtain (macOS) | Strength |
| --- | --- | --- |
| uid, gid, supplementary groups (matched numerically; names are also kept for display, as a list since one ID can have multiple names) | `LOCAL_PEERCRED`, audit token | Strong |
| Code signature (identifier, Team ID, cdhash, signer certificate chain, whether ad-hoc / hardened runtime / platform binary, entitlements, notarization) | `SecCodeCopyGuestWithAttributes` (audit token for the peer, pid for ancestors), `SecCodeCheckValidity`, `SecCodeCopySigningInformation` | Strong (only when verification passes) |
| Executable path | `proc_pidpath` | Medium (if in a location the user cannot rewrite) |
| Executable digest | sha256 of the contents of the file at the executable path | Medium (same as the path. If the file is replaced after exec, it diverges from the running image. On Linux, `/proc/<pid>/exe` points to the running inode, so it is effectively strong) |
| app bundle (bundle ID, version) | Walk up from the executable path to the `.app` and read Info.plist | Strong (a field of `binary`. Paired with `team_id` and `signing_id`) |
| Responsible process | `responsibility_get_pid_responsible_for_pid` (private API) | Medium |
| Process name, argv, cwd, tty | `KERN_PROCARGS2`, `PROC_PIDVNODEPATHINFO`, `kinfo_proc` | Weak |
| env | `KERN_PROCARGS2` (same uid or root only) | Weak (policy below) |
| Icon | `NSWorkspace.icon(forFile:)` scaled down to a 64px PNG | Display only (not used for matching) |

Items that depend on SPIs or private APIs are simply left empty if unavailable; collection as a whole does not stop. On real hardware, they are verified only on the latest macOS in use. If an older version cannot provide them, they just end up empty, which fails safe.

## Signature Trust and Warnings

Icons and names are "what it looks like"; the signature is "who it actually is". The core assigns each process a signature trust level and provides the evaluation used to highlight cases where the two disagree. Both pam-passkey's approval UI and cw's rule creation UI display this evaluation as is.

| Trust level | State | Display |
| --- | --- | --- |
| platform | Apple platform binary | No warning |
| notarized | Developer ID signed and notarized | No warning (signer name and Team ID shown alongside) |
| developer\_id | Developer ID signed but not notarized | ⚠️ Not notarized |
| adhoc | ad-hoc signed (no Team ID) | ⚠️ ad-hoc |
| unsigned / invalid | Unsigned, or verification failed | ⛔ Unsigned / Invalid signature |

Since anyone can imitate icons and names, the UI always shows the signer name and Team ID side by side. There is no mechanism that compares against past approvals and warns "the signer changed". Rules and tags match on the signer, so when the signer changes they naturally stop matching.

Whether something is notarized can be obtained as a boolean via `SecCodeCheckValidity` with the requirement `notarized`. Signature verification is heavy for large apps, and if the ticket is not stapled it may trigger a network lookup, so results are cached keyed by cdhash with an expiry (notarization can be revoked later, so the cache is not indefinite).

**Icons**: taken from the local .app. The App Store API is not used, because it cannot return Developer ID distributed apps and would mean querying an external service about which apps are in use. The cache key is the cdhash (or the bundle ID and version if there is none). Since anyone can imitate icons, the UI always shows them alongside the signature trust level.

## env, Sanitization, and Collection Consistency

### env

env can contain secrets such as tokens, so the caller chooses whether to collect it.

| Policy | What is collected |
| --- | --- |
| `none` (default) | Nothing |
| `allowlist` | Only the listed variables (e.g. `PWD`, `SSH_CONNECTION`, `SUDO_COMMAND`) |
| `all` | Everything, but always passed through the redaction rules |

Redaction lives in the core and is replaceable as two functions: the target predicate `Fn(&str) -> bool` (takes the variable name) and the redaction function `Fn(&str, &str) -> String` (takes the name and value). By default, variables whose name contains `TOKEN`, `SECRET`, `PASS`, `KEY`, `CRED`, `AUTH`, `COOKIE`, `SESSION`, `PRIVATE`, `CERT`, `SALT`, `PWD`, or `OTP` (case-insensitive) have their value redacted, keeping only the name. The word choice follows existing lists such as Rails' `filter_parameters` and Sentry's default redaction. `PWD` also catches the working directory variable, but this is not a problem because the working directory is available as the cwd item. To exclude it, replace the predicate with one that wraps the default and excludes PWD. env is a weak item, so by default it cannot be used as a matching condition.

### Sanitization for Display

Strings whose content the other side can freely choose, such as argv, paths, and env values, go through a core function when shown on screen.

- Control characters and bidi control characters are shown escaped (preventing attacks that reorder the display to make it look like a different command).
- Overly long values are truncated, in a form that makes the truncation visible.
- Matching uses the original value before sanitization.

### Collection Consistency

Collection takes time, and processes may be replaced in the meantime.

1. At the start of collection, record the audit token for the peer and the unique\_id (or pid and start time if unavailable) for ancestors.
2. Verify the signature by referring to the peer via its audit token (referring by pid could hit a different process in the meantime).
3. At the end of collection, confirm that the recorded identifiers have not changed. If they have, discard the result and return an error.
4. An ancestor may have exited partway through. In that case, end the sequence in a form that shows "it was cut off here".

## ACL Rule Shape and Evaluation

The ACL is made of four parts. subject, tag, and rule are static definitions that can be named and reused; they go into the signed list and appear in the same form in configuration files and in the approval UI. A grant is a rule applied to an actual process with the subject's placeholders and its conditions pinned to concrete values, and it is the only thing evaluation looks at.

| Part | Contents | Used for |
| --- | --- | --- |
| subject | A condition on one process. Can hold conditions on ancestors as an ordered list | The target of a rule, tag definitions |
| tag | A named subject. Matching processes get the tag | Display in the approval UI, conditions in other subjects |
| rule | Who (subject), on what (targets), until when and under what circumstances (conditions), with what outcome (effect). The conditions stay symbolic | The source of grants. Pick "the usual allow" in the approval UI and apply it with a single passkey |
| grant | A rule applied to the peer at the moment of approval, with the subject's placeholders pinned to the actual values and each condition pinned to a concrete value | Evaluation |

If no grant matches, the default effect applies (usually `ask`), and deny takes precedence over allow.

### subject

A subject is a condition on one process and does not distinguish between the peer and ancestors. Conditions on ancestors are written in `ancestors` as an ordered list. A value of `true` is a placeholder, filled with that process's actual value when the grant is created ("rule").

```json
{
  "match": { "binary": { "team_id": true, "signing_id": true } },
  "ancestors": [
    { "match": { "binary": { "signing_id": "com.anthropic.claude-code", "team_id": true } } },
    { "tags": ["terminal-app"] }
  ]
}
```

This example is a process that "has claude-code above it, and above that a process tagged `terminal-app`"; the target's own Team ID and signing identifier, and claude-code's Team ID, are fixed to the values at the time of approval.

| Element | Contents |
| --- | --- |
| match | Conditions on the process's own items (shape described under matcher below) |
| tags | Tags attached to the process |
| ancestors | An ordered list of conditions on ancestors. Each entry has `match` and `tags`. The entries match somewhere among the ancestors in this order (others may sit in between). Nearest first |
| include\_self | If `true`, matching of the `ancestors` list may start from the process itself rather than its ancestors (used to define tags for "itself or its descendants"). One per subject, not per entry |

`match` and `tags` are conditions on the process itself, and `ancestors` are conditions on ancestors (the process itself is not included unless `include_self` is given). Writing only `ancestors` means no condition is placed on the process itself.

`ancestors` is matched as a subsequence.

- The list is ordered nearest first relative to the target, the same direction as the collection result sequence `[target, parent, grandparent, …]`.
- Each entry only needs to match somewhere among the ancestors above the one the previous entry matched, in this order, and other ancestors may sit in between. Depth is not stable because of the presence or absence of tmux, direnv, or wrappers, so there is no way of writing that distinguishes "nothing in between".
- Matching is decided greedily from the near side. Entry 1 goes to the nearest matching ancestor, entry 2 to the nearest matching ancestor above that, and so on, so which ancestor's values fill an entry's placeholders is uniquely determined. An entry with no concrete values and no tags (only `{"match": {"binary": {"team_id": true}}}`) matches the nearest ancestor that has that value.
- `ancestors` is not nested inside an entry, and entries are not referenced by name. Deep conditions are confined to tag definitions.

All conditions within a subject are AND. OR is expressed by writing separate rules, so that readers of a rule do not have to follow nested logical expressions.

### tag

A tag is a named subject. On every collection, each process in the sequence is matched against the tag's subject, and matching processes get the tag. Deep conditions are confined to tag (or named subject) definitions, and rules just refer to them by name. In the following example, the tag is attached to the pj1 claude session itself and to every process launched from it.

```json
{
  "tag": "claude-pj1",
  "subject": {
    "ancestors": [
      {
        "match": {
          "binary": { "signing_id": "com.anthropic.claude-code", "team_id": "VWXYZ67890" },
          "cwd": "/Users/alice/src/pj1/**"
        }
      },
      { "match": { "binary": { "team_id": "ABCDE12345" } } }
    ],
    "include_self": true
  }
}
```

With this, a rule's subject only needs `{"tags": ["claude-pj1"]}`. The UI shows the tag on every process that has it. The processes that pass when that tag is authorized are exactly the processes shown with the tag on screen.

- The strength of a tag used as a condition is the same as the strength of the tag definition's subject (the calculation rules are in "Rule Creation and Strength Constraints").
- The `claude-pj1` above has only `ancestors` and no condition on the target itself, so it is Weak, and an `allow` rule using it as the subject needs an epoch scope (the rule example below has `os.session` and `app.unlock`, so it satisfies this).
- Tag definitions go into the same signed list as rules. If a process with the same uid could rewrite a definition, every rule conditioned on that tag would widen.
- A tag definition may refer to another tag; cycles are an error at load time.

### rule

A rule is a static definition. Its conditions are written symbolically and do not yet hold epochs or times. It goes into the same signed list as subjects and tags.

```json
{
  "id": "pj1-claude-usual",
  "effect": "allow",
  "subject": { "tags": ["claude-pj1"] },
  "targets": ["key:k1"],
  "conditions": [{ "os.session": "unlocked" }, "app.unlock", { "age": "1h" }, { "uses": 3 }, "os.not_remote"]
}
```

| Element | Contents |
| --- | --- |
| id | The rule's name. A grant points to it via `rule_id` |
| effect | `allow` (pass without authentication), `deny` (reject), `ask` (require the app's re-authentication) |
| subject | The subject above. May be referenced by name |
| targets | What the rule applies to (key globs, tags). The target vocabulary is decided by the app. Apps that do not need it omit it |
| conditions | A list of condition names (all AND). There are lifetime and state conditions; which one is decided by the vocabulary (below) |

A subject value is either a concrete value or a placeholder (`true`) (decision record: [DR-0007](decisions/DR-0007-pin-placeholders-and-ordered-ancestors.md)).

| Value written in a rule | Meaning | Example |
| --- | --- | --- |
| A string (glob / regular expression / numeric range depending on the item) | A hand-written concrete value. Matched as is | `{"binary": {"team_id": "MYTEAM", "signing_id": "myapp"}}` = always allow from my own app |
| `true` | A placeholder. When the grant is created, the actual value of the process the subject matched is pinned | `{"binary": {"team_id": true, "signing_id": true}}` = fixed to the app that was approved |

- In structured values they can be mixed per field (`{"binary": {"signing_id": "com.googlecode.iterm2", "team_id": true}}` = find it by signing identifier and pin its Team ID).
- `process` is either `true` (pin the individual process) or a concrete composite value.
- Simple items (`cwd`, `uid`, `path` …) also take `true`, and pin the actual value as an exact match.
- This way "the usual allow" needs only one rule, and there is no need to save a separate rule per app.

There are two kinds of conditions, and which kind is decided when it is registered in the vocabulary. A rule just lists names in `conditions`, with no separate place per kind (all AND).

| Kind | When it becomes false | Examples |
| --- | --- | --- |
| lifetime (scope) | It never comes back. The grant expires permanently | `os.session`, `app.unlock`, `age`, `until`, `uses` |
| state | It just does not match while false | `os.not_remote`, `os.console_active`, `time.window` |

`uses` (consumable) is also a lifetime condition. Once it reaches 0, it never comes back. The kind is known by the vocabulary, not by the person writing the rule, so the approval UI and the trace show the kind next to each condition, letting readers see which meaning applies.

A static rule is never used directly in evaluation. Evaluation looks only at grants. Rules in the list that have no lifetime or consumable conditions automatically become permanent grants at load time. This lets a hand-written deny take effect without an "allow" operation. Rules containing lifetime or consumable conditions become grants only through approval.

### grant

A grant is a rule applied to an actual process (the peer at the moment of approval), with the subject's placeholders pinned to the actual values and each condition pinned to a concrete value. When the grant is created, placeholders in the subject's `match` are filled with the values of the target process (the head of the sequence), placeholders in an `ancestors` entry are filled with the values of the ancestor that entry matched, the epoch at that moment is recorded for lifetime conditions, and `age` is converted to a time.

```json
{
  "id": "g-2026-11-08-0001",
  "rule_id": "pj1-claude-usual",
  "effect": "allow",
  "subject": { "tags": ["claude-pj1"] },
  "targets": ["key:k1"],
  "conditions": [
    { "key": "os.session", "args": "unlocked", "pinned": { "boot": "7B1E…", "awake": 12, "unlocked": 3 } },
    { "key": "app.unlock", "pinned": 12 },
    { "key": "until", "pinned": "2026-11-08T13:00:00+09:00" },
    { "key": "uses", "pinned": 3 },
    { "key": "os.not_remote" }
  ],
  "created_at": "2026-11-08T12:00:00+09:00",
  "created_from": "approval-ui"
}
```

- Each element of `conditions` has `key`, the original arguments `args` (if needed), and `pinned` (the pinned value; absent for state conditions). `age` is converted into the pinned value of `until` when the grant is created (`key` also becomes `until`).
- The pinned value of `os.session` holds every epoch at or below its level (for `unlocked`, the three of `boot`, `awake`, and `unlocked`).
- `id` is assigned uniquely by `Policy::grant` (the `g-…` above is illustrative).
- No placeholder remains in the subject (if one does, it is a load error). If there is no value to fill one with (such as `team_id: true` without a signature), the grant cannot be created (`GrantError::ValueUnavailable`).
- A grant is self-contained. It holds its own effect, targets, pinned conditions, and the subject with its placeholders resolved, and holds the id of the original rule as `rule_id` (used for display and cleanup). Even if the rule changes later, existing grants do not change.
- References to tag names and subject names inside the subject are kept as names. Tag definitions live in the signed list and updating them is an intended change, so it is fine for that to reach existing grants too.
- A grant created from a rule without lifetime or consumable conditions has no pinned values and never expires (a permanent grant). A deny is usually of this kind.

A saved rule is itself what gets reapplied. Thanks to placeholders, the same rule can also be used to approve a different app. The approval UI shows the list of rules; picking one and passing a single passkey creates a grant. The flow of choosing conditions on the spot in the approval UI and allowing is two steps: "assemble a rule, then immediately turn it into a grant". Whether to save the rule to the list is the user's choice; if not saved, it becomes a throwaway rule.

### Names and References

subjects, tags, rules, and sets of conditions can all be named, placed in the list, and referenced by name from elsewhere. If a subject created in the approval UI is saved with a name, it can be reused from then on in tag definitions and other rules.

References are written as strings (no wrapper such as `{"ref": "…"}`).

**Reason for the decision**: at every place a reference can appear, what it refers to is fixed to one kind, and there is no place where kinds are mixed.

- Inside `tags`, only tag names.
- In a subject position (a rule's `subject`), a string is a subject name and an object is an inline definition. The type distinguishes them. Entries of `ancestors` are not referenced by name; only an inline `match` and `tags` are written.
- A rule is only referred to by name when applied, and is never referenced from within the list.
- Elements of `conditions`, both plain strings and ones with arguments such as `{"age": "1h"}`, are vocabulary names.

A wrapper would only add writing and reading effort without reducing ambiguity. This is revisited only if the premise breaks (a form is added where names of different kinds can appear in the same place).

### matcher

The keys of `match` are names of items registered in the vocabulary (`Vocabulary`), and the values are conditions on those items. The matching forms are decided per item.

| Form | Applicable items |
| --- | --- |
| Exact match | All |
| glob | Paths, process names, cwd. Paths and cwd are written as absolute paths; `~` is not interpreted |
| Regular expression | Paths, argv |
| Numeric range | uid |

An item or field whose rule value is a placeholder (`true`) becomes an exact match on the actual value in the grant ("rule"). There is no exact match on booleans. JSON `true` is reserved for placeholders; there are currently no boolean items, and when one is needed it is represented as a string.

`process`, `binary`, and `os.session` are structured values and allow exact match only (every field of `binary` is exact match). Signature conditions are considered a match only when signature verification passed. An ad-hoc signature has an empty Team ID, so it never matches a Team ID condition.

**`process`** is the item meaning "this individual process" (decision record: [DR-0005](decisions/DR-0005-process-identity-as-one-item.md)). In a rule it is written as `true` (pin the approved individual process) or a concrete composite value, and in a grant it becomes a composite value that `Policy::grant` gives every identifier obtainable at that moment (e.g. `{"process": {"unique_id": 12345, "pid": 501, "start_time": {"secs": 1762570683, "micros": 123456}}}`). Matching compares by the strongest identifier present on both sides, and at worst checks that the pair of pid and start time matches. The person writing the rule does not care which identifier was compared. Its class is Strong. It can be written both in `match` and inside `ancestors`, so "descendants of the shell in this terminal tab" can be expressed. Once the pinned process exits, it is no longer in the sequence and the grant stops matching. This expresses the lifetime of a process in the sequence. Deleting grants that point to exited processes is the responsibility of cleanup (the app). The UI shows it as the single choice "only this process".

**`binary`** is the item meaning "this process's code". Its value is a composite of any number of fields, `{digest?, team_id?, signing_id?, bundle_id?, cdhash?}` (e.g. `{"binary": {"team_id": "VWXYZ67890", "signing_id": "com.anthropic.claude-code"}}`). Each field value is a string or the placeholder `true`, and in a grant every one is a string. `digest` is `sha256:<hex>`, `cdhash` is hex, and `team_id`, `signing_id`, and `bundle_id` are the values from the signature or Info.plist as is. No field takes a boolean value, so `true` only has the meaning of a placeholder. Matching verifies each field present in the value, and matches only when all of them match (AND). Signature-derived fields (`team_id`, `signing_id`, `bundle_id`, `cdhash`) are considered a match only when signature verification passed. A valid signature is a property of matching the signature-derived fields, so there is no item that represents only that. Its class is the strongest among the fields present in the value: Strong if there is a signature-derived field, Medium if there is only `digest`.

The validity rules for values are closed within `binary`.

- If there is `signing_id`, there is also `team_id`. The signing identifier is a value the developer chooses freely, and even an ad-hoc signature can claim it.
- If there is `bundle_id`, there are also `team_id` and `signing_id`. Anyone can write Info.plist.
- `cdhash` and `digest` may stand alone.
- Empty (no fields at all) is invalid.
- A value with an unknown field is invalid and is an error rather than being silently dropped (the same goes for values of `process`).
- Placeholder fields also count as "present" (`{"signing_id": "com.googlecode.iterm2", "team_id": true}` is valid).

The builder aligns the fields and puts `true` so that they satisfy these rules (if the user picks `signing_id`, `team_id` goes in too), and loading treats values that do not satisfy them as errors.

- `cdhash` is the strongest field, determining the values of all the fields below. This is because the CodeDirectory includes the identifier, the Team ID, and the hash of Info.plist (`CS_SUPPORTSTEAMID`, `teamOffset`, `CSSLOT_INFOSLOT` in the SDK's `cs_blobs.h`).
- `digest` is the hash of the contents of the file at the executable path, placed as a floor for when the signature cannot be relied on. On macOS it reads the path from `proc_pidpath`, so if the file is replaced after exec, it diverges from the running image (its class is Medium, the same as the executable path). On Linux, `/proc/<pid>/exe` points to the running inode, so it is effectively a strong means. In environments and apps where signature-derived fields are available, `digest` is not used, and the UI shows signature-derived fields first.

**`os.session`** is a lifetime condition that selects an OS epoch by level (epochs are defined in "scope: Grant Lifetime"). It is written in a rule's `conditions`, not in a subject's `match`. Its argument is a level, `boot` < `awake` < `unlocked`, and its pinned value is a composite of the epochs at or below the chosen level (e.g. `{"boot": "7B1E…", "awake": 12, "unlocked": 3}`). `check` is true only when all epochs at or below the level match. Its class is Strong (epochs cannot be forged).

### Item Registration

The items usable in conditions (`match` keys, lifetime scope names, state condition names) are registered in the vocabulary in the same form, whether built-in or from an app (decision record: [DR-0006](decisions/DR-0006-structured-values-instead-of-depends.md)).

```
register(key, impl)
```

| Argument | Contents |
| --- | --- |
| key | The item's name (namespaces below) |
| impl | The implementation for each kind of item. For matcher items, the `Matcher` trait (`matches` for matching, and `class` for deciding the class from the value). For lifetime and state items, the condition trait (observe / pin / check / advance, "Condition Implementation") |

Registration goes into procline-acl's `Vocabulary`, where matcher items, scopes, and conditions share the same container. The only checks at registration time are duplicate keys and the namespace.

Namespaces are aligned with the item's category.

- Unprefixed: attributes of the target process itself (`process`, `binary`, `uid`, `gid`, `path`, `cwd`, `argv`, `env`, `name`, `tty`, `responsible` …). A subject is "a condition on that process", so these are unprefixed.
- `os.`: host state and epochs. `time.`: time. `app.`: app-specific (rules in "Vocabulary Added by Apps").
- `until`, `age`, and `uses` are the lifetime of the grant itself, and are unprefixed as built-in basic words.

An item holds the shape and validity of its own values. There are no dependencies across keys; where structure is needed, the value of a single key is given structure (`process`, `binary`, `os.session`).

- The builder (`SubjectBuilder` / `RuleBuilder`, which create rules from the approval UI) does not hold the collection result; from what the user picked (`process`, a combination of `binary` fields, a level of `os.session`), it assembles a subject with the picked fields set to `true`. The actual values are filled in by `Policy::grant`. For `binary`, it aligns the fields so that the validity rules are satisfied; the level of `os.session` is written as the argument of the rule's condition (the epochs are pinned when the grant is created).
- Loading (`Policy::load_verified`, `Policy::load_grant`) has the item's implementation check values and treats invalid values (including unknown fields) as errors. If a placeholder remains in a grant, that too is treated as an invalid value and is an error (`LoadError::InvalidValue`).
- The UI (app side) shows one choice per key, and within it lets the user pick the level of the value or the combination of fields.
- When an app's item is to be used together with a built-in item, they are placed side by side in the same `match` (AND).

### Strength: Class and Depth

An item's strength is expressed on two axes.

| Axis | What it represents | Value |
| --- | --- | --- |
| class | Whether a process with the same uid can forge the value (the strength in the "Collected Information" tables) | Strong / Medium / Weak |
| depth | How narrowly the value constrains | The level of the value, or the number of pinned fields |

- The class is decided by the item from the value (`Matcher::class`). It also accepts rule values containing placeholders, and decides by which fields they are placed in (`{"binary": {"team_id": true}}` is Strong). For most items it is constant regardless of the value, as in the "Collected Information" tables (`process` and uid are Strong; executable path and responsible process are Medium; name, argv, cwd, tty, and env are Weak). `os.session` is Strong.
- The class of `binary` is the strongest among the fields present in the value: Strong if there is a signature-derived field, Medium if there is only `digest`.
- Which item has which class is held by the vocabulary (the implementations of the registered items). Items in the collection result do not carry a strength.
- depth is material for UI ordering and for additional constraints an app may impose. It is not used for rule strength constraints ("Rule Creation and Strength Constraints").

### Evaluation

The target of evaluation is grants.

1. Exclude expired grants (those whose lifetime `check` is false; they become candidates for cleanup).
2. Exclude grants whose targets do not match the target.
3. Match each grant's subject and take the state `check`. The subject's `match` and `tags` are matched against the target itself, and `ancestors` is matched against the sequence as a subsequence, greedily from the near side. If even one `deny` matches, reject.
4. If an `allow` matches, allow. Among the matching allows, exactly one is adopted. Grants that do not change under advance (permanent, or without `uses`) are preferred, and ties go to the oldest by creation. This avoids consuming limited `uses` when another grant would pass anyway.
5. If an `ask` matches, or nothing matches, the default effect.
6. Apply each condition's `advance` only to the adopted grant. If even one returns a new pinned value, create a new grant with the pinned values replaced (grants are immutable).

The evaluation result (`Decision`) returns not only the effect but also the id of the adopted grant and which item each condition matched (the trace). This is used for the UI's "why did this pass, why was I asked". When step 6 changed the grant, the new version is also returned (`updated_grant`).

There are two entry points for evaluation. `evaluate` runs through step 6 and also replaces the in-memory grant with the new version. `explain` is for displaying the trace; it does not apply `advance`, and `updated_grant` is always empty.

- The app signs and persists `updated_grant`, and hands over the value only after the write succeeds. Even if the write fails, memory holds the decremented side, which fails safe.
- A grant whose `uses` reached 0 is treated as expired by step 1 on the next evaluation. Deleting it is the responsibility of cleanup (the app).

## scope: Grant Lifetime

Lifetime conditions (hereafter scopes) pin the epoch at that moment when a grant is created; on every evaluation the current epoch is compared with the pinned value, and if they differ the grant expires permanently. This means "during this particular unlock" rather than "while unlocked", so locking once and unlocking again does not revive the grant.

With this shape, every scope is automatically guaranteed to "never come back once ended", and all an app has to add is a single implementation of the condition trait ("Condition Implementation"). If the current epoch cannot be observed when creating a grant, the grant cannot be created (`PinError::Unobservable`), and if it cannot be observed at evaluation, `check` becomes false and the grant expires. Both fail safe.

Multiple scopes can be listed, and the grant is in effect only while all of them are alive (AND). They are combined like "24 hours, but only until reboot".

### Built-in Vocabulary

| Name | When it ends | How the epoch is obtained (macOS) |
| --- | --- | --- |
| `until` | At the specified time | Clock (judged by time rather than epoch) |
| `age` | Elapsed time since the grant's creation | Converted to the pinned value of `until` when the grant is created |
| `uses` | After being adopted N times | The remaining count is pinned and decreases by 1 each time it is adopted (a counter rather than an epoch) |
| `os.session` | The end of any of the periods at or below the chosen level. `boot` ends on reboot, `awake` on sleep or hibernation, `unlocked` on screen lock (manual, automatic lock when away, screen saver) | `boot` is `kern.bootsessionuuid`, `awake` is the wake count counted via IOKit power notifications, `unlocked` is the count from screen unlock notifications |
| `os.login_session` | Logout, ssh disconnect | The asid in the audit token (of the peer when the grant is created) |
| `os.console_user` | User switch | Count of console user changes |

The level names of `os.session` are names of periods.

- `boot` is the period from startup to reboot, `awake` from waking to sleep or hibernation, and `unlocked` from unlocking to screen lock.
- The pinned value of level N holds every epoch at or below it. `awake` and `unlocked` are not strictly nested (the screen can be locked without sleeping), but choosing `unlocked` also expires on sleep. This is by design.
- observe returns the epochs of the three levels as one composite value `{"boot": uuid, "awake": count, "unlocked": count}`, including only the levels whose period is currently in progress (levels outside their period, i.e. while locked or asleep, are omitted. `boot` is `kern.bootsessionuuid`; the others are the count of period starts). pin copies the fields at or below the argument's level, and `check` is true only when every field in pinned is present in observed and matches. Outside the period the field is missing, so it is false, and when the period starts again the count changes, so the grant expires permanently. This is because if only the unlock count were used as the epoch, the count would not change while locked, and the grant would pass.
- User switching (`os.console_user`) and the login session (`os.login_session`) are not levels of `os.session`; they are independent items. No level covers the period until the display sleeps for power saving. It happens with neither lock nor sleep and also requires handling multiple monitors, so apps that want it add it under `app.`.

Notification-counted epochs (`awake` and `unlocked` of `os.session`, `os.console_user`) can only be counted while the daemon is running. When the daemon restarts, all grants that pinned them expire (since it is unknown what happened in between). For grants reloaded at startup, there is either no observed value for these epochs or pinned and observed do not match, so `check` becomes false; this too is guaranteed automatically ("Storage").

### Vocabulary Added by Apps

App-specific vocabulary goes in the `app.` namespace. The only namespaces are the built-ins (`os.`, `time.`, etc.) and `app.`; apps do not create namespaces freely. Only one app evaluates at a time, so multiple namespaces are unnecessary, and allowing free creation could collide with namespaces added to the crates in the future. For cw, it would be things like:

- `app.unlock`: one opening of the vault. Ends on manual lock or vkey\_ttl expiry.
- `app.passphrase`: one issuance of P. Ends when it becomes Sealed.

Rules with unregistered names are an error at load time (silently ignoring them would produce grants that stay in effect longer than intended).

## Conditions, Rule Creation, and Storage

### Conditions

State conditions are ones whose truth value can change on every evaluation. Unlike scopes, when one becomes false the grant does not expire; it just does not match at that time. As with scopes, apps can add their own under `app.` names in addition to the built-ins.

| Name | True when |
| --- | --- |
| `os.not_remote` | The peer's session is not via ssh (no sshd among the ancestors, the asid belongs to the console) |
| `os.console_active` | The screen is not locked |
| `os.tty` | The peer has the specified tty |
| `time.window` | Within the specified days of the week and time range |

Location conditions such as "while on the home Wi-Fi" are added by apps as needed.

### Condition Implementation: observe / pin / check / advance

Lifetime (scope), consumable (`uses`), and state conditions are expressed with the functions of the same trait. Only `observe` reads outside state (epochs, screen lock state, etc.); `pin` / `check` / `advance` decide their results from the values passed in. A condition touches only its own pinned value and never receives the whole grant.

```rust
/// The observed value of this condition. EvalContext::capture observes it only once at the start of evaluation, and it does not change during evaluation
pub struct Observed<'a> {
    pub now: SystemTime,
    pub value: Option<&'a Value>,   // the result of observe(). None if absent
}

trait Condition {
    fn kind(&self) -> ConditionKind;                                   // Lifetime / State
    /// Observe the current value (an epoch uuid, screen lock state, etc.). EvalContext::capture calls it once for every condition at the start of evaluation. None for conditions with nothing to observe
    fn observe(&self) -> Option<Value>;
    /// Called once when creating a grant. Returns the pinned value. Ok(None) for state conditions. Err(PinError::Unobservable) for a lifetime condition with no observed value. Err(PinError::InvalidArgs) if args are invalid
    fn pin(&self, args: Option<&Value>, obs: &Observed) -> Result<Option<Value>, PinError>;
    /// The check. No side effects
    fn check(&self, args: Option<&Value>, pinned: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> bool;
    /// Called only on the adopted grant. The new version of the pinned value. None means no change
    fn advance(&self, pinned: Option<&Value>) -> Option<Value>;
}

enum PinError { Unobservable, InvalidArgs { reason: String } }
```

| Item | observe | pin | check | advance |
| --- | --- | --- | --- | --- |
| Epochs (`os.session`, `app.unlock` …) | The current epoch | The observed value (Err if absent). For `os.session`, the composite of the epochs at or below the level | pinned == observed. For `os.session`, all epochs at or below the level match | None |
| `until` | None | The time in args | obs.now < pinned | None |
| `age` | None | obs.now + the duration in args (becomes the pinned value of `until`) | obs.now < pinned | None |
| `uses` | None | N from args | pinned > 0 | pinned − 1 |
| State (`os.console_active`, etc.) | The current state (if there is something to observe) | None | Looks at observed / args / chain | None |

- `ConditionKind` has two values, Lifetime / State. Epochs, `until`, `age`, and `uses` are Lifetime; `uses` too never comes back once it reaches 0.
- `EvalContext` holds `now` and "key → the result of `observe()`". The Policy builds `Observed { now, value: ctx.observed(key) }` per condition and passes it (a condition does not know its own key).
- `args` reaches the state `check`, so arguments such as the time range of `time.window` can be used in the check.

### Rule Creation and Strength Constraints

Rules are created by picking items in the approval UI (RuleBuilder). Choosing "by this process's signature" or "by the Team ID of the claude-code above" produces a subject with the picked fields set to placeholders (`true`), and the actual values are filled in when the grant is created. For `binary`, the builder aligns the picked fields into a valid combination, and for `os.session` the level is chosen via the condition's argument ("Item Registration"). `SubjectBuilder` creates the subject and `RuleBuilder` creates the static rule.

- `SubjectBuilder` does not receive the collection result. It assembles a subject containing `true` from a `PinSpec`, and concrete values are written with `exact`. Ancestor entries are assembled with `AncestorBuilder` and added in order with `ancestor`.
- `pin` and `exact` on the same key are merged per field into one value for `binary` (an error if the same field is in both), and for simple items and `process` the second one is an error (`BuildError::Conflict`). `SubjectBuilder::build` / `AncestorBuilder::build` check only the validity of values (the `binary` rules, empty); checking against the vocabulary (unregistered items) is done by `RuleBuilder::build`.
- `RuleBuilder::build()` returns a static `Rule` and does not record epochs. It checks the validity of values and the strength (class) vs scope constraints (below). The constraints are judged by the presence of lifetime or consumable conditions (there are no pinned values yet). The strength class can be judged even with placeholders in place.
- Pinning is done by `Policy::grant(rule, tagged, ctx)`. It fills the subject's placeholders with the actual values from `tagged`, pins each condition, and also puts the grant into the in-memory Policy and returns it (signing and saving are up to the app). A `GrantError` is one of: no value to fill a placeholder (`ValueUnavailable`), `pin` failed (`PinError`: no observed value, invalid arguments), or a value is invalid.
- So that the approval UI can show "what will be pinned" before the passkey, `Policy::resolve_subject(subject, tagged)` gives the subject with its placeholders filled (name references are resolved to the subject in the list before filling. An entry that matched the target itself via `include_self` is filled with the target's own values). `Policy::grant` also uses this internally.

A rule's strength is determined by the subject's conditions on the target process itself (decision record: [DR-0003](decisions/DR-0003-rule-strength-from-own-match.md)).

- The conditions on the target process itself are the `match` and, from the definitions of the tags referenced by `tags`, the conditions on the process itself. The rule's strength is the strongest class among those items.
- `ancestors` conditions are not counted. Even if the ancestors are strongly identified, the target is "any descendant of them", and the target itself is not constrained. The same holds with `include_self` (it only lets matching of the list start from the process itself, and does not constrain the process itself).
- A subject with no condition on the process itself (only `ancestors`) is the weakest and is subject to the same constraints as Weak.
- The strength of a tag used as a condition is that of the tag definition's subject, calculated by the same rules.

The following constraints are checked at build time, and an error is returned if they are not met. Constraints are judged by class; depth is not used. Apps can change the constraint values.

| Rule strength (class) | Scopes allowed for `allow` (default) |
| --- | --- |
| Strong (signature, `process`) | No restriction |
| Medium (executable path, responsible process) | `until` within 7 days, or includes an epoch scope |
| Weak (name, cwd, argv, env) | Includes an epoch scope (`os.login_session`, `app.unlock`, etc.) |

For the constraint check, `uses` is treated the same as an epoch scope (it is a lifetime condition and never comes back once exhausted).

No constraint is placed on `deny`. Even a deny on weak conditions at least works in the safe direction. The UI shows "This condition can also be claimed by other processes of the same user" as soon as a weak condition is picked.

### Storage

There are two storage forms: "one list" and "one grant per file". Both are JSON, and saving and signing are the app's responsibility.

**The list** (subjects, tags, rules): the crate provides an entry point (`Policy::load_verified`) to "receive the bytes of the list and a signature, verify, then load". cw signs the list with the D-side key so that a process with the same uid cannot add allow rules on its own (treated the same as the PasskeyRegistry).

**Grants**: grants are held in memory, and to guard against unintended daemon termination, each one is signed and persisted individually on creation and on update, and all of them are reloaded at startup. The crate has the JSON shape of `Grant` and two entry points.

- `Policy::load_grant(bytes, sig, &verifier)`: receives the bytes and signature of one grant, verifies, then returns a `Grant`. It performs the same checks as the list (unregistered items, validity of values), and returns an error if they fail.
- `Policy::add_grant(grant)`: puts a reloaded grant into the in-memory Policy.


- Since it is one per file, the write for a `uses` update stays light (to be measured with a benchmark at implementation time).
- Among grants reloaded at startup, those that pinned epochs countable only while the daemon is running (`awake` of `os.session`, etc.) have no observed value or pinned and observed do not match, so `check` becomes false and they expire. "Expires on daemon restart" is guaranteed automatically.
- The persistence directory is placed where nothing other than the evaluating daemon (other processes with the same uid) can write. If it were writable, a grant file from before it was used up could be rolled back to restore `uses`. The location is decided by the app.

## API Skeleton

The entry points are collection, evaluation, rule creation, and grant issuance. Vocabulary extension registers matcher items, scopes, and conditions with the same `register`.

```rust
// Collection (procline-macos)
let chain: ProcessChain = collect_peer(&stream, &CollectOptions {
    env: EnvPolicy::Allowlist(&["PWD", "SSH_CONNECTION"]),
    icon: true,
    max_ancestors: 32,
})?;
// chain.processes()[0] is the target, the rest are ancestors. chain.truncated
// p.signature_trust(): Platform / Notarized / DeveloperId / AdHoc / Unsigned / Invalid

// Strength (shared types in procline-core). Which item has which class is held by Vocabulary, not by ProcessInfo items
enum Strength { Strong, Medium, Weak }               // class (decided by the item from the value)
struct Depth(u8);                                    // depth (level of the value / number of pinned fields)

// A value written in a rule (procline-core). In JSON, true is Pin, anything else is a value of T
enum Pinnable<T> { Pin, Value(T) }

// Structured values (procline-core)
struct BinaryPin { digest: Option<Pinnable<String>>, team_id: Option<Pinnable<String>>, signing_id: Option<Pinnable<String>>, bundle_id: Option<Pinnable<String>>, cdhash: Option<Pinnable<CdHash>> }  // in JSON each field is true (placeholder) or a string (cdhash is hex)
// BinaryPin::validate(&self) -> Result<(), BinaryPinError>: validity of the value (signing_id needs team_id, bundle_id needs team_id and signing_id, empty is invalid. Placeholder fields also count as present). Unknown fields are an error at load time
enum SessionLevel { Boot, Awake, Unlocked }          // level of os.session (the value of args. In JSON "boot" / "awake" / "unlocked")

// Vocabulary (procline-acl)
let mut vocab = Vocabulary::builtin();               // matcher items (process / binary / uid / cwd, etc.), os.* scopes and conditions (os.session, etc.), until / age / uses
// matcher items, lifetime, and state items are added with the same register. Duplicate keys and namespace violations are errors
vocab.register(Item::matcher_fn("app.workspace", Strength::Weak, |p, v| ...))?;  // items whose class is constant regardless of the value are registered with a closure, stating the class explicitly
// items whose class changes with the value implement the Matcher trait (matches and class(&self, value) -> Strength) and are registered with Item::matcher(key, impl)
// vocab.class(key, &value) -> Option<Strength>: the class the item decided from the value (None for unregistered keys and condition items)
vocab.register(Item::condition("app.unlock", CwUnlock::new(&vault)))?;           // a value implementing Condition (lifetime)
// state items are also passed to register with the same Item::condition(...). Whether lifetime or state is returned by Condition::kind

trait Condition {
    fn kind(&self) -> ConditionKind;                 // Lifetime / State
    fn observe(&self) -> Option<Value>;              // EvalContext::capture calls it once at the start of evaluation
    fn pin(&self, args: Option<&Value>, obs: &Observed) -> Result<Option<Value>, PinError>;
    fn check(&self, args: Option<&Value>, pinned: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> bool;
    fn advance(&self, pinned: Option<&Value>) -> Option<Value>;
}

// Loading the list (subjects, tags, rules) and reloading saved grants
let mut policy = Policy::load_verified(bytes, sig, &verifier, &vocab)?;  // unregistered items, tag cycles, validity violations of values are errors
let saved = policy.load_grant(grant_bytes, grant_sig, &verifier)?;  // verifies one grant and checks it against the vocabulary (unregistered items, validity violations of values are errors)
policy.add_grant(saved);                             // puts it into the in-memory Policy

// Evaluation
let tagged = policy.tag(&chain);                     // tags attached to each process (also used for display)
let decision = policy.evaluate(&tagged, &Target::key("github/token"), &ctx);  // applies advance to the adopted grant
if let Some(grant) = &decision.updated_grant {
    // sign and persist, then hand over the value after the write succeeds
}
let shown = policy.explain(&tagged, &Target::key("github/token"), &ctx);      // no advance (for displaying the trace)

pub struct Decision {
    pub effect: Effect,
    pub grant_id: Option<String>,        // the adopted grant. None for the default effect
    pub trace: Trace,
    pub updated_grant: Option<Grant>,    // the new version of a grant changed by advance. Always None for explain
}

// The shape of a subject (procline-acl)
struct Subject { r#match: BTreeMap<String, MatchValue>, tags: Vec<String>, ancestors: Vec<AncestorMatch>, include_self: bool }
struct AncestorMatch { r#match: BTreeMap<String, MatchValue>, tags: Vec<String> }  // an entry of ancestors. Holds no nested ancestors
// MatchValue { Pin, Exact(..), Glob(..), Regex(..), Range { .. }, Process(Pinnable<ProcessIdentity>), Binary(BinaryPin) }: Pin is the placeholder for simple items

// Creating a rule from the approval UI (does not receive the collection result; assembles a subject containing true)
let subject = SubjectBuilder::new()
    .pin("binary", PinSpec::Binary(vec![BinaryField::TeamId, BinaryField::SigningId]))  // the key, and which fields of its value to make placeholders
    .ancestor(
        AncestorBuilder::new()
            .exact("binary", MatchValue::Binary(BinaryPin {
                signing_id: Some(Pinnable::Value("com.anthropic.claude-code".into())),
                team_id: None, digest: None, bundle_id: None, cdhash: None,
            }))                                      // find it by signing_id,
            .pin("binary", PinSpec::Binary(vec![BinaryField::TeamId]))  // and pin its Team ID (merged per field with the exact on the same key into one value)
            .build()?,
    )
    .ancestor(AncestorBuilder::new().tag("terminal-app").build()?)  // added in order, nearest first
    .build()?;
// SubjectBuilder: new / pin(key, PinSpec) / exact(key, MatchValue) / tag(name) / ancestor(AncestorMatch) / include_self() / build() -> Result<Subject, BuildError>
// AncestorBuilder: new / pin / exact / tag / build() -> Result<AncestorMatch, BuildError>
// build checks only the validity of values (the binary rules, empty). Unregistered items are checked by RuleBuilder::build
// pin and exact on the same key: binary is merged per field (BuildError::Conflict if the same field is in both), simple items and process give BuildError::Conflict on the second one
// PinSpec { All, Binary(Vec<BinaryField>) }: All is for process and simple items (sets the whole value to true). The level of os.session is specified with RuleBuilder::condition below
// BinaryField { Digest, TeamId, SigningId, BundleId, CdHash }

// Approval UI preview: show "what will be pinned" before the passkey
let preview = policy.resolve_subject(&rule.subject, &tagged)?;  // the Subject with the placeholders of a SubjectRef (a name is fine too) filled with the actual values from tagged. GrantError::ValueUnavailable if a value is missing

let rule = RuleBuilder::new(subject, &vocab)
    .targets(["key:k1"])
    .condition(ConditionUse::with_args("age", json!("1h")))
    .condition(ConditionUse::with_args("os.session", json!("unlocked")))  // stays symbolic. The epoch is pinned when the grant is created
    .allow()
    .build()?;                                       // a static Rule. Checks the validity of values and the strength (class) vs scope constraints

// Applying a rule to create a grant (pins the subject's placeholders and each condition. Saved rules use the same entry point)
let grant = policy.grant(&rule, &tagged, &ctx)?;     // pins, assigns an id, also puts it into the in-memory Policy and returns it
// GrantError: ValueUnavailable { key, field: Option<String> } (no value to fill a placeholder), pin failure (Unobservable / InvalidArgs), validity violation of a value
// the app signs and persists the grant
```

- `EvalContext::capture` takes the current time and the result of each condition's `observe()` only once at the start of evaluation, so the values do not change during evaluation. From it, the Policy builds an `Observed` per condition and passes it to `pin` and `check`. In tests, all of them can be replaced.
- `uses` decreases inside `evaluate` via the `advance` of the adopted grant. The app signs and persists `decision.updated_grant`, and hands over the value only after the write succeeds.

---

Pending decisions are in [docs/QUESTIONS.md](QUESTIONS.md); work items are in `docs/issue/`.
