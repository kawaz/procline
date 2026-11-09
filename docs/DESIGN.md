# Collecting Information About the Connecting Process and ACL Design

## Overview

A set of crates for collecting information about a process and its ancestors, and for defining and evaluating access control (ACL) over that information. pam-passkey's approval UI and cw's ACL matching and after-the-fact allow rules need the same thing, so it is carved out of both into a shared component. The main entry point for collection is the peer of a UNIX domain socket (its audit token), but the center is the process itself, and nothing depends on it being a peer.

**Consumers and how they use it**

- **pam-passkey**: collects the calling process and its ancestors and shows them in the approval UI. It does not use matching.
- **cw**: collects the peer and decides allow, deny, or re-authentication via a per-key ACL. It creates rules after the fact from the approval UI.

**Design pillars**

1. **Identify by something stronger than pid**: the peer is identified by its audit token and ancestors by a per-process unique ID, so pid reuse cannot cause a mix-up.
2. **Display and matching share the same types**: a rule can be built directly from the information shown on screen.
3. **Every item has a strength**: conditions that identify the approved individual process or code (code signature, identification of the individual process) and conditions that any process with the same uid can satisfy (name, cwd, argv, uid) are distinguished by class when the item is registered, so that the app can constrain allows based only on conditions that identify nothing. The constraint values are given by the app; the crate holds only the checking mechanism.
4. **Apps can extend the vocabulary**: matcher items, scopes (grant lifetimes), and conditions can be registered by an app in the same form as the built-in vocabulary.

**Scope**

macOS is implemented first, in a form that Linux can be added to later. Linux collection (`SO_PEERCRED`, pidfd, `/proc`) is added the same way on top of the same types.

**Threat model assumptions**

The adversary is another process with the same uid. root and impersonation of the evaluating app itself are out of scope (the same as cw's design document).

- A signature only shows the identity of the code; it does not represent what that code executes (a script read by an interpreter, the operations of an AI agent).
- Signature-derived fields are used on the premise that the signature's identity represents that process's code. A signed binary without hardened runtime can be hijacked by a process with the same uid, but identifying a hijacked process is outside the scope of this crate and is not used in deciding the class.
- Protecting the storage of the list and grants and the signing key (a key that processes with the same uid cannot use) is the app's responsibility. cw handles it with a Secure Enclave key.

## Structure

Collection is implemented in per-OS crates, while the types and matching live in an OS-independent core. Apps use only the entry crate procline, which pulls in the per-OS crate for the build target (`[target.'cfg(target_os = "macos")'.dependencies]`). The core itself is not the entry point because the per-OS crates depend on the core's types, so having the core load them would create a cycle. The ACL depends only on the types, so it works unchanged when Linux collection is added. The `os.*` vocabulary is provided by the per-OS crate as `procline_acl::Item`s, so procline-macos also depends on procline-acl (procline-acl depends only on the core, so there is no cycle). The name comes from process lineage (a process and the sequence of its ancestors) (decision record: [DR-0001](decisions/DR-0001-crate-naming.md)).

| crate | Contents | Depends on |
| --- | --- | --- |
| procline | Entry point. Re-exports the core types and the collect of the build target's OS | core, a per-OS crate (only one, per target) |
| procline-core | Types for collection results, the strength class type (`Strength`), signature trust evaluation, sanitization for display, env policy and redaction, the JSON shape | none (OS-independent) |
| procline-macos | Collection of the peer and ancestors, code signature verification, icons, providing the `os.*` vocabulary (`procline_macos::os_items()`) | core, procline-acl, Security framework, AppKit |
| procline-acl | Types for rules and grants, evaluation, the vocabulary (matcher items, scopes, conditions) and its registration, the OS-independent built-in vocabulary, rule creation and grant issuance | core |

Apps (cw, pam-passkey) use only what they need. pam-passkey uses only collection; cw uses everything. cw registers the `os.*` items from `procline_macos::os_items()` with `Vocabulary::register`. cw-specific vocabulary (`app.unlock` and so on) is defined on the cw side and registered into procline-acl under `app.` names.

## Collected Information

The collection result is a sequence that starts with the target process (usually the peer) followed by its ancestors up to launchd. The sequence also holds the boot UUID of the boot it was collected in (`kern.bootsessionuuid`, `ProcessChain.boot_uuid`). Each process has the items below; items that could not be obtained are left empty. The "Strength" column in the tables is the class when the item is used for matching, determined by how much the condition pins down the approved individual process or code ("Strength: Class and Depth").

### Identifiers

| Item | How to obtain (macOS) | Strength | Notes |
| --- | --- | --- | --- |
| audit token (peer) | `getsockopt(LOCAL_PEERTOKEN)` | Strong | Public API. Contains pid, pidversion, uid, asid |
| unique\_id / parent\_unique\_id | `p_uniqueid` and `p_puniqueid` from `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` | Strong | 64-bit ID unique per launch. Lets ancestors be traced reliably. It is an SPI under `#ifdef PRIVATE`, so if unavailable, fall back to the pair of pid and start time |
| pid, start time | `kinfo_proc` from `sysctl(KERN_PROC_PID)` (readable regardless of uid) | Strong (as a pair) | Together they form an identifier (identification when unique\_id is unavailable). The pidversion in the audit token changes on exec, so it can be used to detect a peer that exec'd after connecting |
| asid (audit session ID) | audit token | Strong | Distinct per login or ssh session. It is reused across boots, so it is used for the pinned value of `os.login_session` paired with the boot UUID |

These identifiers are an internal classification of collection: in the rule vocabulary, the audit token, unique\_id, and pid with start time are folded into the single item `process` that identifies the individual process ("matcher"), and the asid is used only internally as the pinned value of `os.login_session` (`{boot_uuid, asid}`) and does not appear in the vocabulary.

### Process Attributes

| Item | How to obtain (macOS) | Strength |
| --- | --- | --- |
| uid, gid, supplementary groups (matched numerically; names are also kept for display, as a list since one ID can have multiple names) | `LOCAL_PEERCRED`, audit token (peer), `kinfo_proc` (ancestors. Supplementary groups are up to 16 entries of `cr_groups`, the first being the effective gid) | Weak |
| Code signature (identifier, Team ID, cdhash, signer certificate chain, whether ad-hoc / hardened runtime / platform binary, entitlements, notarization) | `SecCodeCopyGuestWithAttributes` (audit token for the peer, pid for ancestors), `SecCodeCheckValidity`, `SecCodeCopySigningInformation` | Strong (only when verification passes) |
| Executable path. Its owner (whether root) and whether the user can write to it are also collected (used for deciding the class. "Writable" means the user can write to the file itself or to any directory on the path) | `proc_pidpath` | Strong (a root-owned location the user cannot write to), Medium (a location the user can write to) |
| Executable digest | sha256 of the contents of the file at the executable path | Medium (same as the path. If the file is replaced after exec, it diverges from the running image. On Linux, `/proc/<pid>/exe` points to the running inode, so it is effectively strong) |
| app bundle (bundle ID, version) | Taken from `kSecCodeInfoPList` of `SecCodeCopySigningInformation` (the Info.plist sealed by the signature) and held in `Signature.bundle_id` (used for matching). `ProcessInfo.bundle`, read by walking up from the executable path to the `.app`, is for display | Strong (a field of `binary`. Paired with `team_id` and `signing_id`) |
| Responsible process | `responsibility_get_pid_responsible_for_pid` (private API). Held as the identification of the individual process (`ProcessInfo.responsible: Option<ProcessIdentity>`) rather than a pid | Medium |
| Process name, argv, cwd, tty | `kinfo_proc` (name and tty), `KERN_PROCARGS2` (argv), `PROC_PIDVNODEPATHINFO` (cwd). argv and cwd for the same uid or root only | Weak |
| env | `KERN_PROCARGS2` (same uid or root only. `KERN_PROCARGS2` does not return the env of a platform binary, so it is unavailable and becomes `None` rather than empty) | Display only (it holds only the values after redaction, so it cannot be used for matching. Policy below) |
| Icon | `NSWorkspace.icon(forFile:)` scaled down to a 64px PNG | Display only (not used for matching) |

BSD information (pid, ppid, uid / gid, start time, name, tty) is taken from `kinfo_proc` via `sysctl(KERN_PROC_PID)`. It is readable regardless of uid, so ancestors with a different uid (such as launchd) can be traced too. `proc_pidinfo(PROC_PIDTBSDINFO)` fails with `EPERM` for processes with a different uid, so it is used only to supplement the name with the 32-byte `pbi_name` for the same uid (`p_comm` in `kinfo_proc` is shorter).

Items that depend on SPIs or private APIs are simply left empty if unavailable; collection as a whole does not stop. On real hardware, they are verified only on the latest macOS in use. If an older version cannot provide them, they just end up empty, which fails safe.

## Signature Trust and Warnings

Icons and names are "what it looks like"; the signature is "who it actually is". The core assigns each process a signature trust level and provides the evaluation used to highlight cases where the two disagree. Both pam-passkey's approval UI and cw's rule creation UI display this evaluation as is.

| Trust level | State | Display |
| --- | --- | --- |
| platform | Apple platform binary | No warning |
| app\_store | Distributed through the App Store (Apple signed, no notarization ticket) | No warning |
| notarized | Developer ID signed and notarized | No warning (signer name and Team ID shown alongside) |
| developer\_id | Developer ID signed but not notarized | ⚠️ Not notarized |
| adhoc | ad-hoc signed (no Team ID) | ⚠️ ad-hoc |
| unknown | Validly signed, but the chain cannot be confirmed to end at an Apple root (a self-made or third-party certificate, or it could not be evaluated) | ⚠️ Signer cannot be confirmed |
| unsigned / invalid | Unsigned, or verification failed | ⛔ Unsigned / Invalid signature |

platform, app\_store, notarized, and developer\_id presuppose that the signature's certificate chain ends at an Apple root (`Signature.apple_anchored`, the result of `SecCodeCheckValidity` with the requirement `anchor apple generic`). The platform binary mark and the certificate names can both be written by the signer, so a signature whose chain cannot be confirmed is unknown. The decision order is: unsigned → invalid → ad-hoc → unknown if not anchored at Apple (including when it could not be evaluated) → platform → App Store → Developer ID (notarized if notarized). An ad-hoc signature has no chain, and the OS's platform binaries are not ad-hoc signed, so placing ad-hoc before the anchor check does not produce false warnings for OS binaries. The kind of certificate is decided by the string of the leaf certificate's subject summary (`Apple Mac OS Application Signing` is App Store, `Developer ID Application: …` is Developer ID) (provisional. Other Apple certificates fall back to developer\_id).

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

Redaction lives in the core and is replaceable as two functions (a `Redaction` passed via `CollectOptions.redaction`): the target predicate `Fn(&str) -> bool` (takes the variable name) and the redaction function `Fn(&str, &str) -> String` (takes the name and value). By default, variables whose name contains `TOKEN`, `SECRET`, `PASS`, `KEY`, `CRED`, `AUTH`, `COOKIE`, `SESSION`, `PRIVATE`, `CERT`, `SALT`, `PWD`, or `OTP` (case-insensitive) have their value replaced with `[redacted]`, keeping only the name. The word choice follows existing lists such as Rails' `filter_parameters` and Sentry's default redaction. `PWD` also catches the working directory variable, but this is not a problem because the working directory is available as the cwd item. To exclude it, replace the predicate with one that wraps the default and excludes PWD. The env in the collection result holds only the values after redaction, so it cannot be used for matching (display only).

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
4. An ancestor may have exited partway through. In that case, end the sequence in a form that shows "it was cut off here". For a process reparented to launchd after its parent exited, the ppid becomes 1 but `p_puniqueid` keeps the original parent's value, so the sequence ends there as `ancestor_exited` (linking launchd as the parent would record a parent-child relationship that does not exist).

## ACL Rule Shape and Evaluation

The ACL is made of four parts. subject, tag, and rule are static definitions that can be named and reused; they go into the signed list and appear in the same form in configuration files and in the approval UI. A grant is a rule applied to an actual process with the subject's placeholders and its conditions pinned to concrete values, and it is the only thing evaluation looks at.

| Part | Contents | Used for |
| --- | --- | --- |
| subject | A condition on one process. Can hold conditions on ancestors as an ordered list | The target of a rule, tag definitions |
| tag | A named subject. Matching processes get the tag | Display in the approval UI, conditions in other subjects |
| rule | Who (subject), on what (targets), until when and under what circumstances (conditions), with what outcome (effect). The conditions stay symbolic | The source of grants. Pick "the usual allow" in the approval UI and apply it with a single passkey |
| grant | A rule applied to the peer at the moment of approval, with the subject's placeholders pinned to the actual values and each condition pinned to a concrete value | Evaluation |

If no grant matches, the default effect applies (given by the app as `default_effect` of `Policy::load_verified`), and deny takes precedence over allow.

### subject

A subject is a condition on one process and does not distinguish between the peer and ancestors. Conditions on ancestors are written in `ancestors` as an ordered list. A value of `true` is a placeholder, filled with that process's actual value when the grant is created. Placeholders can be written only in a rule's inline subject ("rule").

```json
{
  "match": { "binary": { "team_id": true, "signing_id": true } },
  "ancestors": [
    { "match": { "binary": { "signing_id": "com.anthropic.claude-code", "team_id": true } } },
    { "tags": ["terminal-app"] }
  ]
}
```

This example is a process that "has claude-code above it, and above that a process tagged `terminal-app`"; the target's own Team ID and signing identifier, and claude-code's Team ID, are fixed to the values at the time of approval. The terminal app does not appear among the ancestors of a shell inside tmux. The tmux server daemonizes and becomes a child of launchd, so the lineage is cut at the tmux server.

| Element | Contents |
| --- | --- |
| match | Conditions on the process's own items (shape described under matcher below) |
| tags | Tags attached to the process |
| ancestors | An ordered list of conditions on ancestors. Each entry has `match` and `tags`. The entries match somewhere among the ancestors in this order (others may sit in between). Nearest first |
| include\_self | If `true`, matching of the `ancestors` list may start from the process itself rather than its ancestors (used to define tags for "itself or its descendants"). One per subject, not per entry |

`match` and `tags` are conditions on the process itself, and `ancestors` are conditions on ancestors (the process itself is not included unless `include_self` is given). Writing only `ancestors` means no condition is placed on the process itself.

`ancestors` is matched as a subsequence.

- The list is ordered nearest first relative to the target, the same direction as the collection result sequence `[target, parent, grandparent, …]`.
- Each entry only needs to match somewhere among the ancestors above the one the previous entry matched, in this order, and other ancestors may sit in between. Depth is not stable because of the presence or absence of direnv or wrappers, so there is no way of writing that distinguishes "nothing in between".
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
          "cwd": { "glob": "/Users/alice/src/pj1/**" }
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
- The `claude-pj1` above has only `ancestors` and no condition on the target itself, so it is Weak. Which scopes an `allow` of a Weak rule requires is decided by the app's constraint table (with the example table in "Rule Creation and Strength Constraints", an epoch scope is needed, and the rule example below has `os.session` and `app.unlock`, so it satisfies this).
- Placeholders (`true`) cannot be written in a tag definition ("rule").
- Tag definitions go into the same signed list as rules. If a process with the same uid could rewrite a definition, every rule conditioned on that tag would widen.
- A tag definition may refer to another tag; cycles are an error at load time.
- When the sequence is cut off, whether a tag with conditions on ancestors is attached may not be decidable. Such tags go into `TaggedChain.undecidable_tags`, and the approval UI shows them distinguished from "not attached" ("Evaluation").

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
| targets | The list of what the rule applies to. Each element is a glob over the target (the string of a `Target`). The target vocabulary is decided by the app. An empty `targets` matches every target |
| conditions | A list of condition names (all AND). There are lifetime and state conditions; which one is decided by the vocabulary (below) |

A subject value is either a concrete value or a placeholder (`true`) (decision record: [DR-0007](decisions/DR-0007-pin-placeholders-and-ordered-ancestors.md)).

| Value written in a rule | Meaning | Example |
| --- | --- | --- |
| A concrete value (a string or a number. A glob / regular expression / numeric range is `{"glob": …}` / `{"regex": …}` / `{"min": …, "max": …}`) | A hand-written concrete value. Matched as is | `{"binary": {"team_id": "MYTEAM", "signing_id": "myapp"}}` = always allow from my own app |
| `true` | A placeholder. When the grant is created, the actual value of the process the subject matched is pinned | `{"binary": {"team_id": true, "signing_id": true}}` = fixed to the app that was approved |

- In structured values they can be mixed per field (`{"binary": {"signing_id": "com.googlecode.iterm2", "team_id": true}}` = find it by signing identifier and pin its Team ID).
- `process` is either `true` (pin the individual process) or a concrete composite value.
- Simple items (`cwd`, `uid`, `path` …) also take `true`, and pin the actual value as an exact match.
- This way "the usual allow" needs only one rule, and there is no need to save a separate rule per app.

Placeholders can be written only in a rule's inline subject (decision record: [DR-0008](decisions/DR-0008-evaluation-semantics.md)). If a tag definition or a named subject contains `true`, loading is an error (`LoadError::InvalidValue`). A rule containing placeholders does not automatically become a grant at load time; it becomes a grant only through approval (below).

There are two kinds of conditions, and which kind is decided when it is registered in the vocabulary. A rule just lists names in `conditions`, with no separate place per kind (all AND).

| Kind | When it becomes false | Examples |
| --- | --- | --- |
| lifetime (scope) | It never comes back. The expiry is settled in that evaluation ("Evaluation") | `os.session`, `app.unlock`, `age`, `until`, `uses` |
| state | It just does not match while false | `os.not_remote`, `os.console_active`, `time.window` |

`uses` (consumable) is also a lifetime condition. Once it reaches 0, it never comes back. The kind is known by the vocabulary, not by the person writing the rule, so the approval UI and the trace show the kind next to each condition, letting readers see which meaning applies.

A static rule is never used directly in evaluation. Evaluation looks only at grants. Rules in the list that have no lifetime or consumable conditions, contain no placeholders, and contain no conditions whose pin needs the chain or an observed value (`os.login_session`, etc.) automatically become permanent grants at load time. This lets a hand-written deny take effect without an "allow" operation. Other rules become grants only through approval.

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
    { "key": "os.session", "args": "unlocked", "pinned": { "boot": "7B1E…", "awake": "…", "unlocked": "…" } },
    { "key": "app.unlock", "pinned": 12 },
    { "key": "until", "pinned": "2026-11-08T13:00:00+09:00" },
    { "key": "uses", "pinned": 3 },
    { "key": "os.not_remote" }
  ],
  "created_at": "2026-11-08T12:00:00+09:00",
  "created_from": "approval-ui"
}
```

- Each element of `conditions` has `key`, the original arguments `args` (if needed), and `pinned` (the pinned value; state conditions normally have none, and only those that fix a value depending on the peer, such as `os.login_session`, have one). `age` is converted into the pinned value of `until` when the grant is created (`key` also becomes `until`).
- The pinned value of `os.session` holds every epoch at or below its level (for `unlocked`, the three of `boot`, `awake`, and `unlocked`. `awake` is the wake time, `unlocked` is the unlock time).
- `id` is assigned uniquely by `Policy::grant` (the `g-…` above is illustrative).
- No placeholder remains in the subject (if one does, it is a load error). If there is no value to fill one with (such as `team_id: true` without a signature), the grant cannot be created (`GrantError::ValueUnavailable`).
- A grant is self-contained. It holds its own effect, targets, pinned conditions, and the subject with its placeholders resolved, and holds the id of the original rule as `rule_id` (used for display and cleanup). Even if the rule changes later, existing grants do not change.
- A grant's subject is an inline subject. If the rule's subject refers to one by name, it is expanded when the grant is created. Only references to tag names inside the subject are kept as names. Tag definitions live in the signed list and updating them is an intended change, so it is fine for that to reach existing grants too.
- A grant created from a rule without lifetime or consumable conditions never expires (a permanent grant). A deny is usually of this kind.
- `Policy::grant` only returns the grant and does not put it into the in-memory Policy. It takes effect when the app signs and persists it and, after the write succeeds, puts it in with `Policy::add_grant` ("Storage").

A saved rule is itself what gets reapplied. Thanks to placeholders, the same rule can also be used to approve a different app. The approval UI shows the list of rules; picking one and passing a single passkey creates a grant. The flow of choosing conditions on the spot in the approval UI and allowing is two steps: "assemble a rule, then immediately turn it into a grant". Whether to save the rule to the list is the user's choice; if not saved, it becomes a throwaway rule.

### Names and References

subjects, tags, rules, and sets of conditions can all be named, placed in the list, and referenced by name from elsewhere. If a subject created in the approval UI is saved with a name, it can be reused from then on in tag definitions and other rules.

References are written as strings (no wrapper such as `{"ref": "…"}`). Not using a wrapper concerns how references are written and does not apply to the shape of values (glob / regular expression / numeric range values are written as `{"glob": …}` / `{"regex": …}` / `{"min": …, "max": …}`; "matcher").

**Reason for the decision**: at every place a reference can appear, what it refers to is fixed to one kind, and there is no place where kinds are mixed.

- Inside `tags`, only tag names.
- In a subject position (a rule's `subject`), a string is a subject name and an object is an inline definition. The type distinguishes them. Entries of `ancestors` are not referenced by name; only an inline `match` and `tags` are written.
- A rule is only referred to by name when applied, and is never referenced from within the list.
- Elements of `conditions`, both plain strings and ones with arguments such as `{"age": "1h"}`, are vocabulary names.

A wrapper would only add writing and reading effort without reducing ambiguity. This is revisited only if the premise breaks (a form is added where names of different kinds can appear in the same place).

### matcher

The keys of `match` are names of items registered in the vocabulary (`Vocabulary`), and the values are conditions on those items. The matching forms are decided per item.

| Form | JSON | Applicable items |
| --- | --- | --- |
| Exact match | A string or a number | All |
| glob | `{"glob": "…"}` | Paths, process names, cwd. Paths and cwd are written as absolute paths; `~` is not interpreted |
| Regular expression | `{"regex": "…"}` | Paths, argv (for argv it is applied per element and is true if any element matches. It is not applied to the joined string) |
| Numeric range | `{"min": …, "max": …}` | uid |

An item or field whose rule value is a placeholder (`true`) becomes an exact match on the actual value in the grant ("rule"). There is no exact match on booleans. JSON `true` is reserved for placeholders; there are currently no boolean items, and when one is needed it is represented as a string.

The item checks the validity of values (`Matcher::validate`, called by loading and the builder), and the item is also what replaces a placeholder with the actual value (`Matcher::resolve`; `ResolveError::ValueUnavailable` if the process has no value).

`process`, `binary`, and `os.session` are structured values and allow exact match only (every field of `binary` is exact match). Signature conditions are considered a match only when signature verification passed. An ad-hoc signature has an empty Team ID, so it never matches a Team ID condition.

**`process`** is the item meaning "this individual process" (decision record: [DR-0005](decisions/DR-0005-process-identity-as-one-item.md)). In a rule it is written as `true` (pin the approved individual process) or a concrete composite value, and in a grant it becomes a composite value that `Policy::grant` gives every identifier obtainable at that moment plus the boot UUID (`kern.bootsessionuuid`) (e.g. `{"process": {"boot_uuid": "7B1E…", "unique_id": 12345, "pid": 501, "start_time": {"secs": 1762570683, "micros": 123456}}}`). Matching compares every identifier present on both sides, and matches only when all of them match. At worst it checks that the pair of pid and start time matches. The person writing the rule does not care which identifier was compared. Its class is Strong. It can be written both in `match` and inside `ancestors`, so "descendants of the shell in this terminal tab" can be expressed. Once the pinned process exits, it is no longer in the sequence and the grant stops matching. This expresses the lifetime of a process in the sequence. Deleting grants that point to exited processes is the responsibility of cleanup (the app). The UI shows it as the single choice "only this process". `process` is the identity of the individual process, and it stays the same individual even when exec changes the code inside it. The identity of the code is carried by `binary`, so to also fix the code, pin `binary` together with it.

**`binary`** is the item meaning "this process's code". Its value is a composite of any number of fields, `{digest?, team_id?, signing_id?, bundle_id?, cdhash?}` (e.g. `{"binary": {"team_id": "VWXYZ67890", "signing_id": "com.anthropic.claude-code"}}`). Each field value is a string or the placeholder `true`, and in a grant every one is a string. `digest` is `sha256:<hex>`, `cdhash` is hex, and `team_id`, `signing_id`, and `bundle_id` are the values from the signature and the Info.plist sealed by the signature as is (`bundle_id` is matched against `Signature.bundle_id`). No field takes a boolean value, so `true` only has the meaning of a placeholder. Matching verifies each field present in the value, and matches only when all of them match (AND). Signature-derived fields (`team_id`, `signing_id`, `bundle_id`, `cdhash`) are considered a match only when signature verification passed. A valid signature is a property of matching the signature-derived fields, so there is no item that represents only that. Its class is the strongest among the fields present in the value: Strong if there is a signature-derived field, Medium if there is only `digest`. Apple's OS binaries (Terminal.app, `/bin/zsh`, etc.) have no Team ID, so they are written with a root-owned `path` rather than `binary` (Strong).

The validity rules for values are closed within `binary`.

- If there is `signing_id`, there is also `team_id`. The signing identifier is a value the developer chooses freely, and even an ad-hoc signature can claim it.
- If there is `bundle_id`, there are also `team_id` and `signing_id`. Anyone can write Info.plist.
- `cdhash` and `digest` may stand alone.
- Empty (no fields at all) is invalid.
- A value with an unknown field is invalid and is an error rather than being silently dropped (the same goes for values of `process`).
- Placeholder fields also count as "present" (`{"signing_id": "com.googlecode.iterm2", "team_id": true}` is valid).

The builder aligns the fields and puts `true` so that they satisfy these rules (if the user picks `signing_id`, `team_id` goes in too), and loading treats values that do not satisfy them as errors.

- `cdhash` is the strongest field, determining the values of all the fields below. This is because the CodeDirectory includes the identifier, the Team ID, and the hash of Info.plist (`CS_SUPPORTSTEAMID`, `teamOffset`, `CSSLOT_INFOSLOT` in the SDK's `cs_blobs.h`).
- `digest` is the hash of the contents of the file at the executable path, placed as a floor for when the signature cannot be relied on. Whether to collect it is chosen with `CollectOptions::digest` (not collected by default). On macOS it reads the path from `proc_pidpath`, so if the file is replaced after exec, it diverges from the running image (its class is Medium). On Linux, `/proc/<pid>/exe` points to the running inode, so it is effectively a strong means. In environments and apps where signature-derived fields are available, `digest` is not used, and the UI shows signature-derived fields first.

**`os.session`** is a lifetime condition that selects an OS epoch by level (epochs are defined in "scope: Grant Lifetime"). It is written in a rule's `conditions`, not in a subject's `match`. Its argument is a level, `boot` < `awake` < `unlocked`, and its pinned value is a composite of the epochs at or below the chosen level (e.g. `{"boot": "7B1E…", "awake": wake time, "unlocked": unlock time}`). `check` is true only when all epochs at or below the level match. It is a condition item, so it is not counted in the rule's strength (the subject's class).

### Item Registration

The items usable in conditions (`match` keys, lifetime scope names, state condition names) are registered in the vocabulary in the same form, whether built-in or from an app (decision record: [DR-0006](decisions/DR-0006-structured-values-instead-of-depends.md)).

```
register(key, impl)
```

| Argument | Contents |
| --- | --- |
| key | The item's name (namespaces below) |
| impl | The implementation for each kind of item. For matcher items, the `Matcher` trait (`matches` for matching, `class` for deciding the class from the value, `validate` for checking the validity of the value, and `resolve` for replacing a placeholder with the actual value). For lifetime and state items, the condition trait (observe / pin / check / advance, plus validate\_args for checking the validity of the arguments, "Condition Implementation") |

Registration goes into procline-acl's `Vocabulary`, where matcher items, scopes, and conditions share the same container. The only checks at registration time are duplicate keys and the namespace.

- `Vocabulary::builtin()` holds only the OS-independent items: the matcher items (`process`, `binary`, `uid`, `gid`, `path`, `cwd`, `argv`, `name`, `tty`, `responsible`), `until`, `age`, `uses`, and `time.window`.
- The `os.*` items (`os.session`, `os.console_user`, `os.login_session`, `os.not_remote`, `os.console_active`) are provided by procline-macos as `Item`s (`procline_macos::os_items() -> Vec<procline_acl::Item>`), and the app registers them with `register`.

Namespaces are aligned with the item's category.

- Unprefixed: attributes of the target process itself (`process`, `binary`, `uid`, `gid`, `path`, `cwd`, `argv`, `name`, `tty`, `responsible` …). A subject is "a condition on that process", so these are unprefixed.
- `os.`: host state and epochs. `time.`: time. `app.`: app-specific (rules in "Vocabulary Added by Apps").
- `until`, `age`, and `uses` are the lifetime of the grant itself, and are unprefixed as built-in basic words.

An item holds the shape and validity of its own values. There are no dependencies across keys; where structure is needed, the value of a single key is given structure (`process`, `binary`, `os.session`).

- The builder (`SubjectBuilder` / `RuleBuilder`, which create rules from the approval UI) does not hold the collection result; from what the user picked (`process`, a combination of `binary` fields, a level of `os.session`), it assembles a subject with the picked fields set to `true`. The actual values are filled in by `Policy::grant` with `Matcher::resolve`. For `binary`, it aligns the fields so that the validity rules are satisfied; the level of `os.session` is written as the argument of the rule's condition (the epochs are pinned when the grant is created).
- Loading (`Policy::load_verified`, `Policy::load_grant`) has the item's implementation (`Matcher::validate`, `Condition::validate_args`) check values and treats invalid values (including unknown fields) as errors. If a placeholder is in a place where placeholders cannot be written (a grant, a tag definition, a named subject), that too is treated as an invalid value and is an error (`LoadError::InvalidValue`). Tag names and subject names with no definition are `LoadError::UnknownTag` / `LoadError::UnknownSubject`.
- The UI (app side) shows one choice per key, and within it lets the user pick the level of the value or the combination of fields.
- When an app's item is to be used together with a built-in item, they are placed side by side in the same `match` (AND).

### Strength: Class and Depth

An item's strength is expressed on two axes.

| Axis | What it represents | Value |
| --- | --- | --- |
| class | How much the condition pins down the approved individual process or code (the strength in the "Collected Information" tables) | Strong / Medium / Weak |
| depth | How narrowly the value constrains | The level of the value, or the number of pinned fields |

The definition of the class and the decision record for the built-in classes are in [DR-0009](decisions/DR-0009-strength-class-as-specificity.md).

| Class | Built-in items |
| --- | --- |
| Strong | `process`, `binary` with a signature-derived field, `path` in a root-owned location the user cannot write to |
| Medium | Responsible process, `digest` (a `binary` with only it), `path` in a location the user can write to |
| Weak | `name`, `cwd`, `argv`, `uid`, `gid`, `tty` |

- The class is decided by the item from the value (`Matcher::class(value, process)`). It also accepts rule values containing placeholders, and decides by which fields they are placed in (`{"binary": {"team_id": true}}` is Strong). `process` is the process being matched; it is passed when creating a grant and at evaluation, and is absent (`None`) at rule build and at load time.
- The class of `binary` is the strongest among the fields present in the value: Strong if there is a signature-derived field, Medium if there is only `digest`.
- The class of `path` is decided by the attributes the collection side (procline-macos) obtains per path (the owner and whether the user can write to it, `PathMeta`). Strong / Medium is decided when creating a grant and at evaluation, where there is a process; at rule build and load time, where there is no process, it is Medium (the weaker side). "A location the user can write to" means the user can write to (replace) the file itself or any directory on the path.
- `uid` and `gid` are Weak because every process with the same uid satisfies them, so they identify nothing.
- Which item has which class is held by the vocabulary (the implementations of the registered items). Items in the collection result do not carry a strength.
- depth is a UI concept, and the crate has neither a calculation nor a type for it. It is material for UI ordering and for additional constraints an app may impose. It is not used for rule strength constraints ("Rule Creation and Strength Constraints").

### Evaluation

The target of evaluation is grants (decision record: [DR-0008](decisions/DR-0008-evaluation-semantics.md)). Evaluation separates the stage that decides the truth of each condition from the stage that decides adoption per grant.

1. Check each grant's conditions.
   - A grant that uses a condition whose observation failed (that key in `EvalContext` is `Err(ObserveError)`) cannot be decided in that evaluation. Its id is put in `Decision.undecidable`, and it is neither allowed nor expired.
   - A grant whose lifetime `check` became false has its expiry settled on the spot in that evaluation, and its id is put in `Decision.expired`. Once settled, an expiry never comes back (it is not revived by the clock going backwards or by an observation recovering).
   - Exclude grants whose targets do not match the target.
   - Match each grant's subject and take the state `check`. The subject's `match` and `tags` are matched against the target itself, and `ancestors` is matched against the sequence as a subsequence, greedily from the near side.
   - When the sequence is cut off (`ProcessChain.truncated` is `Some`): the subject's conditions (`match` ∧ `tags` ∧ the `ancestors` subsequence) are all positive conditions, and extending the sequence never turns "matched" into "did not match" (monotone). So a grant that matched on the cut-off sequence also matches on the full sequence, and it is used in deciding the effect. A grant that has conditions on ancestors (`ancestors`, or a tag whose definition has `ancestors`; when a tag refers to another tag, this is followed transitively) whose conditions on the target itself (`match` and the own part of `tags`) matched but whose ancestor conditions were not found within the cut-off sequence is undecidable (a grant whose own conditions failed fails on the full sequence too, so it is not treated as undecidable). Its id is put in `Decision.undecidable`, and it is not used in deciding the effect. A grant whose subject matched but whose state `check` is false is false on the full sequence too, so it is not treated as undecidable.
2. Decide the effect. The order is deny > allow > ask.
   - If even one `deny` matches, reject.
   - If an `allow` matches, allow. Among the matching allows, exactly one is adopted. Grants that do not change under advance (permanent, or without `uses`) are preferred, and ties go to the oldest by creation. This avoids consuming limited `uses` when another grant would pass anyway.
   - If an `ask` matches, `Effect::Ask` (the app's re-authentication). `Decision.grant_id` is the id of the adopted ask grant.
   - If nothing matches, the default effect (`default_effect` of `Policy::load_verified`). `Decision.grant_id` is None.
3. Apply each condition's `advance` only to the adopted grant. If even one returns a new pinned value, create a new grant with the pinned values replaced (grants are immutable).
4. The app signs and persists the changed grant, and uses the result (allow) only after the write succeeds.

The evaluation result (`Decision`) returns not only the effect but also the id of the adopted grant and which item each condition matched (the trace). This is used for the UI's "why did this pass, why was I asked". `Decision.trace` is not returned to the peer (it would reveal which condition failed). When step 3 changed the grant, the new version is also returned (`updated_grant`).

There are two entry points for evaluation. `evaluate` runs through step 3 and only returns `updated_grant`; it does not replace the in-memory grant. `explain` is for displaying the trace; it does not apply `advance`, and `updated_grant` is always empty. `explain` also fills `expired`, but it does not settle the expiry (the app does not use `explain`'s `expired` for deletion).

- The app signs and persists `updated_grant`, and after the write succeeds replaces the in-memory grant with `Policy::add_grant` (replacing the one with the same id), then hands over the value. If the write fails, the allow is not used.
- The app removes the grants in `evaluate`'s `expired` with `Policy::remove_grant` and from storage. A grant whose `uses` reached 0 also has its expiry settled on the next evaluation and appears here.
- When `undecidable` is non-empty, whether to let an allow pass while there is an undecidable deny is decided by the app. The crate returns the facts.

## scope: Grant Lifetime

Lifetime conditions (hereafter scopes) pin the epoch at that moment when a grant is created; on every evaluation the current epoch is compared with the pinned value, and if they differ the grant expires permanently. This means "during this particular unlock" rather than "while unlocked", so locking once and unlocking again does not revive the grant.

With this shape, every scope is automatically guaranteed to "never come back once ended", and all an app has to add is a single implementation of the condition trait ("Condition Implementation"). If the current epoch cannot be observed when creating a grant, the grant cannot be created (`PinError::Unobservable`), and if at evaluation there is no observed value because it is outside the period (`observe` returns `Ok(None)`), `check` becomes false and the expiry is settled. Both fail safe. When the observation itself fails (`observe` returns `Err`), this is distinguished from being outside the period, and the grant is treated as undecidable in that evaluation (neither allowed nor expired; "Evaluation").

Multiple scopes can be listed, and the grant is in effect only while all of them are alive (AND). They are combined like "24 hours, but only until reboot".

### Built-in Vocabulary

| Name | When it ends | How the epoch is obtained (macOS) |
| --- | --- | --- |
| `until` | At the specified time | Clock (judged by time rather than epoch) |
| `age` | Elapsed time since the grant's creation | Converted to the pinned value of `until` when the grant is created |
| `uses` | After being adopted N times | The remaining count is pinned and decreases by 1 each time it is adopted (a counter rather than an epoch) |
| `os.session` | The end of any of the periods at or below the chosen level. `boot` ends on reboot, `awake` on sleep or hibernation, `unlocked` on screen lock (manual, automatic lock when away, screen saver) | `boot` is `kern.bootsessionuuid`, `awake` is the time of the most recent wake (`kern.waketime`), `unlocked` is the time of the most recent unlock |
| `os.console_user` | User switch | A value intrinsic to the user switch event |

`until`, `age`, and `uses` are in procline-acl's `Vocabulary::builtin()`, and `os.*` is provided by procline-macos's `os_items()` ("Item Registration").

An epoch is a value intrinsic to the event (the boot UUID, the time of a wake or unlock, etc.). It is unique independently of daemon restarts, so grants reloaded across a restart can also be judged correctly.

The level names of `os.session` are names of periods.

- `boot` is the period from startup to reboot, `awake` from waking to sleep or hibernation, and `unlocked` from unlocking to screen lock.
- The pinned value of level N holds every epoch at or below it. `awake` and `unlocked` are not strictly nested (the screen can be locked without sleeping), but choosing `unlocked` also expires on sleep. This is by design.
- observe returns the epochs of the three levels as one composite value `{"boot": uuid, "awake": wake time, "unlocked": unlock time}`, including only the levels whose period is currently in progress (levels outside their period, i.e. while locked or asleep, are omitted. `boot` is `kern.bootsessionuuid`; the others are the time that period started). pin copies the fields at or below the argument's level, and `check` is true only when every field in pinned is present in observed and matches. Outside the period the field is missing, so it is false and the expiry is settled, and even when the period starts again the time differs, so it does not match. This is because if only the unlock time were used as the epoch, the value would not change while locked, and the grant would pass.
- User switching (`os.console_user`) and the login session (`os.login_session`) are not levels of `os.session`; they are independent items. No level covers the period until the display sleeps for power saving. It happens with neither lock nor sleep and also requires handling multiple monitors, so apps that want it add it under `app.`.

### Vocabulary Added by Apps

App-specific vocabulary goes in the `app.` namespace. The only namespaces are the ones the crates use (`os.`, `time.`, etc.) and `app.`; apps do not create namespaces freely. Only one app evaluates at a time, so multiple namespaces are unnecessary, and allowing free creation could collide with namespaces added to the crates in the future. For cw, it would be things like:

- `app.unlock`: one opening of the vault. Ends on manual lock or vkey\_ttl expiry.
- `app.passphrase`: one issuance of P. Ends when it becomes Sealed.

Rules with unregistered names are an error at load time (silently ignoring them would produce grants that stay in effect longer than intended).

## Conditions, Rule Creation, and Storage

### Conditions

State conditions are ones whose truth value can change on every evaluation. Unlike scopes, when one becomes false the grant does not expire; it just does not match at that time. As with scopes, apps can add their own under `app.` names in addition to the built-ins. The state of state conditions (`os.console_active`, etc.) is obtained not from distributed notifications but from an authoritative API (`CGSessionCopyCurrentDictionary`, etc.).

| Name | True when |
| --- | --- |
| `os.not_remote` | The peer's asid belongs to the console session. Judged by the asid alone (the presence of ancestors can be changed by a double fork, so it is not used) |
| `os.console_active` | The screen is not locked |
| `os.login_session` | The peer's login session is the same as when the grant was created (it holds the pair of the boot UUID and asid at creation, `{boot_uuid, asid}`, as its pinned value. The asid is reused across boots, so it is paired with the boot UUID. Detecting logout is not promised) |
| `time.window` | Within the specified days of the week and time range |

Location conditions such as "while on the home Wi-Fi" are added by apps as needed.

### Condition Implementation: observe / pin / check / advance

Lifetime (scope), consumable (`uses`), and state conditions are expressed with the functions of the same trait. Only `observe` reads outside state (epochs, screen lock state, etc.); `pin` / `check` / `advance` decide their results from the values passed in. A condition touches only its own pinned value and never receives the whole grant.

```rust
/// The observed value of this condition. EvalContext::capture observes it only once at the start of evaluation, and it does not change during evaluation
pub struct Observed<'a> {
    pub now: SystemTime,
    pub value: Result<Option<&'a Value>, &'a ObserveError>,   // the result of observe() as is. If Err, the Policy does not call check and treats it as undecidable, and pin returns PinError::Unobservable
}

trait Condition {
    fn kind(&self) -> ConditionKind;                                   // Lifetime / State
    /// Observe the current value (an epoch uuid, screen lock state, etc.). EvalContext::capture calls it once for every condition at the start of evaluation. Ok(None) for conditions with nothing to observe and outside the period (for a lifetime condition, check becomes false and the expiry is settled). When the observation fails (a sysctl or IOKit call fails) it is Err, and grants that use that condition cannot be decided in that evaluation
    fn observe(&self) -> Result<Option<Value>, ObserveError>;
    /// Called once when creating a grant. Returns the pinned value. Values taken from the chain, such as the {boot_uuid, asid} of os.login_session, look at chain. State conditions normally return Ok(None); those that fix a value depending on the peer at creation (os.login_session) return a pinned value. Err(PinError::Unobservable) for a lifetime condition with no observed value. Err(PinError::InvalidArgs) if args are invalid
    fn pin(&self, args: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> Result<Option<Value>, PinError>;
    /// The check. No side effects
    fn check(&self, args: Option<&Value>, pinned: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> bool;
    /// Called only on the adopted grant. The new version of the pinned value. None means no change
    fn advance(&self, pinned: Option<&Value>) -> Option<Value>;
    /// Validity of the arguments. Called by loading and the builder
    fn validate_args(&self, args: Option<&Value>) -> Result<(), String>;
}

enum PinError { Unobservable, InvalidArgs { reason: String } }
struct ObserveError { reason: String }
```

| Item | observe | pin | check | advance |
| --- | --- | --- | --- | --- |
| Epochs (`os.session`, `app.unlock` …) | The current epoch | The observed value (Err if absent). For `os.session`, the composite of the epochs at or below the level | pinned == observed. For `os.session`, all epochs at or below the level match | None |
| `until` | None | The time in args | obs.now < pinned | None |
| `age` | None | obs.now + the duration in args (becomes the pinned value of `until`) | obs.now < pinned | None |
| `uses` | None | N from args | pinned > 0 | pinned − 1 |
| State (`os.console_active`, etc.) | The current state (if there is something to observe) | None | Looks at observed / args / chain | None |
| State `os.login_session` | None | `{boot_uuid, asid}` from chain (`ProcessChain.boot_uuid` and the peer's asid) | `{boot_uuid, asid}` from chain == pinned | None |

- `ConditionKind` has two values, Lifetime / State. Epochs, `until`, `age`, and `uses` are Lifetime; `uses` too never comes back once it reaches 0.
- `EvalContext` holds `now` and "key → the result of `observe()` (`Result<Option<Value>, ObserveError>`)". The Policy builds `Observed { now, value: ctx.observed(key) }` per condition and passes it (a condition does not know its own key). A grant that uses a condition whose key's result is `Err` is treated as undecidable in that evaluation and put in `Decision.undecidable` ("Evaluation").
- `args` reaches the state `check`, so arguments such as the time range of `time.window` can be used in the check.
- State conditions can also have pinned values. This is to fix a value depending on the peer (the `{boot_uuid, asid}` of `os.login_session`) when the grant is created. The lifetime rule "once false, the expiry is settled" applies only to conditions that compare an observed value (the state of the world) with the pinned value. A value depending on the peer not matching just means a different peer came, not that the state of the world changed, so it is a state condition.

### Rule Creation and Strength Constraints

Rules are created by picking items in the approval UI (RuleBuilder). Choosing "by this process's signature" or "by the Team ID of the claude-code above" produces a subject with the picked fields set to placeholders (`true`), and the actual values are filled in when the grant is created. For `binary`, the builder aligns the picked fields into a valid combination, and for `os.session` the level is chosen via the condition's argument ("Item Registration"). `SubjectBuilder` creates the subject and `RuleBuilder` creates the static rule.

- `SubjectBuilder` does not receive the collection result. It assembles a subject containing `true` from a `PinSpec`, and concrete values are written with `exact`. Ancestor entries are assembled with `AncestorBuilder` and added in order with `ancestor`.
- `pin` and `exact` on the same key are merged per field into one value for `binary` (an error if the same field is in both), and for simple items and `process` the second one is an error (`BuildError::Conflict`). `SubjectBuilder::build` / `AncestorBuilder::build` check only the validity of values (the `binary` rules, empty); checking against the vocabulary (unregistered items, `Matcher::validate`, `Condition::validate_args`) is done by `RuleBuilder::build`.
- `RuleBuilder` is created from `Policy::rule_builder(id, subject)`. This is because calculating the strength needs both the definitions of tags and named subjects and the vocabulary. The rule's `id` is given by this argument.
- `RuleBuilder::build()` returns a static `Rule` and does not record epochs. It checks the validity of values and the strength (class) vs scope constraints (below). The strength class can be judged even with placeholders in place.
- Pinning is done by `Policy::grant(rule, tagged, ctx)`. It fills the subject's placeholders with the actual values from `tagged`, pins each condition, and returns the grant. It does not put it into the in-memory Policy (signing and saving are up to the app, which puts it in with `Policy::add_grant` after the write succeeds). A `GrantError` is one of: no value to fill a placeholder (`ValueUnavailable`), `pin` failed (`PinError`: no observed value, invalid arguments), a value is invalid, or the constraints are not met (`ScopeTooWeak`).
- So that the approval UI can show "what will be pinned" before the passkey, `Policy::resolve_subject(subject, tagged)` gives the subject with its placeholders filled (name references are resolved to the subject in the list before filling. An entry that matched the target itself via `include_self` is filled with the target's own values). `Policy::grant` also uses this internally.

A rule's strength is determined by the subject's conditions on the target process itself (decision record: [DR-0003](decisions/DR-0003-rule-strength-from-own-match.md)).

- The conditions on the target process itself are the `match` and, from the definitions of the tags referenced by `tags`, the conditions on the process itself. The rule's strength is the strongest class among those items.
- `ancestors` conditions are not counted. Even if the ancestors are strongly identified, the target is "any descendant of them", and the target itself is not constrained. The same holds with `include_self` (it only lets matching of the list start from the process itself, and does not constrain the process itself).
- A subject with no condition on the process itself (only `ancestors`) is the weakest and is subject to the same constraints as Weak.
- The strength of a tag used as a condition is that of the tag definition's subject, calculated by the same rules.

The constraint table (the scope conditions allowed for `allow` per class, `AllowConstraints`) is given by the app to `RuleBuilder` / `Policy`. The crate has no default values and holds only the checking mechanism. `Policy` holds the `AllowConstraints` (given as an argument of `Policy::load_verified`), and `RuleBuilder::build`, `Policy::load_verified`, `Policy::grant`, and `Policy::load_grant` perform the same check and return an error if it is not met (`BuildError::ScopeTooWeak`, `LoadError::ScopeTooWeak`, `GrantError::ScopeTooWeak`). Constraints are judged by class; depth is not used. Which scopes satisfy the constraints is also decided by the app's constraint table.

- The shape of the constraint table is three entries, `strong` / `medium` / `weak` (all required), each holding either `Unrestricted` (no restriction) or `AnyOf([...])` (satisfying any one of the listed options is enough). An element of `AnyOf` is either `Condition(key)` (contains a condition with that key) or `UntilWithin(duration)` (expires within that duration).
- Time constraints are expressed with `ScopeOption::UntilWithin`. `Condition("age")` / `Condition("until")` can also be written, but on the grant side `age` has been converted to `until`, so `Condition("age")` is never satisfied by a grant.
- When it is judged: the length of `age` and the presence of lifetime conditions are judged at rule build (and at load time), and the absolute time of `until` is judged when creating the grant (against now at that moment). The reference time for `UntilWithin` in `Policy::load_grant` is the grant's `created_at`. The class of `path` being decided by the process also happens when creating the grant (at build time it is judged as Medium).

| Rule strength (class) | Scopes allowed for `allow` (an example of constraints given by the app) |
| --- | --- |
| Strong (signature, `process`, `path` in a root-owned location the user cannot write to) | No restriction |
| Medium (responsible process, `digest`, `path` in a location the user can write to) | `until` within 7 days, or includes an epoch scope |
| Weak (name, cwd, argv, uid, gid, tty) | Includes an epoch scope (`os.session`, `app.unlock`, etc.) |

No constraint is placed on `deny`. Even a deny on weak conditions at least works in the safe direction. The UI shows "This condition can also be satisfied by other processes of the same user" as soon as a weak condition is picked.

### Storage

There are two storage forms: "one list" and "one grant per file". Both are JSON, and saving and signing are the app's responsibility. Signatures are verified with `PolicyVerifier::verify(&self, kind: SignedKind, bytes, sig)`, implemented by the app, and `enum SignedKind { List, Grant }` separates the purposes of the list's and grants' signatures.

**The list** (subjects, tags, rules): the crate provides an entry point (`Policy::load_verified`) to "receive the bytes of the list and a signature, verify, then load". cw signs the list with the D-side key so that a process with the same uid cannot add allow rules on its own (treated the same as the PasskeyRegistry).

**Grants**: grants are held in memory, and to guard against unintended daemon termination, each one is signed and persisted individually on creation and on update, and all of them are reloaded at startup. In-memory grants change only when the app calls `add_grant` / `remove_grant` after persisting (decision record: [DR-0008](decisions/DR-0008-evaluation-semantics.md)). The crate has the JSON shape of `Grant` and the following entry points.

- `Policy::load_grant(bytes, sig, &verifier)`: receives the bytes and signature of one grant, verifies, then returns a `Grant`. It performs the same checks as the list (unregistered items, validity of values, constraints), and returns an error if they fail.
- `Policy::add_grant(grant)`: puts a grant into the in-memory Policy. If one with the same id exists, it is replaced. Used for reloaded grants, grants created with `Policy::grant` and persisted, and persisted `updated_grant`s.
- `Policy::remove_grant(id)`: removes a grant from the in-memory Policy.
- `Policy::grants()`: enumerates the in-memory grants.

Cleanup (deleting grants that are no longer needed) is the app's responsibility, using `Decision.expired` and `Policy::grants()` / `remove_grant`.

- Since it is one per file, the write for a `uses` update stays light (to be measured with a benchmark at implementation time).
- `uses` is never consumed twice. The value is handed over only after the decremented grant has been persisted successfully, so when persisting fails the value has not been handed over either.
- The app serializes `evaluate` → persisting → `add_grant`. If they run concurrently, both evaluations see the grant with the same remaining count, so it can be consumed beyond the limit.
- After reloading the list, grants are also re-checked with `Policy::load_grant`. When a tag definition changes, the strength of grants with that tag in their subject can go down.
- Epochs are values intrinsic to the event, so grants reloaded at startup can also be judged correctly across restarts ("scope: Grant Lifetime").
- The persistence directory is placed where nothing other than the evaluating daemon (other processes with the same uid) can write. If it were writable, a grant file from before it was used up could be rolled back to restore `uses`. The location is decided by the app.

## API Skeleton

The entry points are collection, evaluation, rule creation, and grant issuance. Vocabulary extension registers matcher items, scopes, and conditions with the same `register`.

In JSON, byte strings (such as certificate DER) are written as base64url (without padding), and enum values are written in snake\_case. `code_signing` is `{"state": "signed", …}` or `{"state": "unsigned"}`.

```rust
// Collection (procline-macos)
// examples/dump.rs prints the chain collected with collect_pid as JSON (cargo run -p procline --example dump -- <pid>)
let chain: ProcessChain = collect_peer(&stream, &CollectOptions {
    env: EnvPolicy::Allowlist(&["PWD", "SSH_CONNECTION"]),
    icon: true,
    digest: false,                                   // executable digest (not collected by default)
    max_ancestors: 32,
    redaction: Redaction::default(),                 // replaces env redaction (the two functions: target predicate and redaction)
})?;
// chain.processes()[0] is the target, the rest are ancestors
// chain.truncated: Option<Truncated>. The reason the sequence was cut off: enum Truncated { MaxAncestors, AncestorExited, Unavailable }
// chain.boot_uuid: String. The collection side obtains kern.bootsessionuuid
// p.signature_trust(): Platform / AppStore / Notarized / DeveloperId / AdHoc / Unknown / Unsigned / Invalid
// ProcessInfo holds digest: Option<String> and path_meta: Option<PathMeta>. PathMeta { owner_uid: u32, writable_by_user: bool } (used for deciding the class of path)
// ProcessInfo.responsible: Option<ProcessIdentity>. The responsible process is held as the identification of the individual process rather than a pid
// Signature.bundle_id: Option<String> (from kSecCodeInfoPList. Used for matching; what BinaryPin.bundle_id is matched against). ProcessInfo.bundle (read by walking up from the executable path to the .app) is for display
// ProcessIdentity (the pinned value of process) holds boot_uuid: String. Created with Identity::process_identity(&self, boot_uuid), passing ProcessChain.boot_uuid as boot_uuid

// Strength (shared types in procline-core). Which item has which class is held by Vocabulary, not by ProcessInfo items. depth is a UI concept and has no type
enum Strength { Strong, Medium, Weak }               // class (decided by the item from the value)

// A value written in a rule (procline-core). In JSON, true is Pin, anything else is a value of T
enum Pinnable<T> { Pin, Value(T) }

// Structured values (procline-core)
struct BinaryPin { digest: Option<Pinnable<String>>, team_id: Option<Pinnable<String>>, signing_id: Option<Pinnable<String>>, bundle_id: Option<Pinnable<String>>, cdhash: Option<Pinnable<CdHash>> }  // in JSON each field is true (placeholder) or a string (cdhash is hex)
// BinaryPin::validate(&self) -> Result<(), BinaryPinError>: validity of the value (signing_id needs team_id, bundle_id needs team_id and signing_id, empty is invalid. Placeholder fields also count as present). Unknown fields are an error at load time
enum SessionLevel { Boot, Awake, Unlocked }          // level of os.session (the value of args. In JSON "boot" / "awake" / "unlocked")

// Vocabulary (procline-acl)
let mut vocab = Vocabulary::builtin();               // only OS-independent items: matcher items (process / binary / uid / gid / path / cwd / argv / name / tty / responsible), until / age / uses, time.window
for item in procline_macos::os_items() {             // os.* items (os.session / os.console_user / os.login_session / os.not_remote / os.console_active) are provided by procline-macos
    vocab.register(item)?;
}
// matcher items, lifetime, and state items are added with the same register. Duplicate keys and namespace violations are errors
vocab.register(Item::matcher_fn("app.workspace", Strength::Weak, |p, v| ...))?;  // items whose class is constant regardless of the value are registered with a closure, stating the class explicitly
// items whose class changes with the value implement the Matcher trait and are registered with Item::matcher(key, impl)
//   matches(&self, target: &MatchTarget, value) -> bool (MatchTarget { info: &ProcessInfo, boot_uuid: &str } = one process of the collected snapshot; matching never touches the OS. An item never sees the ancestors, and boot_uuid is the only thing it needs from the chain) / class(&self, value, process: Option<&ProcessInfo>) -> Strength (in build / load where there is no process, items decided by the process are the weaker side) / validate(&self, value: &MatchValue) -> Result<(), String> (validity of the value. Called by loading and the builder)
//   resolve(&self, value: &MatchValue, target: &MatchTarget) -> Result<MatchValue, ResolveError> (placeholder to actual value. ResolveError::ValueUnavailable { field: Option<String> })
// vocab.class(key, &value, process: Option<&ProcessInfo>) -> Option<Strength>: the class the item decided from the value (and the process) (None for unregistered keys and condition items)
vocab.register(Item::condition("app.unlock", CwUnlock::new(&vault)))?;           // a value implementing Condition (lifetime)
// state items are also passed to register with the same Item::condition(...). Whether lifetime or state is returned by Condition::kind

trait Condition {
    fn kind(&self) -> ConditionKind;                 // Lifetime / State
    fn observe(&self) -> Result<Option<Value>, ObserveError>;  // EvalContext::capture calls it once at the start of evaluation. Ok(None) means nothing to observe / outside the period, Err is an observation failure
    fn pin(&self, args: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> Result<Option<Value>, PinError>;  // chain is for pinning the {boot_uuid, asid} of os.login_session
    fn check(&self, args: Option<&Value>, pinned: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> bool;
    fn advance(&self, pinned: Option<&Value>) -> Option<Value>;
    fn validate_args(&self, args: Option<&Value>) -> Result<(), String>;  // validity of the arguments. Called by loading and the builder
}
struct ObserveError { reason: String }
// EvalContext holds Result<Option<Value>, ObserveError> per key. Grants that use a condition that is Err cannot be decided in that evaluation (Decision.undecidable)

// Signature verification (implemented by the app). kind separates the purposes of the list's and grants' signatures
trait PolicyVerifier { fn verify(&self, kind: SignedKind, bytes: &[u8], sig: &[u8]) -> bool; }
enum SignedKind { List, Grant }

// Loading the list (subjects, tags, rules) and reloading saved grants
// constraints: AllowConstraints is the constraint table given by the app (the scope conditions allowed for allow per class). The crate has no default values. Below is an example, not a default
let constraints = AllowConstraints {
    strong: ScopeRequirement::Unrestricted,
    medium: ScopeRequirement::AnyOf(vec![ScopeOption::UntilWithin(Duration::from_secs(7 * 24 * 3600)), ScopeOption::Condition("os.session".into())]),
    weak: ScopeRequirement::AnyOf(vec![ScopeOption::Condition("os.session".into()), ScopeOption::Condition("app.unlock".into())]),
};  // AnyOf is any one of the listed options (OR)
let mut policy = Policy::load_verified(bytes, sig, &verifier, &vocab, constraints, default_effect)?;  // default_effect: Effect is the effect when no grant matches (Decision.grant_id is None). Unregistered items, tag cycles, validity of values, placeholder locations, constraint violations are errors
// LoadError: InvalidValue (validity violation of a value, true in a place where placeholders cannot be written), UnknownTag { name }, UnknownSubject { name }, ScopeTooWeak (constraint violation) …
let saved = policy.load_grant(grant_bytes, grant_sig, &verifier)?;  // verifies one grant and checks it against the vocabulary and the constraints (the reference time for UntilWithin is the grant's created_at). After reloading the list, grants are also re-checked with this
policy.add_grant(saved);                             // puts it into the in-memory Policy (replaces one with the same id)
// policy.remove_grant(id) / policy.grants() -> impl Iterator<Item = &Grant>: used for cleanup

// Evaluation
let tagged = policy.tag(&chain);                     // tags attached to each process (also used for display). TaggedChain borrows only the vocabulary and the chain, not the policy
// tagged.undecidable_tags: BTreeSet<String>. Tags whose presence could not be decided on a cut-off sequence (the approval UI shows them distinguished from "not attached")
let decision = policy.evaluate(&tagged, &Target::key("github/token"), &ctx);  // applies advance to the adopted grant and returns the new version (does not change memory). The app serializes evaluate → persisting → add_grant (running them concurrently can consume uses beyond the limit)
if let Some(grant) = &decision.updated_grant {
    // sign and persist, and after the write succeeds replace it with policy.add_grant(grant.clone()), then hand over the value
}
for id in &decision.expired {
    // delete from storage, and policy.remove_grant(id)
}
// when decision.undecidable is non-empty, whether to let an allow pass while leaving undecidable grants is decided by the app
// decision.trace is not returned to the peer (it would reveal which condition failed)
let shown = policy.explain(&tagged, &Target::key("github/token"), &ctx);      // no advance (for displaying the trace). Fills expired but does not settle the expiry (the app does not use explain's expired for deletion)

pub struct Decision {
    pub effect: Effect,
    pub grant_id: Option<String>,        // the adopted grant (for ask, the adopted ask grant). If None, the effect is load_verified's default_effect
    pub trace: Trace,
    pub updated_grant: Option<Grant>,    // the new version of a grant changed by advance. Always None for explain
    pub expired: Vec<String>,            // ids of grants whose expiry was settled in this evaluation. The app deletes those from evaluate (those from explain are not used for deletion)
    pub undecidable: Vec<String>,        // ids of undecidable grants (those with conditions on ancestors that did not match on a cut-off sequence, and those using a condition whose observation failed). Not used in deciding the effect
}

// The shape of a subject (procline-acl)
struct Subject { r#match: BTreeMap<String, MatchValue>, tags: Vec<String>, ancestors: Vec<AncestorMatch>, include_self: bool }
struct AncestorMatch { r#match: BTreeMap<String, MatchValue>, tags: Vec<String> }  // an entry of ancestors. Holds no nested ancestors
// MatchValue { Pin, Exact(Literal), Glob(..), Regex(..), Range { .. }, Process(Pinnable<ProcessIdentity>), Binary(BinaryPin) }: Pin is the placeholder for simple items
// In JSON, Exact is a string or a number, Glob is {"glob": …}, Regex is {"regex": …}, Range is {"min": …, "max": …}. The Regex of argv is applied per element
// SubjectRef { Inline(Box<Subject>), Named(String) }: the position of a rule's subject. Placeholders can be written only in a rule's Inline
// Grant { id, rule_id: String, effect, subject: Subject, targets, conditions, … }: a grant's subject is inline (a named subject is expanded when the grant is created. Tag names are kept as names)
// targets (rule and grant): each element is a glob over the target (the string of a Target). An empty targets matches every target

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
// build checks only the validity of values (the binary rules, empty). Unregistered items and Matcher::validate are checked by RuleBuilder::build
// pin and exact on the same key: binary is merged per field (BuildError::Conflict if the same field is in both), simple items and process give BuildError::Conflict on the second one
// PinSpec { All, Binary(Vec<BinaryField>) }: All is for process and simple items (sets the whole value to true). The level of os.session is specified with RuleBuilder::condition below
// BinaryField { Digest, TeamId, SigningId, BundleId, CdHash }

// Creating a rule. RuleBuilder is created from Policy (to calculate the strength by looking at the definitions of tags and named subjects and the vocabulary)
let rule = policy.rule_builder("pj1-claude-usual", SubjectRef::Inline(Box::new(subject)))  // the rule's id and subject
    .targets(["key:k1"])
    .condition(ConditionUse::with_args("age", json!("1h")))
    .condition(ConditionUse::with_args("os.session", json!("unlocked")))  // stays symbolic. The epoch is pinned when the grant is created
    .allow()
    .build()?;                                       // a static Rule. Checks the validity of values and the strength (class) against the policy's AllowConstraints (a violation is BuildError::ScopeTooWeak)

// Approval UI preview: show "what will be pinned" before the passkey
let preview = policy.resolve_subject(&rule.subject, &tagged)?;  // the Subject with the placeholders of a SubjectRef (a name is fine too) filled with the actual values from tagged via Matcher::resolve. GrantError::ValueUnavailable if a value is missing

// Applying a rule to create a grant (pins the subject's placeholders and each condition. Saved rules use the same entry point)
let grant = policy.grant(&rule, &tagged, &ctx)?;     // &self. Only returns the grant, pinned and with an id assigned; does not put it into memory
// GrantError: ValueUnavailable { key, field: Option<String> } (no value to fill a placeholder), pin failure (Unobservable / InvalidArgs), validity violation of a value, ScopeTooWeak (constraint violation. The absolute time of until and the class of path are judged here)
// the app signs and persists the grant, and puts it in after the write succeeds
policy.add_grant(grant);
```

- `EvalContext::capture` takes the current time and the result of each condition's `observe()` only once at the start of evaluation, so the values do not change during evaluation. From it, the Policy builds an `Observed` per condition and passes it to `pin` and `check`. In tests, all of them can be replaced.
- `uses` decreases inside `evaluate` via the `advance` of the adopted grant. The app signs and persists `decision.updated_grant`, and after the write succeeds replaces it with `add_grant` and hands over the value.

---

Pending decisions are in [docs/QUESTIONS.md](QUESTIONS.md); work items are in `docs/issue/`.
