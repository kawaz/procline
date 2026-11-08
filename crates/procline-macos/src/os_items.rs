//! The `os.*` vocabulary items: the host state and its epochs on macOS.

use procline_acl::{Condition, ConditionKind, Item, ObserveError, Observed, PinError};
use procline_core::{ProcessChain, SessionLevel};
use serde_json::{Map, Value, json};

use crate::sys::proc as sys;

/// The items, for `os_items`.
pub(crate) fn items() -> Vec<Item> {
    vec![
        Item::condition("os.session", Session),
        Item::condition("os.login_session", LoginSession),
        Item::condition(
            "os.console_user",
            Unsettled {
                kind: ConditionKind::Lifetime,
            },
        ),
        Item::condition(
            "os.not_remote",
            Unsettled {
                kind: ConditionKind::State,
            },
        ),
        Item::condition(
            "os.console_active",
            Unsettled {
                kind: ConditionKind::State,
            },
        ),
    ]
}

/// `os.session`: the OS epochs up to a level, a lifetime condition. The argument is the level, `"boot"`, `"awake"` or `"unlocked"` (`SessionLevel`).
///
/// `observe` returns `{"boot": <kern.bootsessionuuid>, "awake": <seconds of kern.waketime>}`. The epoch of `unlocked` (the time of the last unlock) is not observed yet, since the API to read it is not settled (docs/issue/2026-11-09-os-session-event-values.md): the value lacks the field, so pinning the level `unlocked` fails with `Unobservable` and no grant is made.
///
/// `pin` copies the fields of the levels up to the argument from the observed value (`awake` pins `boot` and `awake`), failing with `Unobservable` when one is missing. `check` holds when every pinned field is in the observed value with the same value: a restart changes `boot` and a wake changes `awake`, and the grant expires.
struct Session;

impl Condition for Session {
    fn kind(&self) -> ConditionKind {
        ConditionKind::Lifetime
    }

    fn observe(&self) -> Result<Option<Value>, ObserveError> {
        let failed = |what: &str, err: std::io::Error| ObserveError {
            reason: format!("cannot read {what}: {err}"),
        };
        let boot = sys::boot_session_uuid().map_err(|err| failed("kern.bootsessionuuid", err))?;
        let awake = sys::wake_time_secs().map_err(|err| failed("kern.waketime", err))?;
        Ok(Some(json!({ "boot": boot, "awake": awake })))
    }

    fn validate_args(&self, args: Option<&Value>) -> Result<(), String> {
        level(args).map(drop)
    }

    fn pin(
        &self,
        args: Option<&Value>,
        obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<Value>, PinError> {
        let level = level(args).map_err(|reason| PinError::InvalidArgs { reason })?;
        let Ok(Some(Value::Object(observed))) = obs.value else {
            return Err(PinError::Unobservable);
        };
        let mut pinned = Map::new();
        for field in fields(level) {
            let value = observed.get(*field).ok_or(PinError::Unobservable)?;
            pinned.insert((*field).to_owned(), value.clone());
        }
        Ok(Some(Value::Object(pinned)))
    }

    fn check(
        &self,
        _args: Option<&Value>,
        pinned: Option<&Value>,
        obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        let (Some(Value::Object(pinned)), Ok(Some(Value::Object(observed)))) = (pinned, obs.value)
        else {
            return false;
        };
        !pinned.is_empty()
            && pinned
                .iter()
                .all(|(field, value)| observed.get(field) == Some(value))
    }

    fn advance(&self, _pinned: Option<&Value>) -> Option<Value> {
        None
    }
}

fn level(args: Option<&Value>) -> Result<SessionLevel, String> {
    args.and_then(|args| serde_json::from_value(args.clone()).ok())
        .ok_or_else(|| "takes a level: \"boot\", \"awake\" or \"unlocked\"".to_owned())
}

/// The fields of the observed value a level pins: its own and those of the levels below it.
fn fields(level: SessionLevel) -> &'static [&'static str] {
    match level {
        SessionLevel::Boot => &["boot"],
        SessionLevel::Awake => &["boot", "awake"],
        SessionLevel::Unlocked => &["boot", "awake", "unlocked"],
    }
}

/// `os.login_session`: the peer is in the login session it was in when the grant was made, a state condition without arguments.
///
/// `pin` returns `{"boot_uuid": <ProcessChain.boot_uuid>, "asid": <asid of the target>}` (the asid is reused after a restart, so it is paired with the boot UUID), failing with `Unobservable` when the target's asid was not collected. `check` holds when the chain's boot UUID and the target's asid equal the pinned ones. Logging out is not detected; a new session gets a new asid.
struct LoginSession;

impl Condition for LoginSession {
    fn kind(&self) -> ConditionKind {
        ConditionKind::State
    }

    /// The value depends on the peer, so it comes from the chain, not from an observation.
    fn observe(&self) -> Result<Option<Value>, ObserveError> {
        Ok(None)
    }

    fn validate_args(&self, args: Option<&Value>) -> Result<(), String> {
        no_args(args)
    }

    fn pin(
        &self,
        args: Option<&Value>,
        _obs: &Observed<'_>,
        chain: &ProcessChain,
    ) -> Result<Option<Value>, PinError> {
        no_args(args).map_err(|reason| PinError::InvalidArgs { reason })?;
        login_session(chain).map(Some).ok_or(PinError::Unobservable)
    }

    fn check(
        &self,
        _args: Option<&Value>,
        pinned: Option<&Value>,
        _obs: &Observed<'_>,
        chain: &ProcessChain,
    ) -> bool {
        pinned.is_some() && login_session(chain).as_ref() == pinned
    }

    fn advance(&self, _pinned: Option<&Value>) -> Option<Value> {
        None
    }
}

/// `{boot_uuid, asid}` of the target of the chain; `None` without an asid.
fn login_session(chain: &ProcessChain) -> Option<Value> {
    let asid = chain.processes().first()?.identity.asid?;
    Some(json!({ "boot_uuid": chain.boot_uuid, "asid": asid }))
}

fn no_args(args: Option<&Value>) -> Result<(), String> {
    match args {
        None => Ok(()),
        Some(_) => Err("takes no arguments".to_owned()),
    }
}

/// `os.console_user` (lifetime), `os.not_remote` and `os.console_active` (state): the APIs that tell whether an asid is the console's, whether the screen is locked, and when the console user switched are not settled yet.
///
/// Until they are, observing fails (`Err`), so a grant using one of them is undecidable in every evaluation, and pinning fails with `Unobservable`, so no such grant is made.
struct Unsettled {
    kind: ConditionKind,
}

impl Condition for Unsettled {
    fn kind(&self) -> ConditionKind {
        self.kind
    }

    fn observe(&self) -> Result<Option<Value>, ObserveError> {
        Err(ObserveError {
            reason: "not implemented: the API to read it is not settled yet".to_owned(),
        })
    }

    fn validate_args(&self, args: Option<&Value>) -> Result<(), String> {
        no_args(args)
    }

    fn pin(
        &self,
        args: Option<&Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<Value>, PinError> {
        no_args(args).map_err(|reason| PinError::InvalidArgs { reason })?;
        Err(PinError::Unobservable)
    }

    fn check(
        &self,
        _args: Option<&Value>,
        _pinned: Option<&Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        false
    }

    fn advance(&self, _pinned: Option<&Value>) -> Option<Value> {
        None
    }
}
