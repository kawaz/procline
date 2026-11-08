//! The built-in conditions independent of the OS: `until`, `age`, `uses` and `time.window`.
//!
//! Times are RFC 3339 strings (`"2026-11-08T13:00:00+09:00"`); a pin value is written in UTC (`"2026-11-08T04:00:00Z"`, with a fraction of a second when it has one).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Datelike, Local, SecondsFormat, Timelike, Utc, Weekday};
use procline_core::ProcessChain;

use crate::context::Observed;
use crate::vocabulary::{Condition, ConditionKind, ObserveError, PinError};

/// `until`: the grant lives until the time given as its argument.
///
/// The argument and the pin value are RFC 3339 times; the pin value is the argument in UTC. `check` holds while `now` is before it.
pub(crate) struct Until;

/// `age`: the grant lives for the duration given as its argument; a grant holds it as an `until`.
///
/// The argument is a positive integer followed by a unit, `s` (seconds), `m` (minutes), `h` (hours) or `d` (days): `"30m"`, `"1h"`, `"7d"`. `pin` returns the time `now + duration` in the form of an `until` pin value, and `Policy::grant` stores it under the key `until`.
pub(crate) struct Age;

/// `uses`: the grant can be adopted the number of times given as its argument.
///
/// The argument is a positive integer N. The pin value is the remaining count: `check` holds while it is above 0, and `advance` lowers it by 1.
pub(crate) struct Uses;

/// `time.window`: holds on the days of the week and the hours given as its argument, in the local time of the host.
///
/// The argument is `{"days": [...], "from": "HH:MM", "to": "HH:MM"}`:
///
/// - `days`: the days of the week, out of `"mon"`, `"tue"`, `"wed"`, `"thu"`, `"fri"`, `"sat"`, `"sun"`; at least one.
/// - `from` / `to`: the hours as `HH:MM`, holding from `from` (inclusive) to `to` (exclusive) on each of the days. `from` is before `to`; `to` may be `"24:00"` for the end of the day.
///
/// A window across midnight is written as two rules (conditions are ANDed, alternatives are separate rules).
pub(crate) struct TimeWindow;

impl Condition for Until {
    fn kind(&self) -> ConditionKind {
        ConditionKind::Lifetime
    }

    /// The clock decides, so there is nothing to observe.
    fn observe(&self) -> Result<Option<serde_json::Value>, ObserveError> {
        Ok(None)
    }

    fn validate_args(&self, args: Option<&serde_json::Value>) -> Result<(), String> {
        until_args(args).map(drop)
    }

    fn pin(
        &self,
        args: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, PinError> {
        let until = until_args(args).map_err(|reason| PinError::InvalidArgs { reason })?;
        time_value(until)
            .map(Some)
            .map_err(|reason| PinError::InvalidArgs { reason })
    }

    fn check(
        &self,
        _args: Option<&serde_json::Value>,
        pinned: Option<&serde_json::Value>,
        obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        before_pinned(pinned, obs.now)
    }

    fn advance(&self, _pinned: Option<&serde_json::Value>) -> Option<serde_json::Value> {
        None
    }
}

impl Condition for Age {
    fn kind(&self) -> ConditionKind {
        ConditionKind::Lifetime
    }

    /// The clock decides, so there is nothing to observe.
    fn observe(&self) -> Result<Option<serde_json::Value>, ObserveError> {
        Ok(None)
    }

    fn validate_args(&self, args: Option<&serde_json::Value>) -> Result<(), String> {
        age_args(args).map(drop)
    }

    fn pin(
        &self,
        args: Option<&serde_json::Value>,
        obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, PinError> {
        let invalid = |reason| PinError::InvalidArgs { reason };
        let duration = age_args(args).map_err(invalid)?;
        let until = obs
            .now
            .checked_add(duration)
            .ok_or_else(|| "the duration ends beyond the representable time".to_owned())
            .map_err(invalid)?;
        time_value(until).map(Some).map_err(invalid)
    }

    /// The same as `until`'s; a grant holds an `age` as an `until`, so evaluation calls `until`'s.
    fn check(
        &self,
        _args: Option<&serde_json::Value>,
        pinned: Option<&serde_json::Value>,
        obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        before_pinned(pinned, obs.now)
    }

    fn advance(&self, _pinned: Option<&serde_json::Value>) -> Option<serde_json::Value> {
        None
    }
}

impl Condition for Uses {
    fn kind(&self) -> ConditionKind {
        ConditionKind::Lifetime
    }

    /// The count is in the pin value, so there is nothing to observe.
    fn observe(&self) -> Result<Option<serde_json::Value>, ObserveError> {
        Ok(None)
    }

    fn validate_args(&self, args: Option<&serde_json::Value>) -> Result<(), String> {
        uses_args(args).map(drop)
    }

    fn pin(
        &self,
        args: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, PinError> {
        let count = uses_args(args).map_err(|reason| PinError::InvalidArgs { reason })?;
        Ok(Some(serde_json::Value::from(count)))
    }

    fn check(
        &self,
        _args: Option<&serde_json::Value>,
        pinned: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        remaining(pinned).is_some_and(|count| count > 0)
    }

    /// One use fewer. A pin value that is not a positive count is left as is; `check` is false for it, so such a grant is never adopted.
    fn advance(&self, pinned: Option<&serde_json::Value>) -> Option<serde_json::Value> {
        remaining(pinned)
            .and_then(|count| count.checked_sub(1))
            .map(serde_json::Value::from)
    }
}

impl Condition for TimeWindow {
    fn kind(&self) -> ConditionKind {
        ConditionKind::State
    }

    /// The clock decides, so there is nothing to observe.
    fn observe(&self) -> Result<Option<serde_json::Value>, ObserveError> {
        Ok(None)
    }

    fn validate_args(&self, args: Option<&serde_json::Value>) -> Result<(), String> {
        Window::parse(args).map(drop)
    }

    /// A state condition on the clock: nothing to pin. Only the arguments are checked.
    fn pin(
        &self,
        args: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, PinError> {
        Window::parse(args).map_err(|reason| PinError::InvalidArgs { reason })?;
        Ok(None)
    }

    /// Whether `now`, in the local time of the host, falls on one of the days within the hours. Invalid arguments never hold.
    fn check(
        &self,
        args: Option<&serde_json::Value>,
        _pinned: Option<&serde_json::Value>,
        obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        let Ok(window) = Window::parse(args) else {
            return false;
        };
        utc(obs.now).is_ok_and(|now| window.contains(&now.with_timezone(&Local)))
    }

    fn advance(&self, _pinned: Option<&serde_json::Value>) -> Option<serde_json::Value> {
        None
    }
}

/// The time an `until` argument or pin value names.
pub(crate) fn parse_time(value: &serde_json::Value) -> Result<SystemTime, String> {
    let text = value
        .as_str()
        .ok_or_else(|| "takes an RFC 3339 time string".to_owned())?;
    DateTime::parse_from_rfc3339(text)
        .map(SystemTime::from)
        .map_err(|err| format!("{text:?} is not an RFC 3339 time: {err}"))
}

/// The duration of an `age` argument.
pub(crate) fn age_args(args: Option<&serde_json::Value>) -> Result<Duration, String> {
    let text = args.and_then(serde_json::Value::as_str).ok_or_else(|| {
        "takes a duration string: a positive integer and a unit s, m, h or d (\"1h\")".to_owned()
    })?;
    parse_duration(text)
}

fn until_args(args: Option<&serde_json::Value>) -> Result<SystemTime, String> {
    let value = args.ok_or_else(|| "takes an RFC 3339 time string".to_owned())?;
    parse_time(value)
}

fn uses_args(args: Option<&serde_json::Value>) -> Result<u64, String> {
    args.and_then(serde_json::Value::as_u64)
        .filter(|count| *count > 0)
        .ok_or_else(|| "takes a positive integer, the number of uses".to_owned())
}

fn remaining(pinned: Option<&serde_json::Value>) -> Option<u64> {
    pinned.and_then(serde_json::Value::as_u64)
}

/// `now` is before the pinned time. A missing or unreadable pin value never holds, so the grant expires.
fn before_pinned(pinned: Option<&serde_json::Value>, now: SystemTime) -> bool {
    pinned
        .and_then(|value| parse_time(value).ok())
        .is_some_and(|until| now < until)
}

/// `"<n><unit>"` with a positive integer n and a unit s, m, h or d.
fn parse_duration(text: &str) -> Result<Duration, String> {
    let invalid = || {
        format!(
            "{text:?} is not a duration; write a positive integer and a unit s, m, h or d (\"1h\")"
        )
    };
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(invalid)?;
    let (digits, unit) = text.split_at(split);
    let count: u64 = digits.parse().map_err(|_| invalid())?;
    if count == 0 {
        return Err(format!("{text:?} is zero; give a positive duration"));
    }
    let seconds_per_unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(invalid()),
    };
    count
        .checked_mul(seconds_per_unit)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("{text:?} is too long"))
}

fn utc(time: SystemTime) -> Result<DateTime<Utc>, String> {
    let out_of_range = || "the time is outside the representable range".to_owned();
    let since = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| out_of_range())?;
    let secs = i64::try_from(since.as_secs()).map_err(|_| out_of_range())?;
    DateTime::from_timestamp(secs, since.subsec_nanos()).ok_or_else(out_of_range)
}

fn time_value(time: SystemTime) -> Result<serde_json::Value, String> {
    utc(time)
        .map(|time| serde_json::Value::String(time.to_rfc3339_opts(SecondsFormat::AutoSi, true)))
}

/// The parsed argument of `time.window`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Window {
    /// Indexed by `Weekday::num_days_from_monday`.
    days: [bool; 7],
    /// Minutes from midnight; `from < to <= 24 * 60`.
    from: u32,
    to: u32,
}

impl Window {
    fn parse(args: Option<&serde_json::Value>) -> Result<Self, String> {
        let shape =
            || "takes {\"days\": [\"mon\", …], \"from\": \"HH:MM\", \"to\": \"HH:MM\"}".to_owned();
        let object = args
            .and_then(serde_json::Value::as_object)
            .ok_or_else(shape)?;
        if let Some(unknown) = object
            .keys()
            .find(|key| !["days", "from", "to"].contains(&key.as_str()))
        {
            return Err(format!("unknown field {unknown:?}; {}", shape()));
        }
        let names = object
            .get("days")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(shape)?;
        if names.is_empty() {
            return Err("days is empty; give at least one day".to_owned());
        }
        let mut days = [false; 7];
        for name in names {
            let day = name.as_str().and_then(weekday).ok_or_else(|| {
                format!("{name} is not a day; write one of mon, tue, wed, thu, fri, sat, sun")
            })?;
            days[day.num_days_from_monday() as usize] = true;
        }
        let from = clock(object.get("from"), "from")?;
        let to = clock(object.get("to"), "to")?;
        if from >= 24 * 60 {
            return Err("from is 24:00; the window starts within the day".to_owned());
        }
        if from >= to {
            return Err(
                "from is not before to; write a window across midnight as two rules".to_owned(),
            );
        }
        Ok(Self { days, from, to })
    }

    fn contains(&self, local: &DateTime<Local>) -> bool {
        let minute = local.hour() * 60 + local.minute();
        self.days[local.weekday().num_days_from_monday() as usize]
            && self.from <= minute
            && minute < self.to
    }
}

fn weekday(name: &str) -> Option<Weekday> {
    Some(match name {
        "mon" => Weekday::Mon,
        "tue" => Weekday::Tue,
        "wed" => Weekday::Wed,
        "thu" => Weekday::Thu,
        "fri" => Weekday::Fri,
        "sat" => Weekday::Sat,
        "sun" => Weekday::Sun,
        _ => return None,
    })
}

/// `"HH:MM"` as minutes from midnight, `00:00` to `24:00`.
fn clock(value: Option<&serde_json::Value>, field: &str) -> Result<u32, String> {
    let invalid = || format!("{field} takes \"HH:MM\" from 00:00 to 24:00");
    let text = value
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?;
    let (hours, minutes) = text.split_once(':').ok_or_else(invalid)?;
    if hours.len() != 2 || minutes.len() != 2 {
        return Err(invalid());
    }
    let hours: u32 = hours.parse().map_err(|_| invalid())?;
    let minutes: u32 = minutes.parse().map_err(|_| invalid())?;
    if minutes >= 60 || hours > 24 || (hours == 24 && minutes != 0) {
        return Err(invalid());
    }
    Ok(hours * 60 + minutes)
}

#[cfg(test)]
mod tests {
    use super::{Window, parse_duration};
    use std::time::Duration;

    // 期間の書式: 整数 + 単位 (s / m / h / d) だけを受け、0・単位なし・未知の単位・符号・小数は不正。
    #[test]
    fn duration_takes_a_positive_integer_and_a_unit() {
        assert_eq!(parse_duration("30m"), Ok(Duration::from_secs(1800)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse_duration("7d"), Ok(Duration::from_secs(7 * 86_400)));
        assert_eq!(parse_duration("45s"), Ok(Duration::from_secs(45)));
        for invalid in [
            "0h",
            "1",
            "h",
            "1w",
            "-1h",
            "1.5h",
            "1 h",
            "",
            "99999999999999999999d",
        ] {
            assert!(parse_duration(invalid).is_err(), "{invalid:?}");
        }
    }

    // time.window の引数: 曜日は 1 つ以上、from < to、to だけ 24:00 を書ける、未知の field は不正。
    #[test]
    fn window_arguments_are_checked() {
        let parse = |args: serde_json::Value| Window::parse(Some(&args));
        assert!(
            parse(serde_json::json!({"days": ["mon"], "from": "09:00", "to": "24:00"})).is_ok()
        );
        for invalid in [
            serde_json::json!({"days": [], "from": "09:00", "to": "18:00"}),
            serde_json::json!({"days": ["monday"], "from": "09:00", "to": "18:00"}),
            serde_json::json!({"days": ["mon"], "from": "18:00", "to": "09:00"}),
            serde_json::json!({"days": ["mon"], "from": "09:00", "to": "09:00"}),
            serde_json::json!({"days": ["mon"], "from": "24:00", "to": "24:00"}),
            serde_json::json!({"days": ["mon"], "from": "9:00", "to": "18:00"}),
            serde_json::json!({"days": ["mon"], "from": "09:60", "to": "18:00"}),
            serde_json::json!({"days": ["mon"], "from": "09:00", "to": "24:01"}),
            serde_json::json!({"days": ["mon"], "from": "09:00"}),
            serde_json::json!({"days": ["mon"], "from": "09:00", "to": "18:00", "tz": "UTC"}),
            serde_json::json!("09:00-18:00"),
        ] {
            assert!(parse(invalid.clone()).is_err(), "{invalid}");
        }
        assert!(Window::parse(None).is_err());
    }
}
