//! The built-in conditions `until`, `age`, `uses` and `time.window`: their arguments, pin, check and advance, and `EvalContext::capture`.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use chrono::{Local, TimeZone};
use common::{NOW, at, chain, condition, process};
use procline_acl::{
    Condition, ConditionKind, EvalContext, Item, ObserveError, Observed, PinError, Vocabulary,
};
use procline_core::ProcessChain;
use serde_json::{Value, json};

/// What a built-in condition sees when nothing is observed for it.
fn unobserved(now: SystemTime) -> Observed<'static> {
    Observed {
        now,
        value: Ok(None),
    }
}

fn one_process() -> ProcessChain {
    chain(vec![process(1)])
}

// until: 引数は RFC 3339 の時刻だけを受け、pin 値はそれを UTC に直した時刻。時刻以外 (期間や数値) と引数なしは不正。
#[test]
fn until_pins_the_time_in_utc() {
    let vocab = Vocabulary::builtin();
    let until = condition(&vocab, "until");
    assert_eq!(until.kind(), ConditionKind::Lifetime);
    assert_eq!(until.observe(), Ok(None));
    let pinned = until.pin(
        Some(&json!("2026-11-08T13:00:00+09:00")),
        &unobserved(at(NOW)),
        &one_process(),
    );
    assert_eq!(pinned, Ok(Some(json!("2026-11-08T04:00:00Z"))));
    for invalid in [json!("1h"), json!(1_794_110_400), json!("2026-11-08 13:00")] {
        assert!(until.validate_args(Some(&invalid)).is_err(), "{invalid}");
        assert!(matches!(
            until.pin(Some(&invalid), &unobserved(at(NOW)), &one_process()),
            Err(PinError::InvalidArgs { .. })
        ));
    }
    assert!(until.validate_args(None).is_err());
}

// until の check は now が pin 値より前の間だけ真。ちょうどその時刻で偽になり、pin 値が無い・読めないときも偽 (失効する側)。advance は何も変えない。
#[test]
fn until_holds_before_the_pinned_time() {
    let vocab = Vocabulary::builtin();
    let until = condition(&vocab, "until");
    let pinned = json!("2026-11-08T04:00:00Z");
    let chain = one_process();
    let check = |now, pinned: Option<&Value>| until.check(None, pinned, &unobserved(now), &chain);
    assert!(check(at(NOW - 1), Some(&pinned)));
    assert!(!check(at(NOW), Some(&pinned)));
    assert!(!check(at(NOW + 1), Some(&pinned)));
    assert!(!check(at(NOW - 1), None));
    assert!(!check(at(NOW - 1), Some(&json!("tomorrow"))));
    assert_eq!(until.advance(Some(&pinned)), None);
}

// age: pin 値は now + 期間の時刻で、until の pin 値と同じ形になる (grant ではこれを until として持つ)。
#[test]
fn age_pins_now_plus_the_duration() {
    let vocab = Vocabulary::builtin();
    let age = condition(&vocab, "age");
    assert_eq!(age.kind(), ConditionKind::Lifetime);
    assert_eq!(age.observe(), Ok(None));
    let chain = one_process();
    let pin = |args: Value| age.pin(Some(&args), &unobserved(at(NOW)), &chain);
    assert_eq!(pin(json!("1h")), Ok(Some(json!("2026-11-08T05:00:00Z"))));
    assert_eq!(pin(json!("30m")), Ok(Some(json!("2026-11-08T04:30:00Z"))));
    assert_eq!(pin(json!("7d")), Ok(Some(json!("2026-11-15T04:00:00Z"))));
    let pinned = pin(json!("1h")).unwrap().unwrap();
    assert!(age.check(None, Some(&pinned), &unobserved(at(NOW + 3599)), &chain));
    assert!(!age.check(None, Some(&pinned), &unobserved(at(NOW + 3600)), &chain));
    assert_eq!(age.advance(Some(&pinned)), None);
}

// age の期間は整数 + 単位 (s / m / h / d) の文字列だけを受ける。不正なら validate_args も pin も拒否する (pin は InvalidArgs)。
#[test]
fn age_rejects_invalid_durations() {
    let vocab = Vocabulary::builtin();
    let age = condition(&vocab, "age");
    assert!(age.validate_args(Some(&json!("7d"))).is_ok());
    for invalid in [
        json!("0h"),
        json!("1w"),
        json!("h"),
        json!("1.5h"),
        json!(3600),
    ] {
        assert!(age.validate_args(Some(&invalid)).is_err(), "{invalid}");
        assert!(matches!(
            age.pin(Some(&invalid), &unobserved(at(NOW)), &one_process()),
            Err(PinError::InvalidArgs { .. })
        ));
    }
    assert!(age.validate_args(None).is_err());
}

// uses: pin 値は引数の N、check は残りが 1 以上の間だけ真、advance は 1 減らす。0 は減らさない (check が偽なので採用されない)。
#[test]
fn uses_counts_down_to_zero() {
    let vocab = Vocabulary::builtin();
    let uses = condition(&vocab, "uses");
    assert_eq!(uses.kind(), ConditionKind::Lifetime);
    assert_eq!(uses.observe(), Ok(None));
    let chain = one_process();
    let obs = unobserved(at(NOW));
    assert_eq!(uses.pin(Some(&json!(3)), &obs, &chain), Ok(Some(json!(3))));
    assert!(uses.check(None, Some(&json!(1)), &obs, &chain));
    assert!(!uses.check(None, Some(&json!(0)), &obs, &chain));
    assert!(!uses.check(None, None, &obs, &chain));
    assert_eq!(uses.advance(Some(&json!(3))), Some(json!(2)));
    assert_eq!(uses.advance(Some(&json!(1))), Some(json!(0)));
    assert_eq!(uses.advance(Some(&json!(0))), None);
}

// uses の引数は正の整数だけ。0、負数、文字列、引数なしは不正。
#[test]
fn uses_takes_a_positive_integer() {
    let vocab = Vocabulary::builtin();
    let uses = condition(&vocab, "uses");
    for invalid in [json!(0), json!(-1), json!("3"), json!(1.5)] {
        assert!(uses.validate_args(Some(&invalid)).is_err(), "{invalid}");
        assert!(matches!(
            uses.pin(Some(&invalid), &unobserved(at(NOW)), &one_process()),
            Err(PinError::InvalidArgs { .. })
        ));
    }
    assert!(uses.validate_args(None).is_err());
}

/// The instant of the local date and time.
fn local(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> SystemTime {
    SystemTime::from(
        Local
            .with_ymd_and_hms(year, month, day, hour, minute, 0)
            .single()
            .expect("an unambiguous local time"),
    )
}

// time.window: 指定の曜日の from 以上 to 未満のローカル時刻だけ真。to ちょうどは偽、別の曜日は偽。pin 値は持たず、失効もしない (状態型)。
#[test]
fn time_window_holds_on_the_days_within_the_hours() {
    let vocab = Vocabulary::builtin();
    let window = condition(&vocab, "time.window");
    assert_eq!(window.kind(), ConditionKind::State);
    let args = json!({"days": ["mon", "wed"], "from": "09:00", "to": "18:00"});
    let chain = one_process();
    assert_eq!(
        window.pin(Some(&args), &unobserved(at(NOW)), &chain),
        Ok(None)
    );
    // 2026-11-09 は月曜、2026-11-10 は火曜。
    let check = |now| window.check(Some(&args), None, &unobserved(now), &chain);
    assert!(check(local(2026, 11, 9, 9, 0)));
    assert!(check(local(2026, 11, 9, 17, 59)));
    assert!(!check(local(2026, 11, 9, 18, 0)));
    assert!(!check(local(2026, 11, 9, 8, 59)));
    assert!(!check(local(2026, 11, 10, 10, 0)));
    assert_eq!(window.advance(None), None);
}

// time.window の不正な引数は validate_args と pin が拒否し、check は真にしない。
#[test]
fn time_window_rejects_invalid_arguments() {
    let vocab = Vocabulary::builtin();
    let window = condition(&vocab, "time.window");
    let invalid = json!({"days": ["mon"], "from": "18:00", "to": "09:00"});
    assert!(window.validate_args(Some(&invalid)).is_err());
    assert!(matches!(
        window.pin(Some(&invalid), &unobserved(at(NOW)), &one_process()),
        Err(PinError::InvalidArgs { .. })
    ));
    assert!(!window.check(
        Some(&invalid),
        None,
        &unobserved(local(2026, 11, 9, 12, 0)),
        &one_process()
    ));
}

/// A condition that counts its observations and returns a fixed value.
struct CountingObserve {
    calls: Arc<AtomicUsize>,
    result: Result<Option<Value>, ObserveError>,
}

impl Condition for CountingObserve {
    fn kind(&self) -> ConditionKind {
        ConditionKind::State
    }
    fn observe(&self) -> Result<Option<Value>, ObserveError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
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
        None
    }
}

// capture は全 condition の observe を 1 回ずつ呼び、結果 (値も Err も) を key ごとに保存する。now は呼んだ時点の時計。
#[test]
fn capture_observes_every_condition_once() {
    let mut vocab = Vocabulary::builtin();
    let value_calls = Arc::new(AtomicUsize::new(0));
    let error_calls = Arc::new(AtomicUsize::new(0));
    let failure = ObserveError {
        reason: "sysctl failed".to_owned(),
    };
    vocab
        .register(Item::condition(
            "app.epoch",
            CountingObserve {
                calls: Arc::clone(&value_calls),
                result: Ok(Some(json!(12))),
            },
        ))
        .unwrap();
    vocab
        .register(Item::condition(
            "app.broken",
            CountingObserve {
                calls: Arc::clone(&error_calls),
                result: Err(failure.clone()),
            },
        ))
        .unwrap();
    let before = SystemTime::now();
    let ctx = EvalContext::capture(&vocab);
    let after = SystemTime::now();
    assert_eq!(value_calls.load(Ordering::SeqCst), 1);
    assert_eq!(error_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ctx.observed("app.epoch"), Ok(Some(&json!(12))));
    assert_eq!(ctx.observed("app.broken"), Err(&failure));
    assert_eq!(ctx.observed("until"), Ok(None));
    assert!(before <= ctx.now() && ctx.now() <= after);
}
