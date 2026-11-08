//! The `os.*` items: `os.session` against the epochs of the machine running the tests, `os.login_session` on synthetic chains, and the items whose APIs are not settled.

use std::process::Command;
use std::time::SystemTime;

use procline_acl::{
    Condition, ConditionKind, EvalContext, ItemKind, Observed, PinError, Vocabulary,
};
use procline_core::{Identity, ProcessChain, ProcessInfo};
use procline_macos::os_items;
use serde_json::{Value, json};

fn vocabulary() -> Vocabulary {
    let mut vocab = Vocabulary::builtin();
    for item in os_items() {
        vocab.register(item).unwrap();
    }
    vocab
}

fn condition<'v>(vocab: &'v Vocabulary, key: &str) -> &'v dyn Condition {
    match vocab.get(key).map(|item| item.kind()) {
        Some(ItemKind::Condition(condition)) => condition.as_ref(),
        _ => panic!("{key:?} is not a condition item"),
    }
}

/// The output of `sysctl -n <name>`, trimmed.
fn sysctl(name: &str) -> String {
    let output = Command::new("/usr/sbin/sysctl")
        .args(["-n", name])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// The seconds of `sysctl -n kern.waketime`, printed as `{ sec = N, usec = M } <date>`.
fn wake_secs() -> i64 {
    let text = sysctl("kern.waketime");
    let sec = text
        .split("sec = ")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .unwrap_or_else(|| panic!("unexpected kern.waketime: {text}"));
    sec.trim().parse().unwrap()
}

fn chain_with_asid(boot_uuid: &str, asid: Option<u32>) -> ProcessChain {
    let process = ProcessInfo {
        identity: Identity {
            audit_token: None,
            unique_id: Some(1),
            parent_unique_id: None,
            pid: 100,
            start_time: None,
            asid,
        },
        credentials: None,
        code_signing: None,
        path: None,
        path_meta: None,
        digest: None,
        bundle: None,
        responsible: None,
        name: None,
        argv: None,
        cwd: None,
        tty: None,
        env: None,
        icon_png: None,
    };
    ProcessChain::new(vec![process], boot_uuid.to_owned(), None)
}

fn observed(value: &Value) -> Observed<'_> {
    Observed {
        now: SystemTime::now(),
        value: Ok(Some(value)),
    }
}

// os.session の observe は実機の kern.bootsessionuuid と kern.waketime の秒を {boot, awake} で返し、unlocked は含めない (取得 API が未確定)。EvalContext::capture も同じ値を key に保存する。
#[test]
fn session_observes_boot_and_awake_of_this_machine() {
    let vocab = vocabulary();
    let session = condition(&vocab, "os.session");
    assert_eq!(session.kind(), ConditionKind::Lifetime);
    let expected = json!({ "boot": sysctl("kern.bootsessionuuid"), "awake": wake_secs() });
    assert_eq!(session.observe(), Ok(Some(expected.clone())));
    let ctx = EvalContext::capture(&vocab);
    assert_eq!(ctx.observed("os.session"), Ok(Some(&expected)));
}

// pin は引数の段階以下の field を写す (boot は boot だけ、awake は boot と awake)。観測値に無い段階 (unlocked) や観測値が無いときは Unobservable、不正な段階は InvalidArgs。
#[test]
fn session_pins_the_levels_up_to_the_argument() {
    let vocab = vocabulary();
    let session = condition(&vocab, "os.session");
    let chain = chain_with_asid("BOOT", None);
    let now = json!({ "boot": "BOOT", "awake": 1_793_615_747 });
    let pin = |level: &str| session.pin(Some(&json!(level)), &observed(&now), &chain);
    assert_eq!(pin("boot"), Ok(Some(json!({ "boot": "BOOT" }))));
    assert_eq!(
        pin("awake"),
        Ok(Some(json!({ "boot": "BOOT", "awake": 1_793_615_747 })))
    );
    assert_eq!(pin("unlocked"), Err(PinError::Unobservable));
    assert!(matches!(pin("asleep"), Err(PinError::InvalidArgs { .. })));
    let nothing = Observed {
        now: SystemTime::now(),
        value: Ok(None),
    };
    assert_eq!(
        session.pin(Some(&json!("boot")), &nothing, &chain),
        Err(PinError::Unobservable)
    );
    assert!(session.validate_args(Some(&json!("awake"))).is_ok());
    assert!(session.validate_args(None).is_err());
}

// check は pin 値の field が全部観測値にあって一致するときだけ真。起床 (awake が変わる) で awake の grant は偽、boot の grant は真のまま。再起動 (boot が変わる) と期間の外 (field が欠ける) では偽。
#[test]
fn session_holds_while_the_pinned_epochs_stay() {
    let vocab = vocabulary();
    let session = condition(&vocab, "os.session");
    let chain = chain_with_asid("BOOT", None);
    let boot = json!({ "boot": "BOOT" });
    let awake = json!({ "boot": "BOOT", "awake": 100 });
    let check =
        |pinned: &Value, now: &Value| session.check(None, Some(pinned), &observed(now), &chain);
    assert!(check(&awake, &json!({ "boot": "BOOT", "awake": 100 })));
    let woke = json!({ "boot": "BOOT", "awake": 200 });
    assert!(!check(&awake, &woke));
    assert!(check(&boot, &woke));
    assert!(!check(&boot, &json!({ "boot": "REBOOTED", "awake": 100 })));
    assert!(!check(&awake, &json!({ "boot": "BOOT" })));
    assert!(!check(&json!({}), &woke));
    assert_eq!(session.advance(Some(&awake)), None);
}

// os.login_session は状態型で、pin は列の boot UUID と対象の asid の組、check は同じ boot の同じ asid の相手だけ真。asid が取れなければ Unobservable。
#[test]
fn login_session_pins_the_boot_and_asid_of_the_target() {
    let vocab = vocabulary();
    let login = condition(&vocab, "os.login_session");
    assert_eq!(login.kind(), ConditionKind::State);
    assert_eq!(login.observe(), Ok(None));
    let nothing = Observed {
        now: SystemTime::now(),
        value: Ok(None),
    };
    let console = chain_with_asid("BOOT", Some(100_001));
    let pinned = login.pin(None, &nothing, &console).unwrap().unwrap();
    assert_eq!(pinned, json!({ "boot_uuid": "BOOT", "asid": 100_001 }));
    assert!(login.check(None, Some(&pinned), &nothing, &console));
    let other_session = chain_with_asid("BOOT", Some(100_002));
    assert!(!login.check(None, Some(&pinned), &nothing, &other_session));
    let after_restart = chain_with_asid("REBOOTED", Some(100_001));
    assert!(!login.check(None, Some(&pinned), &nothing, &after_restart));
    assert_eq!(
        login.pin(None, &nothing, &chain_with_asid("BOOT", None)),
        Err(PinError::Unobservable)
    );
    assert!(login.validate_args(Some(&json!("x"))).is_err());
}

// 取得 API が未確定の項目 (os.console_user / os.not_remote / os.console_active) は、observe が失敗し (grant は判定不能)、pin は Unobservable (grant を作れない)。
#[test]
fn unsettled_items_fail_to_observe_and_to_pin() {
    let vocab = vocabulary();
    for (key, kind) in [
        ("os.console_user", ConditionKind::Lifetime),
        ("os.not_remote", ConditionKind::State),
        ("os.console_active", ConditionKind::State),
    ] {
        let item = condition(&vocab, key);
        assert_eq!(item.kind(), kind, "{key}");
        assert!(item.observe().is_err(), "{key}");
        let failed = item.observe().unwrap_err();
        let obs = Observed {
            now: SystemTime::now(),
            value: Err(&failed),
        };
        assert_eq!(
            item.pin(None, &obs, &chain_with_asid("BOOT", Some(1))),
            Err(PinError::Unobservable),
            "{key}"
        );
    }
}
