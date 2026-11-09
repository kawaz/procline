//! `Vocabulary`: the built-in items, registering items (duplicates and namespaces), and `Vocabulary::class`.

mod common;

use common::{named, target};
use procline_acl::{
    Condition, ConditionKind, Item, ItemKind, Literal, MatchValue, ObserveError, Observed,
    PinError, RegisterError, Vocabulary,
};
use procline_core::{BinaryPin, PathMeta, Pinnable, ProcessChain, ProcessInfo, Strength};

/// A state condition that does nothing; only its registration is under test.
struct Inert;

impl Condition for Inert {
    fn kind(&self) -> ConditionKind {
        ConditionKind::State
    }
    fn observe(&self) -> Result<Option<serde_json::Value>, ObserveError> {
        Ok(None)
    }
    fn validate_args(&self, _args: Option<&serde_json::Value>) -> Result<(), String> {
        Ok(())
    }
    fn pin(
        &self,
        _args: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, PinError> {
        Ok(None)
    }
    fn check(
        &self,
        _args: Option<&serde_json::Value>,
        _pinned: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        true
    }
    fn advance(&self, _pinned: Option<&serde_json::Value>) -> Option<serde_json::Value> {
        None
    }
}

// builtin() は OS に依らない項目だけを持つ: matcher の項目 10 個と、until / age / uses / time.window の条件。os.* は収集側の crate が提供し、アプリが register で足すので入っていない。
#[test]
fn builtin_has_the_os_independent_items() {
    let vocab = Vocabulary::builtin();
    for key in [
        "process",
        "binary",
        "uid",
        "gid",
        "path",
        "cwd",
        "argv",
        "name",
        "tty",
        "responsible",
    ] {
        assert!(
            matches!(vocab.get(key).map(Item::kind), Some(ItemKind::Matcher(_))),
            "{key} is a matcher item"
        );
    }
    // until / age / uses は一度偽になれば戻らない寿命型、time.window は偽の間だけ当たらない状態型。
    for (key, kind) in [
        ("until", ConditionKind::Lifetime),
        ("age", ConditionKind::Lifetime),
        ("uses", ConditionKind::Lifetime),
        ("time.window", ConditionKind::State),
    ] {
        assert_eq!(
            vocab.get(key).and_then(Item::condition_kind),
            Some(kind),
            "{key}"
        );
    }
    assert!(vocab.get("os.session").is_none());
}

// アプリの項目は app.、OS の状態と世代は os. の名前で足せる。
#[test]
fn register_accepts_app_and_os_keys() {
    let mut vocab = Vocabulary::builtin();
    assert_eq!(
        vocab.register(Item::matcher_fn("app.workspace", Strength::Weak, |_, _| {
            true
        })),
        Ok(())
    );
    assert_eq!(
        vocab.register(Item::condition("os.not_remote", Inert)),
        Ok(())
    );
    assert!(vocab.get("app.workspace").is_some());
    assert!(vocab.get("os.not_remote").is_some());
}

// 同じ key を 2 度登録すると、後の登録が前の実装を黙って置き換えて照合の意味が変わるので、エラーにする。組み込みの key も同じ。
#[test]
fn register_rejects_a_duplicate_key() {
    let mut vocab = Vocabulary::builtin();
    vocab
        .register(Item::condition("app.unlock", Inert))
        .unwrap();
    assert_eq!(
        vocab.register(Item::condition("app.unlock", Inert)),
        Err(RegisterError::Duplicate {
            key: "app.unlock".to_owned()
        })
    );
}

// 接頭辞なし (プロセス自身の属性と until / age / uses) と time. は組み込みの語彙の名前空間で、register では足せない。接頭辞だけで名前の無い key も不正。組み込みの key を足そうとしたときも、重複より先に名前空間の違反になる。
#[test]
fn register_rejects_keys_outside_the_namespaces() {
    let mut vocab = Vocabulary::builtin();
    for key in [
        "workspace",
        "time.holiday",
        "app.",
        "os.",
        "application.x",
        "process",
    ] {
        assert_eq!(
            vocab.register(Item::condition(key, Inert)),
            Err(RegisterError::Namespace {
                key: key.to_owned()
            }),
            "{key}"
        );
    }
}

// class は登録された matcher の項目が値 (とプロセス) から決めたクラスを返す。条件の項目と未登録の key は None。
#[test]
fn class_delegates_to_the_matcher_item() {
    let vocab = Vocabulary::builtin();
    let team = MatchValue::Binary(BinaryPin {
        team_id: Some(Pinnable::Pin),
        digest: None,
        signing_id: None,
        bundle_id: None,
        cdhash: None,
    });
    assert_eq!(vocab.class("binary", &team, None), Some(Strength::Strong));
    let path = MatchValue::Exact(Literal::Text("/bin/zsh".to_owned()));
    let protected = ProcessInfo {
        path_meta: Some(PathMeta {
            owner_uid: 0,
            writable_by_user: false,
        }),
        ..named(1, "zsh")
    };
    assert_eq!(vocab.class("path", &path, None), Some(Strength::Medium));
    assert_eq!(
        vocab.class("path", &path, Some(&protected)),
        Some(Strength::Strong)
    );
    assert_eq!(vocab.class("until", &MatchValue::Pin, None), None);
    assert_eq!(vocab.class("app.unknown", &MatchValue::Pin, None), None);
}

// matcher_fn で登録したクロージャの項目は、値によらず登録時に与えたクラスを返し、照合はクロージャに任せる。
#[test]
fn matcher_fn_has_a_constant_class() {
    let mut vocab = Vocabulary::default();
    vocab
        .register(Item::matcher_fn("app.zsh", Strength::Medium, |t, _| {
            t.info.name.as_deref() == Some("zsh")
        }))
        .unwrap();
    assert_eq!(
        vocab.class("app.zsh", &MatchValue::Pin, None),
        Some(Strength::Medium)
    );
    let Some(ItemKind::Matcher(m)) = vocab.get("app.zsh").map(Item::kind) else {
        panic!("app.zsh is a matcher item");
    };
    assert!(m.matches(target(&named(1, "zsh")), &MatchValue::Pin));
    assert!(!m.matches(target(&named(1, "bash")), &MatchValue::Pin));
}
