//! The built-in matcher items of `Vocabulary::builtin()`: matching, the value shapes each item accepts, the class, and resolving placeholders.
//!
//! Every process here is synthetic (`common`); nothing calls the OS.

mod common;

use std::path::PathBuf;

use common::{BOOT, at_path, matcher, named, process, signature, signed, target, with_ids};
use procline_acl::{Literal, MatchTarget, MatchValue, ResolveError, Vocabulary};
use procline_core::{
    BinaryPin, CdHash, CodeSigning, PathMeta, Pinnable, ProcessIdentity, ProcessInfo,
    SignatureValidity, StartTime, Strength,
};

fn text(value: &str) -> MatchValue {
    MatchValue::Exact(Literal::Text(value.to_owned()))
}

fn int(value: i64) -> MatchValue {
    MatchValue::Exact(Literal::Integer(value))
}

fn glob(pattern: &str) -> MatchValue {
    MatchValue::Glob(pattern.to_owned())
}

fn regex(pattern: &str) -> MatchValue {
    MatchValue::Regex(pattern.to_owned())
}

fn field(value: &str) -> Option<Pinnable<String>> {
    Some(Pinnable::Value(value.to_owned()))
}

fn binary(pin: BinaryPin) -> MatchValue {
    MatchValue::Binary(pin)
}

fn no_fields() -> BinaryPin {
    BinaryPin {
        digest: None,
        team_id: None,
        signing_id: None,
        bundle_id: None,
        cdhash: None,
    }
}

fn identity_of(process: &ProcessInfo) -> ProcessIdentity {
    process.identity.process_identity(BOOT)
}

fn pinned(identity: ProcessIdentity) -> MatchValue {
    MatchValue::Process(Pinnable::Value(identity))
}

// ---------- process ----------
//
// `process` は「この個体のプロセス」。pin 値は grant を作ったときに取れた識別子 (boot_uuid、unique_id、pid、start_time) の複合で、照合は両側に揃っている識別子を全部比べ、全部一致したときだけ当たる。最も強い 1 つだけで比べると、再起動の後に同じ pid・unique_id が現れたときに取り違えるため、boot_uuid も必ず比べる。

// 承認したときと同じ個体 (全識別子が一致) には当たる。
#[test]
fn process_matches_the_same_individual() {
    let vocab = Vocabulary::builtin();
    let p = process(501);
    assert!(matcher(&vocab, "process").matches(target(&p), &pinned(identity_of(&p))));
}

// pid と起動時刻が同じでも unique_id が違えば別の個体。揃っている識別子はどれも一致を要する。
#[test]
fn process_rejects_a_different_unique_id() {
    let vocab = Vocabulary::builtin();
    let p = process(501);
    let mut other = identity_of(&p);
    other.unique_id = Some(99);
    assert!(!matcher(&vocab, "process").matches(target(&p), &pinned(other)));
}

// 再起動を跨ぐと pid も unique_id も起動時刻の秒も同じ値が再び現れ得る。boot_uuid が違えば当たらないことで、再起動前に承認した個体と取り違えない。
#[test]
fn process_rejects_another_boot() {
    let vocab = Vocabulary::builtin();
    let p = process(501);
    let mut before_restart = identity_of(&p);
    before_restart.boot_uuid = "OTHER-BOOT".to_owned();
    assert!(!matcher(&vocab, "process").matches(target(&p), &pinned(before_restart)));
}

// 片側に unique_id が無い (SPI が取れなかった) ときは比べられる pid と起動時刻の組で比べる。起動時刻が違えば pid の再利用なので当たらない。
#[test]
fn process_compares_only_identifiers_present_on_both_sides() {
    let vocab = Vocabulary::builtin();
    let p = process(501);
    let mut without_unique_id = identity_of(&p);
    without_unique_id.unique_id = None;
    assert!(matcher(&vocab, "process").matches(target(&p), &pinned(without_unique_id.clone())));
    let mut reused_pid = without_unique_id;
    reused_pid.start_time = Some(StartTime { secs: 1, micros: 0 });
    assert!(!matcher(&vocab, "process").matches(target(&p), &pinned(reused_pid)));
}

// pid だけしか比べられないときは当てない。pid は同じ起動の中でも再利用されるので、pid だけの一致は個体を特定しない (最悪でも pid と起動時刻の組の一致を見る)。
#[test]
fn process_needs_more_than_the_pid() {
    let vocab = Vocabulary::builtin();
    let p = process(501);
    let mut pid_only = identity_of(&p);
    pid_only.unique_id = None;
    pid_only.start_time = None;
    assert!(!matcher(&vocab, "process").matches(target(&p), &pinned(pid_only.clone())));
    // 照合側 (収集結果) に unique_id も起動時刻も無い場合も同じ。
    let mut bare = process(501);
    bare.identity.unique_id = None;
    bare.identity.start_time = None;
    assert!(!matcher(&vocab, "process").matches(target(&bare), &pinned(identity_of(&p))));
}

// placeholder は grant を作るときに resolve で実値に置き換える前提で、照合には使えない (当てると「どの個体でもよい」になる)。
#[test]
fn process_placeholder_never_matches() {
    let vocab = Vocabulary::builtin();
    let p = process(501);
    assert!(!matcher(&vocab, "process").matches(target(&p), &MatchValue::Process(Pinnable::Pin)));
}

// 値の形: placeholder か識別子の複合だけ。boot_uuid の空と pid だけの複合は、上の照合で決して当たらない値なので読み込みで弾く。
#[test]
fn process_validate_accepts_identities_and_the_placeholder() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "process");
    let p = process(501);
    assert_eq!(m.validate(&MatchValue::Process(Pinnable::Pin)), Ok(()));
    assert_eq!(m.validate(&pinned(identity_of(&p))), Ok(()));
    let mut no_boot = identity_of(&p);
    no_boot.boot_uuid = String::new();
    assert!(m.validate(&pinned(no_boot)).is_err());
    let mut pid_only = identity_of(&p);
    pid_only.unique_id = None;
    pid_only.start_time = None;
    assert!(m.validate(&pinned(pid_only)).is_err());
    // 単純項目の placeholder (MatchValue::Pin) と文字列・数値は process の値の形ではない。
    assert!(m.validate(&MatchValue::Pin).is_err());
    assert!(m.validate(&int(501)).is_err());
    assert!(m.validate(&text("501")).is_err());
}

// process は個体そのものを特定するので強。
#[test]
fn process_class_is_strong() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "process");
    assert_eq!(
        m.class(&MatchValue::Process(Pinnable::Pin), None),
        Strength::Strong
    );
    assert_eq!(
        m.class(&pinned(identity_of(&process(1))), None),
        Strength::Strong
    );
}

// placeholder は、照合したプロセスの識別子と chain の boot UUID の複合に置き換わる。具体値はそのまま返る。
#[test]
fn process_resolve_pins_identifiers_with_the_boot_uuid() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "process");
    let p = process(501);
    let resolved = m
        .resolve(&MatchValue::Process(Pinnable::Pin), target(&p))
        .unwrap();
    assert_eq!(resolved, pinned(identity_of(&p)));
    let MatchValue::Process(Pinnable::Value(identity)) = &resolved else {
        panic!("resolved to {resolved:?}");
    };
    assert_eq!(identity.boot_uuid, BOOT);
    let concrete = pinned(identity_of(&process(7)));
    assert_eq!(m.resolve(&concrete, target(&p)), Ok(concrete.clone()));
}

// ---------- responsible ----------
//
// 責任プロセスは ProcessInfo.responsible (個体の識別) を process と同じ規則で比べる。クラスは中。

#[test]
fn responsible_matches_the_responsible_individual() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "responsible");
    let terminal = process(400);
    let p = ProcessInfo {
        responsible: Some(identity_of(&terminal)),
        ..process(501)
    };
    // 責任プロセスの個体に当たり、自分自身の個体には当たらない。
    assert!(m.matches(target(&p), &pinned(identity_of(&terminal))));
    assert!(!m.matches(target(&p), &pinned(identity_of(&p))));
    // 責任プロセスが取れなかったプロセスにはどの値も当たらない。
    assert!(!m.matches(target(&process(501)), &pinned(identity_of(&terminal))));
}

#[test]
fn responsible_class_resolve_and_validate() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "responsible");
    assert_eq!(
        m.class(&MatchValue::Process(Pinnable::Pin), None),
        Strength::Medium
    );
    let terminal = process(400);
    let p = ProcessInfo {
        responsible: Some(identity_of(&terminal)),
        ..process(501)
    };
    assert_eq!(
        m.resolve(&MatchValue::Process(Pinnable::Pin), target(&p)),
        Ok(pinned(identity_of(&terminal)))
    );
    // 責任プロセスが無いプロセスでは placeholder を埋められない。
    assert_eq!(
        m.resolve(&MatchValue::Process(Pinnable::Pin), target(&process(501))),
        Err(ResolveError::ValueUnavailable { field: None })
    );
    assert!(m.validate(&text("x")).is_err());
}

// ---------- binary ----------
//
// binary は値にある field を全部検証する (AND)。署名由来の field (team_id、signing_id、bundle_id、cdhash) は、署名があって検証が通ったときだけ一致とみなす。検証の通らない署名の field はコードについて何も保証しないため。digest は ProcessInfo.digest (実行パスのファイルの内容のハッシュ) と比べ、署名に依らない。

fn claude() -> ProcessInfo {
    signed(
        process(600),
        signature("VWXYZ67890", "com.anthropic.claude-code"),
    )
}

#[test]
fn binary_matches_every_field_present() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "binary");
    let value = binary(BinaryPin {
        team_id: field("VWXYZ67890"),
        signing_id: field("com.anthropic.claude-code"),
        ..no_fields()
    });
    assert!(m.matches(target(&claude()), &value));
    // 1 つでも違えば当たらない (AND)。
    let other_team = binary(BinaryPin {
        team_id: field("ABCDE12345"),
        signing_id: field("com.anthropic.claude-code"),
        ..no_fields()
    });
    assert!(!m.matches(target(&claude()), &other_team));
}

// 署名の検証が通らない (改ざん等) プロセスは、field の値が同じでも当たらない。未署名も同じ。
#[test]
fn binary_signature_fields_need_a_verified_signature() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "binary");
    let value = binary(BinaryPin {
        team_id: field("VWXYZ67890"),
        ..no_fields()
    });
    let mut broken = signature("VWXYZ67890", "com.anthropic.claude-code");
    broken.validity = SignatureValidity::Invalid {
        reason: "modified".to_owned(),
    };
    assert!(!m.matches(target(&signed(process(600), broken)), &value));
    let unsigned = ProcessInfo {
        code_signing: Some(CodeSigning::Unsigned),
        ..process(600)
    };
    assert!(!m.matches(target(&unsigned), &value));
    assert!(!m.matches(target(&process(600)), &value));
}

// ad-hoc 署名は Team ID を持たない (None) ので、Team ID の条件には決して当たらない。
#[test]
fn binary_team_id_never_matches_adhoc() {
    let vocab = Vocabulary::builtin();
    let mut adhoc = signature("unused", "a.out");
    adhoc.team_id = None;
    adhoc.adhoc = true;
    let adhoc = signed(process(1), adhoc);
    for team_id in ["VWXYZ67890", ""] {
        let value = binary(BinaryPin {
            team_id: field(team_id),
            ..no_fields()
        });
        assert!(!matcher(&vocab, "binary").matches(target(&adhoc), &value));
    }
}

// bundle_id の照合元は署名で封印された Info.plist の値 (Signature.bundle_id) で、実行パスから遡って読む ProcessInfo.bundle (表示用、誰でも書ける) ではない。
#[test]
fn binary_bundle_id_is_the_sealed_one() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "binary");
    let value = binary(BinaryPin {
        team_id: field("VWXYZ67890"),
        signing_id: field("com.anthropic.claude-code"),
        bundle_id: field("com.anthropic.claude"),
        ..no_fields()
    });
    let mut sealed = signature("VWXYZ67890", "com.anthropic.claude-code");
    sealed.bundle_id = Some("com.anthropic.claude".to_owned());
    assert!(m.matches(target(&signed(process(600), sealed)), &value));
    let display_only = ProcessInfo {
        bundle: Some(procline_core::Bundle {
            id: Some("com.anthropic.claude".to_owned()),
            version: None,
        }),
        ..claude()
    };
    assert!(!m.matches(target(&display_only), &value));
}

// cdhash は署名の cdhash と比べる。
#[test]
fn binary_matches_cdhash() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "binary");
    let same = binary(BinaryPin {
        cdhash: Some(Pinnable::Value(CdHash([0xab; 20]))),
        ..no_fields()
    });
    assert!(m.matches(target(&claude()), &same));
    let other = binary(BinaryPin {
        cdhash: Some(Pinnable::Value(CdHash([0xcd; 20]))),
        ..no_fields()
    });
    assert!(!m.matches(target(&claude()), &other));
}

// digest は署名に依らず ProcessInfo.digest と比べる (未署名のバイナリの床)。digest と署名由来の field を併せれば両方を要する。
#[test]
fn binary_digest_does_not_need_a_signature() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "binary");
    let unsigned = ProcessInfo {
        digest: Some("sha256:00ff".to_owned()),
        ..process(700)
    };
    let digest = binary(BinaryPin {
        digest: field("sha256:00ff"),
        ..no_fields()
    });
    assert!(m.matches(target(&unsigned), &digest));
    assert!(!m.matches(target(&process(700)), &digest));
    let digest_and_team = binary(BinaryPin {
        digest: field("sha256:00ff"),
        team_id: field("VWXYZ67890"),
        ..no_fields()
    });
    assert!(!m.matches(target(&unsigned), &digest_and_team));
    let both = ProcessInfo {
        digest: Some("sha256:00ff".to_owned()),
        ..claude()
    };
    assert!(m.matches(target(&both), &digest_and_team));
}

// 妥当性の規則に反する値 (Team ID の無い signing_id) は、値が実物と一致していても当たらない。signing identifier は ad-hoc 署名でも名乗れるので、単独では何も特定しない。
#[test]
fn binary_invalid_value_never_matches() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "binary");
    let signing_only = binary(BinaryPin {
        signing_id: field("com.anthropic.claude-code"),
        ..no_fields()
    });
    assert!(!m.matches(target(&claude()), &signing_only));
    assert!(!m.matches(target(&claude()), &binary(no_fields())));
    assert!(!m.matches(target(&claude()), &text("VWXYZ67890")));
}

// placeholder の field は resolve で埋める前提で、照合には使えない。
#[test]
fn binary_placeholder_field_never_matches() {
    let vocab = Vocabulary::builtin();
    let value = binary(BinaryPin {
        team_id: Some(Pinnable::Pin),
        ..no_fields()
    });
    assert!(!matcher(&vocab, "binary").matches(target(&claude()), &value));
}

// クラスは値にある field のうち最も強いもの: 署名由来の field があれば強、digest だけなら中。placeholder でも、どの field に置かれているかで決まる。
#[test]
fn binary_class_is_the_strongest_field() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "binary");
    let cases = [
        (
            BinaryPin {
                team_id: Some(Pinnable::Pin),
                ..no_fields()
            },
            Strength::Strong,
        ),
        (
            BinaryPin {
                cdhash: Some(Pinnable::Value(CdHash([0; 20]))),
                ..no_fields()
            },
            Strength::Strong,
        ),
        (
            BinaryPin {
                digest: field("sha256:00"),
                ..no_fields()
            },
            Strength::Medium,
        ),
        (
            BinaryPin {
                digest: Some(Pinnable::Pin),
                ..no_fields()
            },
            Strength::Medium,
        ),
        (
            BinaryPin {
                digest: field("sha256:00"),
                team_id: field("T"),
                ..no_fields()
            },
            Strength::Strong,
        ),
    ];
    for (value, class) in cases {
        assert_eq!(m.class(&binary(value.clone()), None), class, "{value:?}");
    }
    // binary の形でない値 (不正) はルールを強く見せないよう弱。
    assert_eq!(m.class(&text("x"), None), Strength::Weak);
}

// validate は BinaryPin::validate の規則 (signing_id には team_id、bundle_id には両方、空は不正、placeholder も「ある」に数える) と、binary の形であることを検査する。
#[test]
fn binary_validate_applies_the_field_rules() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "binary");
    assert_eq!(
        m.validate(&binary(BinaryPin {
            signing_id: field("com.googlecode.iterm2"),
            team_id: Some(Pinnable::Pin),
            ..no_fields()
        })),
        Ok(())
    );
    assert!(
        m.validate(&binary(BinaryPin {
            signing_id: field("x"),
            ..no_fields()
        }))
        .is_err()
    );
    assert!(m.validate(&binary(no_fields())).is_err());
    assert!(m.validate(&MatchValue::Pin).is_err());
    assert!(m.validate(&glob("/x/*")).is_err());
}

// resolve は placeholder の field だけを照合したプロセスの実値で埋め、具体値の field はそのまま残す。
#[test]
fn binary_resolve_fills_placeholder_fields() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "binary");
    let value = binary(BinaryPin {
        signing_id: field("com.anthropic.claude-code"),
        team_id: Some(Pinnable::Pin),
        ..no_fields()
    });
    assert_eq!(
        m.resolve(&value, target(&claude())),
        Ok(binary(BinaryPin {
            signing_id: field("com.anthropic.claude-code"),
            team_id: field("VWXYZ67890"),
            ..no_fields()
        }))
    );
}

// 埋める値が無ければ、どの field が無いかを添えて失敗する (未署名に team_id: true、digest を取っていないのに digest: true)。検証の通らない署名の値でも埋めない。
#[test]
fn binary_resolve_fails_without_the_value() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "binary");
    let team = binary(BinaryPin {
        team_id: Some(Pinnable::Pin),
        ..no_fields()
    });
    assert_eq!(
        m.resolve(&team, target(&process(1))),
        Err(ResolveError::ValueUnavailable {
            field: Some("team_id".to_owned())
        })
    );
    let mut broken = signature("VWXYZ67890", "x");
    broken.validity = SignatureValidity::Invalid {
        reason: "modified".to_owned(),
    };
    assert_eq!(
        m.resolve(&team, target(&signed(process(1), broken))),
        Err(ResolveError::ValueUnavailable {
            field: Some("team_id".to_owned())
        })
    );
    let digest = binary(BinaryPin {
        digest: Some(Pinnable::Pin),
        ..no_fields()
    });
    assert_eq!(
        m.resolve(&digest, target(&claude())),
        Err(ResolveError::ValueUnavailable {
            field: Some("digest".to_owned())
        })
    );
}

// ---------- path ----------
//
// path は完全一致、glob、正規表現。パスは絶対パスで書き、`~` は解釈しない。glob の `*` はパスの区切りを越えず、`**` は越える (shell と同じ)。

fn zsh() -> ProcessInfo {
    at_path(process(800), "/bin/zsh")
}

#[test]
fn path_matches_exact_glob_and_regex() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "path");
    let p = zsh();
    assert!(m.matches(target(&p), &text("/bin/zsh")));
    assert!(!m.matches(target(&p), &text("/bin/bash")));
    assert!(m.matches(target(&p), &glob("/bin/*")));
    assert!(m.matches(target(&p), &regex("^/bin/(ba|z)sh$")));
    assert!(!m.matches(target(&p), &regex("^/usr/")));
    // パスが取れなかったプロセスにはどの値も当たらない。
    assert!(!m.matches(target(&process(800)), &glob("/**")));
}

// `*` は 1 つの階層の中だけ、`**` は階層を越える。`/usr/*` が `/usr/local/bin/x` に当たると、意図より広いパスを許すことになる。
#[test]
fn path_glob_star_stays_within_a_component() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "path");
    let deep = at_path(process(1), "/usr/local/bin/tool");
    assert!(!m.matches(target(&deep), &glob("/usr/*")));
    assert!(m.matches(target(&deep), &glob("/usr/**")));
    assert!(m.matches(target(&deep), &glob("/usr/**/tool")));
}

// 完全一致は文字列としての一致で、末尾の `/` などの違いを正規化して同一視しない。
#[test]
fn path_exact_is_not_normalized() {
    let vocab = Vocabulary::builtin();
    let p = at_path(process(1), "/opt/app/bin");
    assert!(!matcher(&vocab, "path").matches(target(&p), &text("/opt/app/bin/")));
    assert!(!matcher(&vocab, "path").matches(target(&p), &text("/opt//app/bin")));
}

// クラスは収集側が取った PathMeta で決まる: root 所有で利用者が書けない場所なら強 (同じ uid のプロセスが差し替えられない)、利用者が書ける場所か root 以外の所有なら中。プロセスが無い (rule の build、読み込み) ときと PathMeta が取れなかったときは弱い側の中。
#[test]
fn path_class_follows_path_meta() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "path");
    let with_meta = |owner_uid, writable_by_user| ProcessInfo {
        path_meta: Some(PathMeta {
            owner_uid,
            writable_by_user,
        }),
        ..zsh()
    };
    let value = text("/bin/zsh");
    assert_eq!(
        m.class(&value, Some(&with_meta(0, false))),
        Strength::Strong
    );
    assert_eq!(m.class(&value, Some(&with_meta(0, true))), Strength::Medium);
    assert_eq!(
        m.class(&value, Some(&with_meta(501, false))),
        Strength::Medium
    );
    assert_eq!(m.class(&value, Some(&zsh())), Strength::Medium);
    assert_eq!(m.class(&value, None), Strength::Medium);
    assert_eq!(m.class(&MatchValue::Pin, None), Strength::Medium);
    // path の形でない値 (不正) は弱。
    assert_eq!(m.class(&int(1), Some(&with_meta(0, false))), Strength::Weak);
}

#[test]
fn path_validate_needs_absolute_and_well_formed_patterns() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "path");
    assert_eq!(m.validate(&text("/bin/zsh")), Ok(()));
    assert_eq!(m.validate(&glob("/Applications/*.app/**")), Ok(()));
    assert_eq!(m.validate(&regex("zsh$")), Ok(()));
    assert_eq!(m.validate(&MatchValue::Pin), Ok(()));
    // 相対パスと `~` は解釈しないので、書いても実行パス (常に絶対) に当たらない。読み込みで知らせる。
    assert!(m.validate(&text("bin/zsh")).is_err());
    assert!(m.validate(&text("~/bin/tool")).is_err());
    assert!(m.validate(&glob("**/zsh")).is_err());
    // 組み立てられないパターン。
    assert!(m.validate(&glob("/bin/[")).is_err());
    assert!(m.validate(&regex("(")).is_err());
    // 数値と範囲は path の形ではない。
    assert!(m.validate(&int(1)).is_err());
    assert!(m.validate(&MatchValue::Range { min: 0, max: 1 }).is_err());
}

#[test]
fn path_resolve_pins_the_exact_path() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "path");
    assert_eq!(
        m.resolve(&MatchValue::Pin, target(&zsh())),
        Ok(text("/bin/zsh"))
    );
    assert_eq!(
        m.resolve(&MatchValue::Pin, target(&process(1))),
        Err(ResolveError::ValueUnavailable { field: None })
    );
    assert_eq!(
        m.resolve(&glob("/bin/*"), target(&zsh())),
        Ok(glob("/bin/*"))
    );
}

// ---------- cwd / name / tty ----------
//
// どれも同じ uid のどのプロセスも満たせる値なので弱。cwd は絶対パスの完全一致か glob、name は完全一致か glob、tty は完全一致だけ。

#[test]
fn cwd_matches_exact_and_glob() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "cwd");
    let p = ProcessInfo {
        cwd: Some(PathBuf::from("/Users/alice/src/pj1/sub")),
        ..process(1)
    };
    assert!(m.matches(target(&p), &glob("/Users/alice/src/pj1/**")));
    assert!(!m.matches(target(&p), &glob("/Users/alice/src/pj2/**")));
    assert!(m.matches(target(&p), &text("/Users/alice/src/pj1/sub")));
    assert!(!m.matches(target(&process(1)), &glob("/**")));
    assert_eq!(m.class(&text("/x"), Some(&p)), Strength::Weak);
    assert_eq!(
        m.resolve(&MatchValue::Pin, target(&p)),
        Ok(text("/Users/alice/src/pj1/sub"))
    );
}

#[test]
fn cwd_validate_rejects_regex_and_relative() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "cwd");
    assert_eq!(m.validate(&glob("/Users/**")), Ok(()));
    assert!(m.validate(&regex("pj1")).is_err());
    assert!(m.validate(&glob("src/**")).is_err());
    assert!(m.validate(&int(1)).is_err());
}

#[test]
fn name_matches_exact_and_glob() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "name");
    let p = named(1, "zsh");
    assert!(m.matches(target(&p), &text("zsh")));
    assert!(m.matches(target(&p), &glob("*sh")));
    assert!(!m.matches(target(&p), &text("bash")));
    assert!(!m.matches(target(&process(1)), &glob("*")));
    assert_eq!(m.class(&text("zsh"), None), Strength::Weak);
    assert_eq!(m.validate(&glob("*sh")), Ok(()));
    assert!(m.validate(&regex("sh$")).is_err());
    assert_eq!(m.resolve(&MatchValue::Pin, target(&p)), Ok(text("zsh")));
}

#[test]
fn tty_matches_exact_only() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "tty");
    let p = ProcessInfo {
        tty: Some("ttys003".to_owned()),
        ..process(1)
    };
    assert!(m.matches(target(&p), &text("ttys003")));
    assert!(!m.matches(target(&p), &text("ttys004")));
    // glob は tty の形ではないので、検査で弾き、照合でも当てない。
    assert!(m.validate(&glob("ttys*")).is_err());
    assert!(!m.matches(target(&p), &glob("ttys*")));
    assert_eq!(m.class(&text("ttys003"), None), Strength::Weak);
    assert_eq!(m.resolve(&MatchValue::Pin, target(&p)), Ok(text("ttys003")));
    assert_eq!(
        m.resolve(&MatchValue::Pin, target(&process(1))),
        Err(ResolveError::ValueUnavailable { field: None })
    );
}

// ---------- argv ----------
//
// argv は要素ごとに当て、いずれかの要素に一致すれば真。結合した文字列には当てない (要素の境界をまたぐ一致は、引数の区切りを偽装した別のコマンドに当たり得る)。

fn argv_process() -> ProcessInfo {
    ProcessInfo {
        argv: Some(vec![
            "node".to_owned(),
            "server.js".to_owned(),
            "--port".to_owned(),
            "8080".to_owned(),
        ]),
        ..process(1)
    }
}

#[test]
fn argv_regex_matches_some_element() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "argv");
    let p = argv_process();
    assert!(m.matches(target(&p), &regex(r"^server\.js$")));
    assert!(m.matches(target(&p), &regex("port")));
    assert!(!m.matches(target(&p), &regex("^python")));
    // 結合した文字列 "node server.js" には当てない。
    assert!(!m.matches(target(&p), &regex("node server")));
    assert!(!m.matches(target(&process(1)), &regex(".*")));
}

// 完全一致は、いずれかの要素とまるごと等しいこと。部分一致はしない。
#[test]
fn argv_exact_matches_a_whole_element() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "argv");
    let p = argv_process();
    assert!(m.matches(target(&p), &text("--port")));
    assert!(!m.matches(target(&p), &text("--po")));
}

// argv は列で、1 つの文字列の値として pin できる要素が決まらないので placeholder を持たない。glob も argv の形ではない。クラスは弱。
#[test]
fn argv_has_no_placeholder() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "argv");
    assert!(m.validate(&MatchValue::Pin).is_err());
    assert!(m.validate(&glob("*.js")).is_err());
    assert_eq!(m.validate(&regex("js$")), Ok(()));
    assert_eq!(m.validate(&text("node")), Ok(()));
    assert_eq!(
        m.resolve(&MatchValue::Pin, target(&argv_process())),
        Err(ResolveError::ValueUnavailable { field: None })
    );
    assert_eq!(m.class(&regex("x"), None), Strength::Weak);
}

// ---------- uid / gid ----------
//
// uid は数値の完全一致か範囲 (両端を含む)、gid は完全一致だけ (範囲を書ける項目は uid だけ)。同じ uid の全プロセスが満たすので何も特定せず、弱。

#[test]
fn uid_matches_exact_and_inclusive_range() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "uid");
    let p = with_ids(process(1), 501, 20);
    assert!(m.matches(target(&p), &int(501)));
    assert!(!m.matches(target(&p), &int(502)));
    assert!(m.matches(target(&p), &MatchValue::Range { min: 501, max: 501 }));
    assert!(m.matches(target(&p), &MatchValue::Range { min: 500, max: 501 }));
    assert!(!m.matches(target(&p), &MatchValue::Range { min: 502, max: 600 }));
    // 文字列の "501" は数値の項目の値ではない。
    assert!(!m.matches(target(&p), &text("501")));
    assert!(!m.matches(target(&process(1)), &int(501)));
}

#[test]
fn uid_validate_checks_the_id_range() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "uid");
    assert_eq!(m.validate(&int(0)), Ok(()));
    assert_eq!(m.validate(&int(i64::from(u32::MAX))), Ok(()));
    assert_eq!(m.validate(&MatchValue::Pin), Ok(()));
    assert_eq!(
        m.validate(&MatchValue::Range { min: 500, max: 600 }),
        Ok(())
    );
    // ID でない数 (負、u32 を超える) と、空の範囲 (min > max) は書き間違い。
    assert!(m.validate(&int(-1)).is_err());
    assert!(m.validate(&int(i64::from(u32::MAX) + 1)).is_err());
    assert!(
        m.validate(&MatchValue::Range { min: 600, max: 500 })
            .is_err()
    );
    assert!(m.validate(&regex("50")).is_err());
    assert!(m.validate(&text("501")).is_err());
}

#[test]
fn uid_class_and_resolve() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "uid");
    let p = with_ids(process(1), 501, 20);
    assert_eq!(m.class(&int(0), Some(&p)), Strength::Weak);
    assert_eq!(m.resolve(&MatchValue::Pin, target(&p)), Ok(int(501)));
    assert_eq!(
        m.resolve(&MatchValue::Pin, target(&process(1))),
        Err(ResolveError::ValueUnavailable { field: None })
    );
}

#[test]
fn gid_matches_exact_only() {
    let vocab = Vocabulary::builtin();
    let m = matcher(&vocab, "gid");
    let p = with_ids(process(1), 501, 20);
    assert!(m.matches(target(&p), &int(20)));
    assert!(!m.matches(target(&p), &int(501)));
    assert!(m.validate(&MatchValue::Range { min: 0, max: 100 }).is_err());
    assert!(!m.matches(target(&p), &MatchValue::Range { min: 0, max: 100 }));
    assert_eq!(m.class(&int(20), None), Strength::Weak);
    assert_eq!(m.resolve(&MatchValue::Pin, target(&p)), Ok(int(20)));
}

// ---------- MatchTarget ----------

// 照合は chain の boot UUID を MatchTarget で受け取る。同じプロセスの情報でも、別の起動で集めた chain として見れば process の pin 値に当たらない。
#[test]
fn match_target_carries_the_boot_of_the_chain() {
    let vocab = Vocabulary::builtin();
    let p = process(501);
    let value = pinned(identity_of(&p));
    let other_boot = MatchTarget {
        info: &p,
        boot_uuid: "OTHER-BOOT",
    };
    assert!(!matcher(&vocab, "process").matches(other_boot, &value));
}
