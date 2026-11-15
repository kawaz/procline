# `kSecCSRequirementInformation` で増える key を procline は読まず、渡さなくても `code_signing` は変わらない

- Date: 2026-11-15

観測環境: macOS 26.5.2 (25F84)、カーネル `xnu-12377.121.10~1`、arm64。利用者の権限だけで (sudo なし) 観測した。

## 何を確かめたか

procline-macos は署名の情報を `SecCodeCopySigningInformation` で取る。このフラグに `kSecCSRequirementInformation` を含めると何が増えるか、procline がそれを使っているか、含めない時に収集の結果と所要時間が変わるかを確かめた。

SDK の `SecCode.h` のコメントは、このフラグについて「Return information about internal code requirements embedded in the code. This includes the Designated Requirement.」と書く。

## 判明した事実

- 走っている 1,021 プロセスで、`kSecCSSigningInformation | kSecCSDynamicInformation` に `kSecCSRequirementInformation` を足した時の辞書の key を比べた。増える key と、それを持つプロセスの数:

| 増える key | 件数 |
|---|---:|
| `default-designated-lwcr` | 1,020 |
| `implicit-requirement` | 1,020 |
| `designated-requirement` | 1,020 |
| `requirement-data` | 990 |
| `requirements` | 990 |

- 減る key は無かった
- procline-macos (`crates/procline-macos/src/`) は、増える key をどれも読んでいない (コードを読んで確かめた。フラグの定数と呼び出しにしか出てこない)
- フラグを含める CLI と含めない CLI (他は同じコード) を、同じ pid に続けて走らせて `code_signing` の JSON を比べた: 1,016 件が一致、違いは 0 件。5 件は片方か両方の収集に失敗したので除いた
- 1 回の `SecCodeCopySigningInformation` の所要時間の中央値 (各 100 回、含めない → 含める):

| 対象 | 含めない | 含める |
|---|---:|---:|
| `/sbin/launchd` | 0.0079 ms | 0.0119 ms |
| Developer ID の app 1 つ | 0.0079 ms | 0.0149 ms |
| ad-hoc で署名した自作のプログラム | 0.0202 ms | 0.0222 ms |

## 実用的な示唆

- procline が読む key (identifier、Team ID、cdhash、証明書、flags、status、entitlements、Info.plist) は `kSecCSSigningInformation` と `kSecCSDynamicInformation` で取れる。`kSecCSRequirementInformation` は渡さない
- 所要時間の差は 1 回あたり 0.01 ms 以下で、外す理由は時間でなく、読まない情報を取らないこと (推論: requirement の文字列化の分だけ増えていると見られるが、中は確かめていない)
- 署名の requirement の評価は `SecCodeCheckValidity` に requirement を渡して行っており、署名に埋め込まれた requirement を読む必要は無い

## 検証の詳細

C の試験プログラムで、同じ SecCode に `SecCodeCopySigningInformation` を 2 回 (フラグに `kSecCSRequirementInformation` を含めない / 含める) 呼び、辞書の key の差を出した。所要時間は 2 通りを交互に 100 回ずつ呼び、`CLOCK_MONOTONIC_RAW` で測った中央値。

```c
static int info(SecCodeRef code, int req, CFDictionaryRef *dict) {
    return SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSDynamicInformation | (req ? kSecCSRequirementInformation : 0), dict);
}
```

`code_signing` の比較は、procline のリポの写しでフラグだけを外してビルドした CLI と元の CLI を、`--max-ancestors 0 <pid>` で同じ pid に続けて走らせ、`processes[0]` の `identity`・`path`・`name` が一致したものについて `code_signing` を比べた。
