---
title: 収集だけを使う利用者が、ACL とアイコンを持ち込まずに済む入口が要るか決める
status: open
category: design
created: 2026-11-15T08:32:54+09:00
origin: 自リポ TODO (pam-passkey のセッションからの起票)
---

# 収集だけを使う利用者が、ACL とアイコンを持ち込まずに済む入口が要るか決める

## 概要

pam-passkey は収集と署名の検証だけを使い (DESIGN-ja「構成」: 「pam-passkey は収集だけ」)、helper (ユーザ権限、hardened runtime の Developer ID 署名) が procline を使う方針になった。procline-macos は `os.*` の語彙の提供のために procline-acl に依存し、設計ではアイコンのために AppKit を使う。収集だけの利用者にも、ACL の crate (と、アイコンが実装されれば AppKit) が入る。

## 背景 (事実)

- `crates/procline-macos/Cargo.toml` の依存: procline-core、procline-acl、serde_json、libc、core-foundation、security-framework、security-framework-sys、sha2、plist
- `os_items()` (`procline_acl::Item` を返す) のために procline-macos → procline-acl の依存がある (DR-0001)
- アイコンは `CollectOptions.icon` があるが、今は実装されておらず `icon_png` は常に `None` (`crates/procline-macos/src/collect.rs`)。AppKit はまだリンクしていない。DESIGN-ja は `NSWorkspace.icon(forFile:)` で取るとする
- 入口の procline は core と、target の OS の crate (procline-macos) に依存する

## 確かめること

- 収集だけの利用者に ACL の crate が入ることの実害 (ビルドの時間、バイナリの大きさ、helper の攻撃面)。AppKit を setuid のプロセスや helper に読み込む影響 (pam-passkey は PAM モジュールで AppKit を初期化すると sudo ごと終了することを観測している。helper では未観測)
- 分け方の候補: feature (`acl`、`icon`) で切る、`os_items` を別の crate (procline-macos-acl 等) に移す。どちらも DR-0001 の crate の分け方に関わる
- アイコンを実装する時に、収集の型 (`icon_png`) を AppKit 無しで持てるか

## 結果

- ACL の部分は [DR-0013](../decisions/DR-0013-acl-layer-in-separate-crates.md) で決まり、実装した (2026-11-15)。`os.*` の語彙は新しい crate procline-acl-macos に置き、収集の crate (procline-core、procline-macos、入口の procline) は procline-acl に依存しない。feature は使わない。procline-macos は語彙が使う OS の観測を公開関数 (`boot_session_uuid()`、`wake_time_secs()`) で出す。`cargo tree -p procline` / `-p procline-macos` / `-p procline-cli` に procline-acl は出ない
- アイコンの部分は [DR-0015](../decisions/DR-0015-icon-outside-collection.md) (提案) の裁定待ちで、この issue はそれまで開いておく

## 関連

- [DR-0001](../decisions/DR-0001-crate-naming.md): crate の分け方と依存
- [DR-0013](../decisions/DR-0013-acl-layer-in-separate-crates.md): ACL の層を別の crate に分ける
- [DR-0015](../decisions/DR-0015-icon-outside-collection.md): アイコンを収集の型から外す (提案)
- DESIGN-ja「構成」
