# DR-0001: crate 名を procline と、その接尾辞付きの 3 つにする

- Status: Active
- Date: 2026-11-08

## Context

プロセスとその祖先の情報を集め、その上で ACL を定義・評価する crate 群に名前が要る。中身は 4 つに分かれる: アプリが依存する入口、OS に依存しない型と判定、OS ごとの収集(と OS に依存する語彙)、ACL。名前は中身を表し、crates.io で取れるものにする。

入口の置き方にも制約がある。OS ごとの収集 crate は OS 非依存の型を使うので、型を持つ crate に依存する。アプリには 1 つの crate だけを依存させ、ビルドターゲットに応じて OS ごとの crate を読み込ませたい。

## Decision

| crate | 役割 | 依存 |
| --- | --- | --- |
| `procline` | 入口。core の型と、ビルドターゲットの OS の collect を再公開する | core、OS ごとの crate(target ごとに片方だけ) |
| `procline-core` | OS 非依存の型と判定(収集結果の型、強さのクラス、署名の信頼度、無害化、env の方針) | なし |
| `procline-macos` | macOS での収集、コード署名の検証、アイコン、`os.*` の語彙の提供(`procline_macos::os_items() -> Vec<procline_acl::Item>`) | core、acl |
| `procline-acl` | rule と grant の型、評価、語彙とその登録、OS 非依存の組み込みの語彙(`Vocabulary::builtin()`)、rule の作成と grant の発行 | core |

- `Vocabulary::builtin()` は OS 非依存の項目だけを持つ: matcher の項目(`process`、`binary`、`uid`、`gid`、`path`、`cwd`、`argv`、`name`、`tty`、`responsible`)、`until`、`age`、`uses`、`time.window`。
- `os.*` の項目(`os.session`、`os.console_user`、`os.login_session`、`os.not_remote`、`os.console_active`)は procline-macos が `procline_acl::Item` として提供し、アプリが `Vocabulary::register` で登録する。

- 名前の由来は process lineage(プロセスとその祖先の列)。収集結果が、対象のプロセスから launchd までの祖先を並べた列であることを表す。
- crates.io で 4 つの名前はどれも未登録(crates.io の API `/api/v1/crates/<name>` が 404 を返す)。**crate 名 選定判断基準日: 2026-11-08** (選定を変えたらこの日付と根拠も一緒に更新する)
- 入口は `procline` で、`procline-core` を入口にしない。

## Alternatives Considered

- 案 A: `procline-core` を入口にし、core から OS ごとの crate を読み込む
  - 不採用理由: OS ごとの crate は core の型に依存するので、core から OS ごとの crate を読むと依存が循環する。型を持つ crate と入口を分けることで、依存は「入口 → core と OS ごとの crate」「OS ごとの crate → core と acl」「acl → core」の一方向になる。

## Consequences

- アプリは `procline` に依存すれば収集まで使え、ACL が要るアプリだけ `procline-acl` を足す(pam-passkey は前者だけ、cw は両方)。
- `procline-acl` は `procline-core` の型だけに依存するので、OS ごとの crate を足しても ACL 側は変わらない。OS に依存する語彙は OS ごとの crate の側に置く。
- ACL を使うアプリは、`os.*` の項目を OS ごとの crate から受け取って登録する。
- procline-macos が procline-acl に依存するので、収集だけを使うアプリ(pam-passkey)のビルドにも procline-acl が入る。
- 名前の選定は crates.io の空きに依拠している。基準日から時間をおいて公開するときは、空きを確かめ直す。

## 関連

- [DESIGN-ja の「構成」](../DESIGN-ja.md)
- [DR-0006](DR-0006-structured-values-instead-of-depends.md): `procline-acl` の語彙と、`procline-core` に置く強さの型と構造を持つ値の型
- [DR-0003](DR-0003-rule-strength-from-own-match.md): `procline-acl` のルールの強さの算出
