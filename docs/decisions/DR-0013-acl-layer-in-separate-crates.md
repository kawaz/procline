# DR-0013: ACL の層を収集の層から crate で分け、`os.*` の語彙を procline-acl-macos に置く。依存は ACL → 収集の一方向で、収集の crate は ACL を知らない

- Status: Active
- Date: 2026-11-15

## Context

procline は 2 つの層からなる。

- 収集: プロセスとその祖先の情報を集め、コード署名を検証する。単独で使える機能で、結果の型 (`ProcessChain`) はそれだけで意味を持つ
- ACL: 収集の結果に対して rule と grant を定義し、評価する。収集の上に載る任意の層

利用者はさまざまで、収集だけを使うものも、ACL まで使うものもある。特定の利用者の構成を前提に層の分け方を決めない。

`os.*` の語彙 (`os.session`、`os.login_session` など) は ACL の項目 (`procline_acl::Item`) で、ホストの状態を OS から読む (`os.session` は `kern.bootsessionuuid` と `kern.waketime`)。OS の読み取りは procline-macos の `sys/` にあり、`unsafe` はそこだけに置く。語彙を procline-macos に置くと、procline-macos が procline-acl に依存し、入口の procline がそれを再公開する。収集の層が ACL の層を知る向きの依存になり、収集だけを使う利用者のビルドにも ACL の crate とその依存が入る。

収集だけを呼ぶ試験用のバイナリで、procline-macos が procline-acl に依存する形 (A) と依存しない形 (B) を比べた ([findings](../findings/2026-11-15-collect-only-dependencies-and-icon.md)。macOS 26.5.2、Apple M1 Max 10 コア、rustc 1.100.0、release で冷えた状態からのビルド)。

| | A: procline-acl に依存 | B: procline-acl なし |
|---|---|---|
| 通常の依存の crate の数 (`cargo tree -e normal`、重複を除く) | 53 | 42 |
| ビルドの時間 (2 回、wall / user) | 10.49 s / 58.6 s、9.93 s / 57.9 s | 6.81 s / 27.3 s、6.16 s / 26.9 s |
| バイナリの中の ACL 側のシンボル | 0 | 0 |

- A にだけ入る crate は 11: procline-acl と、その依存の regex、regex-automata、regex-syntax、aho-corasick、globset、bstr、log、chrono、iana-time-zone、num-traits
- 収集だけを呼ぶバイナリでは ACL のコードはリンクの段で落ち、走るコードは A と B で変わらない。違いはビルドに入る crate の数とビルドの時間

- 目的: 層の境界と依存の向きを crate の構成そのもので表し、収集の crate が ACL を知らずに単独で使えるようにする
- 増やしたくないもの:
  - 収集の crate (procline-core、procline-macos、procline) から ACL の crate への依存 (任意の依存、テストだけの依存を含む)
  - ビルドの設定によって公開の形が変わる crate (feature の有無で関数や依存が増減するもの)
  - `unsafe` を持つ場所 (procline-macos の `sys/` の外)

## Decision

- `os.*` の語彙 (`os_items()` とその実装) を新しい crate procline-acl-macos に置く。依存は procline-acl、procline-core、procline-macos (と JSON の値の `serde_json`)。`#![forbid(unsafe_code)]`
- 収集の crate (procline-core、procline-macos、入口の procline) は procline-acl に依存しない。feature は使わない
- procline-macos は、語彙が使う OS の観測を普通の公開関数として出す
  - `procline_macos::boot_session_uuid() -> io::Result<String>`: 起動の UUID (`kern.bootsessionuuid`)。同じ起動の間の収集の `ProcessChain::boot_uuid()` と同じ値
  - `procline_macos::wake_time_secs() -> io::Result<i64>`: 直近の起床の時刻 (`kern.waketime`、epoch からの秒)
  - `unsafe` は引き続き procline-macos の `sys/` の中だけ。procline-acl-macos は公開関数を呼ぶだけ
- 入口の procline は収集だけを再公開する (core の型と、ビルドターゲットの OS の collect)
- 名前は層と OS で対応させる: 収集側が procline-core / procline-macos、ACL 側が procline-acl / procline-acl-macos

| crate | 層 | 依存 |
| --- | --- | --- |
| procline | 収集 (入口) | core、OS ごとの crate (target ごとに片方だけ) |
| procline-core | 収集 (OS 非依存の型と判定) | なし |
| procline-macos | 収集 (macOS) | core |
| procline-acl | ACL (OS 非依存) | core |
| procline-acl-macos | ACL (macOS の `os.*` の語彙) | acl、core、macos |

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| procline-macos の feature `acl` (既定で無効) の後ろに `os_items` と procline-acl への依存を置き、入口の procline の feature から渡す | crate は増えないが、層の境界がビルドの設定に隠れる。収集の crate が ACL への任意の依存を持ち続け、feature の有無の両方をビルドとテストで見る必要がある。feature を外した時に未使用になる内部の関数 (`os.*` だけが使う sysctl の読み取り) にも `cfg` が要る (findings で観測) |
| 今のまま、procline-macos が procline-acl に常に依存する | 収集の層が ACL の層を知る逆向きの依存になる。収集だけを使う利用者のビルドにも ACL の crate とその依存 (11 個) が入る |
| `os_items` を procline-acl の中に OS ごとに置く (`cfg(target_os)`) | procline-acl は OS に依存しない ([DR-0001](DR-0001-crate-naming.md))。OS の観測を ACL の crate が直接呼ぶことになり、`unsafe` の置き場も ACL 側に広がる |

## Consequences

- 収集だけを使う利用者は procline だけに依存し、ビルドに procline-acl とその依存が入らない (`cargo tree -p procline`、`-p procline-macos`、`-p procline-cli` に procline-acl が出ない)
- ACL を使う利用者は procline-acl と procline-acl-macos を依存に足し、`procline_acl_macos::os_items()` の項目を `Vocabulary::register` で登録する
- procline-macos の公開 API に、OS の観測の関数が 2 つ (`boot_session_uuid`、`wake_time_secs`) 加わる。語彙が今後 OS の観測を足す時も、procline-macos の公開関数として足す
- 収集と ACL をまたいで確かめるテスト (実際に起こしたプロセスの保護の状態から、組み込みの語彙のクラスが決まる) は、両方に依存する procline-acl-macos に置く
- crate が 1 つ増える。crates.io で procline-acl-macos は未登録 (2026-11-15 に `/api/v1/crates/procline-acl-macos` が 404)。構成と依存の表、名前の選定は [DR-0001](DR-0001-crate-naming.md)

## 関連

- [DR-0001](DR-0001-crate-naming.md): crate の名前、構成と依存
- [DR-0015](DR-0015-icon-outside-collection.md): アイコンを収集の型から外す (提案)
- [DESIGN-ja の「構成」「項目の登録」「API の骨格」](../DESIGN-ja.md)
- [findings: 収集だけのアプリに入る依存と、AppKit を使わないアイコンの取り出し](../findings/2026-11-15-collect-only-dependencies-and-icon.md)
- issue: [収集だけの利用者の入口](../issue/2026-11-15-minimal-collect-entry.md)
