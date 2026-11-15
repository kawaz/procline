# DR-0013: 収集だけを使うアプリは ACL の crate とアイコンの読み込みを持ち込まない。`os.*` の語彙は feature `acl` の後ろに置き、アイコンは収集から外して feature `icon` の関数にする

- Status: Proposed
- Date: 2026-11-15

## Context

pam-passkey は、祖先の収集と署名の検証を root の PAM モジュールからユーザ権限の helper (hardened runtime、Developer ID 署名) に移し、procline で行う方針になった。pam-passkey が使うのは収集と署名の検証だけで、ACL は使わない (DESIGN-ja「構成」)。今の依存の形では、収集だけを使うアプリにも次が入る。

- procline-macos は `os_items()` (`procline_acl::Item` を返す) のために procline-acl に常に依存する ([DR-0001](DR-0001-crate-naming.md))。入口の procline は procline-macos の `os_items` を再公開する
- アイコンは `CollectOptions.icon` と `ProcessInfo.icon_png` があるが実装されておらず、`icon_png` は常に `None`。DESIGN-ja は `NSWorkspace.icon(forFile:)` (AppKit) で取るとし、構成の表で procline-macos の依存に AppKit を挙げる。今は AppKit をリンクしていない
- pam-passkey は、setuid のプロセス (走っている `sudo`) の中で AppKit を初期化するとプロセスごと終了することを観測している (pam-passkey の findings `2026-11-02-pam-poc.md`)。helper には AppKit を足さない方針を持つ (pam-passkey の DR-0009)。helper に AppKit を読み込んだ時の振る舞いは観測していない

収集だけを使う最小の利用者を想定して、次を観測した (手順と元のデータは [findings](../findings/2026-11-15-collect-only-dependencies-and-icon.md)。macOS 26.5.2、Apple M1 Max 10 コア、rustc 1.100.0。作業コピーを一時ディレクトリに複製し、`procline::collect_pid` で自分の列を集めて JSON で出すだけの試験用のバイナリを、release で冷えた状態からビルドした。B は複製の procline-macos から procline-acl の依存と `os_items` を外したもの)。

| | A: 今の依存 | B: procline-acl なし |
|---|---|---|
| 通常の依存の crate の数 (`cargo tree -e normal`、重複を除く) | 53 | 42 |
| ビルドの時間 (2 回、wall / user) | 10.49 s / 58.6 s、9.93 s / 57.9 s | 6.81 s / 27.3 s、6.16 s / 26.9 s |
| バイナリの中の ACL 側のシンボル (`nm` で `regex`、`globset`、`chrono`、`procline_acl` を含むもの) | 0 (procline-macos と procline-core のものは 304) | 0 |

- A にだけ入る crate は 11: procline-acl と、その依存の regex、regex-automata、regex-syntax、aho-corasick、globset、bstr、log、chrono、iana-time-zone、num-traits。procline-acl 自身は約 4,000 行
- 収集だけを呼ぶバイナリには ACL 側のシンボルが 1 つも無く、ACL のコードはリンクの段で落ちる。走るコードは A と B で変わらない (根拠はシンボルの有無)。違いはビルドの時間と、ビルドに入る (監査の対象になる) crate の数
- バイナリの大きさは、測った commit によって数 KB〜十数 KB 変わり、ACL の有無による一定の差は見られないので、比べる軸にしない (測定値は findings)

アイコンを AppKit 無しで取れるかも観測した。

- 収集の型 `ProcessInfo.icon_png` は PNG のバイト列 (`Option<Vec<u8>>`) で、procline-core は AppKit に依存しない
- ImageIO (`CGImageSourceCreateWithURL`、`CGImageDestination`) だけで、app bundle の `.icns` を PNG に変換できた (Terminal、計算機、Ghostty、テキストエディット、メモの 5 種類で 9 回)。リンクしたのは CoreFoundation、ImageIO、CoreGraphics だけで、走らせた時に dyld が AppKit を読み込まなかった (`DYLD_PRINT_LIBRARIES`。UIFoundation は読み込んだ後に遅延に回された)
- 1 つのプロセスで続けて変換すると、最初の 1 つは 27.5 ms (別のプロセスで 1 つだけ変換した時は 8.9〜17.4 ms)、2 つ目からは 1.7〜3.3 ms だった。署名の検証 (1 プロセスの中央値 1.8 ms、[DR-0011](DR-0011-verified-signature-and-trust-mark.md)) と同じかそれより長い
- 手元の `/Applications`、`/System/Applications`、`/System/Applications/Utilities` の .app 139 個のうち、131 個は Info.plist の `CFBundleIconFile` が指す `.icns` を持っていた。残りの 8 個は、アイコンを宣言しないか、宣言した `.icns` が無かった
- アイコンは、同じ uid が書ける場所に置かれた app bundle なら、その利用者が中身を決められるファイルを画像として解釈することになる

- 目的: 収集だけを使うアプリが、使わない機能のコードと、その機能が読み込むフレームワークを持ち込まない
- 増やしたくないもの:
  - 収集だけのアプリのビルドに入る crate と、プロセスに読み込まれるフレームワーク (特に AppKit)
  - crate の数 ([DR-0001](DR-0001-crate-naming.md) の 4 つ)
  - 機能の有無で形の変わる型 (feature によって field が増減する構造体)

## Decision

### feature と入口からの再公開

アプリが使うのは入口の procline だけ ([DR-0001](DR-0001-crate-naming.md)、DESIGN-ja「構成」) なので、feature は入口に置き、入口が OS ごとの crate の同じ名前の feature に渡す。OS ごとの関数の再公開も、入口が同じ feature の後ろで行う。

```toml
# procline-macos
[dependencies]
procline-acl = { workspace = true, optional = true }

[features]
acl = ["dep:procline-acl"]
icon = []                       # ImageIO と CoreGraphics をリンクする

# procline (入口)。procline-macos は target ごとの依存のまま
[features]
acl = ["procline-macos/acl"]
icon = ["procline-macos/icon"]
```

```rust
// procline-macos
#[cfg(feature = "acl")]
pub fn os_items() -> Vec<procline_acl::Item>;
#[cfg(feature = "icon")]
pub fn icon_png(executable: &Path, max_px: u32) -> Option<Vec<u8>>;

// procline (入口)
#[cfg(target_os = "macos")]
pub use procline_macos::{CollectError, CollectOptions, collect_peer, collect_pid};
#[cfg(all(target_os = "macos", feature = "acl"))]
pub use procline_macos::os_items;
#[cfg(all(target_os = "macos", feature = "icon"))]
pub use procline_macos::icon_png;
```

- 既定の feature は空にする。収集だけのアプリ (pam-passkey) は何も指定せずに済み、ACL を使うアプリ (cw) は procline-acl を依存に足して procline の `acl` を有効にし、アイコンが要るアプリは procline の `icon` を有効にする
- feature を外した時に消えるのは `os_items` / `icon_png` だけで、収集の型と収集の入口は変わらない。`acl` を外した時に未使用になる内部の関数 (`os.*` だけが使う sysctl の呼び出し) も同じ feature の後ろに置く
- この形は target ごとの依存のままビルドでき、入口から両方を呼べた ([findings](../findings/2026-11-15-collect-only-dependencies-and-icon.md) の「feature の受け渡し」)
- Linux の収集を足した時は、同じ名前の feature を Linux の crate にも置き、入口の feature から両方に渡す (持たない機能は Linux の crate の側で関数を置かない)

### `os.*` の語彙は feature `acl` の後ろに置く

`os_items` は procline-acl の型 (`Item`) を返すので、procline-acl への依存ごと feature `acl` の後ろに置く。

### アイコンは収集から外し、feature `icon` の関数にする

- `icon_png(executable, max_px)` は、実行パスから .app を遡り、Info.plist の `CFBundleIconFile` が指す `.icns` を ImageIO で読み、一辺が `max_px` 以下の PNG にする。app bundle の中に無い、アイコンを宣言していない、読めない時は `None`
- `ProcessInfo.icon_png` と `CollectOptions.icon` を消す。アイコンが要るアプリ (承認画面やルールの作成画面を持つもの) は、収集の後に `ProcessInfo.path` を渡して `procline::icon_png` を呼ぶ
- AppKit は使わない。procline-macos は AppKit をリンクしない
- キャッシュは crate が持たない (アプリが cdhash をキーに持つ。DESIGN-ja「署名の検証と信頼の印」)。アプリは自分のキャッシュに無い時だけ呼ぶ
- アイコンは表示専用で、照合に使わない (今と同じ)

### 構成の表

| crate | 依存 |
| --- | --- |
| procline | core、OS ごとの crate (target ごとに片方だけ)。feature `acl` / `icon` で OS ごとの crate の同じ名前の feature を有効にし、`os_items` / `icon_png` を再公開する |
| procline-macos | core、Security framework。feature `acl` で procline-acl、feature `icon` で ImageIO と CoreGraphics |

procline-core と procline-acl の依存は変えない。

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 今の依存のままにする (DR-0001 の Consequences の「収集だけのアプリのビルドにも procline-acl が入る」を受け入れる) | 走るコードは変わらない (観測) ので、実行時の害は無い。一方で収集だけのアプリのビルドに 11 個の crate が入り、ビルドの時間が 1.5 倍強になる (wall、CPU 時間は 2 倍強)。hardened runtime の Developer ID 署名で配る helper では、ビルドに入る crate がそのまま監査の対象になる。feature 1 つで外せるので、持ち込まない側を選ぶ |
| `os_items` を別の crate (procline-macos-acl 等) に移す | `os.*` の観測は procline-macos の内部の sysctl の呼び出し (`kern.bootsessionuuid`、`kern.waketime`) を使い、今後の `os.console_user`、画面ロックの状態も OS の呼び出しを足す。別の crate にすると、内部の呼び出しを公開するか二重に持つことになる。crate が 5 つになり、crates.io の名前の確保も増える。feature なら依存の向き (macos → acl) も中身の置き場も DR-0001 のまま |
| `acl` を既定の feature にする (収集だけのアプリが `default-features = false` にする) | 既定が「使わないアプリにも入る」側になり、外し忘れると黙って入る。既定を空にすれば、ACL のアプリが有効にし忘れた時は `os_items` が無いというコンパイルのエラーで気づける |
| `os_items` を procline-acl の中に OS ごとに置く (`cfg(target_os)`) | procline-acl は OS に依存しない (DR-0001)。Linux の収集を足しても ACL 側が変わらない性質が崩れる |
| アイコンを `NSWorkspace.icon(forFile:)` で取る (DESIGN-ja の今の記述) | 収集の crate が AppKit をリンクする。setuid のプロセスでは AppKit の初期化でプロセスごと終わり (pam-passkey の観測)、helper には AppKit を読み込まない方針がある。ImageIO で 131/139 の app bundle のアイコンを取れる見込みで (`.icns` を持つ数。変換は 5 種類で観測)、取れないものは `None` にすれば足りる (アイコンは表示専用で、印と並べて出す) |
| アイコンを収集の中に残し、feature `icon` の時だけ `CollectOptions.icon` を持つ | feature で field が増減する構造体になり、`CollectOptions` を struct literal で組むアプリが feature の組み合わせで壊れる。field を常に持って feature が無い時に黙って `None` にすると、指定が効かない理由が見えない |
| アイコンを収集の中に残し、`CollectOptions.icon` (実行時の指定) だけで切る | 収集のたびに列の全プロセスの `.icns` を読むことになり、最初の 1 つは 10〜27 ms かかる (観測)。crate はキャッシュを持たないので、アプリが cdhash でキャッシュしていても読む前に止められない。アイコンは識別子の確かめ直し (「収集の整合性」) の中で取る必要も無い (ディスク上のファイルから取る表示用の値で、走っているコードと食い違いうる) |

## Consequences

- 収集だけのアプリは procline に依存するだけで、procline-acl とその依存、AppKit、ImageIO を持ち込まない
- ACL を使うアプリは、procline の feature `acl` を有効にする手間が 1 つ増える
- `ProcessInfo` の JSON から `icon_png` が無くなる。DESIGN-ja「収集する情報」の表のアイコンの行、「構成」の表、「API の骨格」の `CollectOptions` を書き換える
- [DR-0001](DR-0001-crate-naming.md) の Decision の表 (procline-macos の依存が `core、acl`) と Consequences の「収集だけを使うアプリのビルドにも procline-acl が入る」を、この DR が置き換える
- feature の組み合わせが増えるので、既定 (どちらも無し) と `acl`、`icon` ありでビルドとテストを回す
- Cargo の feature は 1 回のビルドで選んだ package の間で合わさる (Cargo の仕様。ここでは観測していない)。同じ workspace で `icon` を有効にする package と一緒にビルドした helper にも ImageIO が入る。持ち込まないことを確実にしたいアプリは、helper のビルドの依存に `icon` を有効にする package を含めない (アプリの側の構成で決めること)
- アイコンの取り出しは、同じ uid が中身を決められるファイルを画像として解釈しうる。呼ぶのはアプリが明示した時だけで、収集の中では解釈しない
- 未観測の点:
  - AppKit を helper (ユーザ権限、hardened runtime) に読み込んだ時の振る舞い (この決定では読み込まない)
  - ImageIO で 64px に縮小した時の所要時間と見た目 (観測は 128px の画像の取り出しまで)
  - アセットカタログ (`Assets.car`) だけを持つ app bundle (手元には無かった)
  - ビルドの時間の比較は試験用のバイナリ 1 つ、冷えた状態の 2 回ずつ

## 関連

- [DR-0001](DR-0001-crate-naming.md): crate の分け方と依存 (この DR が procline-macos の依存の行を置き換える)
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md): 署名の検証の所要時間、crate はキャッシュを持たない
- [DR-0014](DR-0014-chain-trust-boundary-and-caller-supplied-values.md): 評価に渡す chain の出どころと、呼び出し元が渡す値
- [DESIGN-ja の「構成」「収集する情報」「署名の検証と信頼の印」「API の骨格」](../DESIGN-ja.md)
- [findings: 収集だけのアプリに入る依存と、AppKit を使わないアイコンの取り出し](../findings/2026-11-15-collect-only-dependencies-and-icon.md)
- issue: [収集だけの利用者の入口](../issue/2026-11-15-minimal-collect-entry.md)
- pam-passkey (別リポ): DR-0003 (helper の起動)、DR-0009 (helper に AppKit を足さない)、findings `2026-11-02-pam-poc.md` (setuid のプロセスでの AppKit の初期化)
