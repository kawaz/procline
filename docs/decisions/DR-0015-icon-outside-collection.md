# DR-0015: アイコンは収集から外し、feature `icon` の関数にする (ImageIO で `.icns` を読み、AppKit を使わない)

- Status: Proposed
- Date: 2026-11-15

## Context

アイコンは表示専用で、照合に使わない。一方で、収集の型と収集のオプションにアイコンを入れると、収集そのものが画像を扱うフレームワークを読み込むことになり、アイコンを使わない収集の利用者にもそれが入る。

- アイコンは `CollectOptions.icon` と `ProcessInfo.icon_png` があるが実装されておらず、`icon_png` は常に `None`。DESIGN-ja は `NSWorkspace.icon(forFile:)` (AppKit) で取るとし、構成の表で procline-macos の依存に AppKit を挙げる。今は AppKit をリンクしていない
- 利用者の側の観測: pam-passkey は、setuid のプロセス (走っている `sudo`) の中で AppKit を初期化するとプロセスごと終了することを観測している (pam-passkey の findings `2026-11-02-pam-poc.md`)。helper には AppKit を足さない方針を持つ (pam-passkey の DR-0009)。helper に AppKit を読み込んだ時の振る舞いは観測していない

アイコンを AppKit 無しで取れるかを観測した (手順と元のデータは [findings](../findings/2026-11-15-collect-only-dependencies-and-icon.md)。macOS 26.5.2、Apple M1 Max 10 コア)。

- 収集の型 `ProcessInfo.icon_png` は PNG のバイト列 (`Option<Vec<u8>>`) で、procline-core は AppKit に依存しない
- ImageIO (`CGImageSourceCreateWithURL`、`CGImageDestination`) だけで、app bundle の `.icns` を PNG に変換できた (Terminal、計算機、Ghostty、テキストエディット、メモの 5 種類で 9 回)。リンクしたのは CoreFoundation、ImageIO、CoreGraphics だけで、走らせた時に dyld が AppKit を読み込まなかった (`DYLD_PRINT_LIBRARIES`。UIFoundation は読み込んだ後に遅延に回された)
- 1 つのプロセスで続けて変換すると、最初の 1 つは 27.5 ms (別のプロセスで 1 つだけ変換した時は 8.9〜17.4 ms)、2 つ目からは 1.7〜3.3 ms だった。署名の検証 (1 プロセスの中央値 1.8 ms、[DR-0011](DR-0011-verified-signature-and-trust-mark.md)) と同じかそれより長い
- 手元の `/Applications`、`/System/Applications`、`/System/Applications/Utilities` の .app 139 個のうち、131 個は Info.plist の `CFBundleIconFile` が指す `.icns` を持っていた。残りの 8 個は、アイコンを宣言しないか、宣言した `.icns` が無かった
- アイコンは、同じ uid が書ける場所に置かれた app bundle なら、その利用者が中身を決められるファイルを画像として解釈することになる
- 入口の procline の feature `icon` を procline-macos の feature `icon` に渡し、入口から `icon_png()` を呼ぶ形は、target ごとの依存 (`[target.'cfg(target_os = "macos")'.dependencies]`) のままビルドできた (findings の「feature の受け渡し」)

- 目的: アイコンを使わない収集の利用者が、アイコンのためのコードと、それが読み込むフレームワークを持ち込まない
- 増やしたくないもの:
  - アイコンを使わない利用者のビルドに入るコードと、プロセスに読み込まれるフレームワーク (特に AppKit)
  - 機能の有無で形の変わる型 (feature によって field が増減する構造体)

## Decision

### アイコンは収集から外し、feature `icon` の関数にする

- `icon_png(executable, max_px)` は、実行パスから .app を遡り、Info.plist の `CFBundleIconFile` が指す `.icns` を ImageIO で読み、一辺が `max_px` 以下の PNG にする。app bundle の中に無い、アイコンを宣言していない、読めない時は `None`
- `ProcessInfo.icon_png` と `CollectOptions.icon` を消す。アイコンが要るアプリ (承認画面やルールの作成画面を持つもの) は、収集の後に `ProcessInfo.path` を渡して `procline::icon_png` を呼ぶ
- AppKit は使わない。procline-macos は AppKit をリンクしない
- キャッシュは crate が持たない (アプリが cdhash をキーに持つ。DESIGN-ja「署名の検証と信頼の印」)。アプリは自分のキャッシュに無い時だけ呼ぶ
- アイコンは表示専用で、照合に使わない (今と同じ)

### feature と入口からの再公開

アプリが使う収集の入口は procline だけ ([DR-0001](DR-0001-crate-naming.md)、DESIGN-ja「構成」) なので、feature は入口に置き、入口が OS ごとの crate の同じ名前の feature に渡す。OS ごとの関数の再公開も、入口が同じ feature の後ろで行う。

```toml
# procline-macos
[features]
icon = []                       # ImageIO と CoreGraphics をリンクする

# procline (入口)。procline-macos は target ごとの依存のまま
[features]
icon = ["procline-macos/icon"]
```

```rust
// procline-macos
#[cfg(feature = "icon")]
pub fn icon_png(executable: &Path, max_px: u32) -> Option<Vec<u8>>;

// procline (入口)
#[cfg(all(target_os = "macos", feature = "icon"))]
pub use procline_macos::icon_png;
```

- 既定の feature は空にする。アイコンが要るアプリは procline の `icon` を有効にする
- feature を外した時に消えるのは `icon_png` だけで、収集の型と収集の入口は変わらない
- Linux の収集を足した時は、同じ名前の feature を Linux の crate にも置き、入口の feature から両方に渡す (持たない機能は Linux の crate の側で関数を置かない)

### 構成の表

| crate | 依存 |
| --- | --- |
| procline | core、OS ごとの crate (target ごとに片方だけ)。feature `icon` で OS ごとの crate の同じ名前の feature を有効にし、`icon_png` を再公開する |
| procline-macos | core、Security framework。feature `icon` で ImageIO と CoreGraphics |

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| アイコンを `NSWorkspace.icon(forFile:)` で取る (DESIGN-ja の今の記述) | 収集の crate が AppKit をリンクする。setuid のプロセスでは AppKit の初期化でプロセスごと終わり (pam-passkey の観測)、helper には AppKit を読み込まない方針がある。ImageIO で 131/139 の app bundle のアイコンを取れる見込みで (`.icns` を持つ数。変換は 5 種類で観測)、取れないものは `None` にすれば足りる (アイコンは表示専用で、印と並べて出す) |
| アイコンを収集の中に残し、feature `icon` の時だけ `CollectOptions.icon` を持つ | feature で field が増減する構造体になり、`CollectOptions` を struct literal で組むアプリが feature の組み合わせで壊れる。field を常に持って feature が無い時に黙って `None` にすると、指定が効かない理由が見えない |
| アイコンを収集の中に残し、`CollectOptions.icon` (実行時の指定) だけで切る | 収集のたびに列の全プロセスの `.icns` を読むことになり、最初の 1 つは 10〜27 ms かかる (観測)。crate はキャッシュを持たないので、アプリが cdhash でキャッシュしていても読む前に止められない。アイコンは識別子の確かめ直し (「収集の整合性」) の中で取る必要も無い (ディスク上のファイルから取る表示用の値で、走っているコードと食い違いうる) |
## Consequences

- アイコンを使わない収集の利用者は、ImageIO と AppKit を持ち込まない
- `ProcessInfo` の JSON から `icon_png` が無くなる。DESIGN-ja「収集する情報」の表のアイコンの行、「構成」の表、「API の骨格」の `CollectOptions` を書き換える
- feature の組み合わせが増えるので、既定 (無し) と `icon` ありでビルドとテストを回す
- Cargo の feature は 1 回のビルドで選んだ package の間で合わさる (Cargo の仕様。ここでは観測していない)。同じ workspace で `icon` を有効にする package と一緒にビルドしたバイナリにも ImageIO が入る。持ち込まないことを確実にしたいアプリは、そのバイナリのビルドの依存に `icon` を有効にする package を含めない (アプリの側の構成で決めること)
- アイコンの取り出しは、同じ uid が中身を決められるファイルを画像として解釈しうる。呼ぶのはアプリが明示した時だけで、収集の中では解釈しない
- 未観測の点:
  - AppKit を helper (ユーザ権限、hardened runtime) に読み込んだ時の振る舞い (この決定では読み込まない)
  - ImageIO で 64px に縮小した時の所要時間と見た目 (観測は 128px の画像の取り出しまで)
  - アセットカタログ (`Assets.car`) だけを持つ app bundle (手元には無かった)

## 関連

- [DR-0001](DR-0001-crate-naming.md): crate の構成と依存
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md): 署名の検証の所要時間、crate はキャッシュを持たない
- [DR-0013](DR-0013-acl-layer-in-separate-crates.md): ACL の層を別の crate に分ける
- [DESIGN-ja の「構成」「収集する情報」「署名の検証と信頼の印」「API の骨格」](../DESIGN-ja.md)
- [findings: 収集だけのアプリに入る依存と、AppKit を使わないアイコンの取り出し](../findings/2026-11-15-collect-only-dependencies-and-icon.md)
- issue: [収集だけの利用者の入口](../issue/2026-11-15-minimal-collect-entry.md)
- pam-passkey (別リポ): DR-0003 (helper の起動)、DR-0009 (helper に AppKit を足さない)、findings `2026-11-02-pam-poc.md` (setuid のプロセスでの AppKit の初期化)
