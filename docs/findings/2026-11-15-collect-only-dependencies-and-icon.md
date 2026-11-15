# 収集だけのアプリに入る依存 (procline-acl の有無) と、AppKit を使わないアイコンの取り出し

- Date: 2026-11-15

観測環境: macOS 26.5.2、Apple M1 Max (10 コア)、rustc 1.100.0 / cargo 1.100.0。利用者の権限だけで観測した。リポの作業コピーは変えず、一時ディレクトリに複製して試した。

## 判明した事実

- 収集だけを呼ぶ試験用のバイナリで、procline-macos が procline-acl に依存する今の形 (A) と、外した形 (B) を比べた
  - 通常の依存の crate の数は A が 53、B が 42。A にだけ入るのは procline-acl、regex、regex-automata、regex-syntax、aho-corasick、globset、bstr、log、chrono、iana-time-zone、num-traits の 11
  - release で冷えた状態からのビルドは、A が 10.49 s / 9.93 s (wall)、58.6 s / 57.9 s (user)、B が 6.81 s / 6.16 s (wall)、27.3 s / 26.9 s (user)
  - バイナリの大きさは A が 904,752 バイト、B が 904,912 バイトで、A のバイナリに ACL 側のシンボルは 0 個 (procline-macos と procline-core のシンボルは 304 個)。収集だけを呼ぶバイナリでは ACL のコードはリンクの段で落ちる
- procline-macos の procline-acl を optional にして feature `acl` の後ろに `os_items` を置き、入口 procline の feature `acl` / `icon` から `procline-macos/acl` / `procline-macos/icon` に渡す形 (C) は、target ごとの依存 (`[target.'cfg(target_os = "macos")'.dependencies]`) のままビルドでき、入口から `os_items()` と `icon_png()` を呼べた。feature を指定しない試験用のバイナリの依存は 42 で、両方を指定したものは 53
  - C で `acl` を外すと、`os.*` だけが使う `sys::wake_time_secs` が未使用の警告になった
- ImageIO (`CGImageSourceCreateWithURL`、`CGImageDestinationCreateWithURL`) だけで、app bundle の `.icns` を PNG にできた (9 回、5 種類の `.icns`)。試験プログラムがリンクしたのは CoreFoundation、ImageIO、CoreGraphics、libSystem だけで、走らせた時に dyld は AppKit を読み込まなかった (UIFoundation は読み込んだ後に遅延に回された)
  - 所要時間: 別々のプロセスで 1 つずつ変換すると 8.9〜17.4 ms。1 つのプロセスで続けて 6 つ変換すると、最初が 27.5 ms、2 つ目からは 1.7〜3.3 ms
  - 観測した `.icns` は、どれも一番小さい画像が 128px だった (4 枚入り)
- `/Applications`、`/System/Applications`、`/System/Applications/Utilities` の .app 139 個のうち、131 個は Info.plist の `CFBundleIconFile` が指す `.icns` を `Contents/Resources` に持っていた。4 個は `CFBundleIconFile` も `CFBundleIconName` も無く、4 個は `CFBundleIconFile` が指す `.icns` が無かった (その 4 個は `Assets.car` も持たない)

## 実用的な示唆

- ACL の crate を外して得るのは、ビルドの時間 (wall で約 1.5 倍、CPU 時間で約 2 倍の差) と、ビルドに入る crate の数。走るコードは変わらない
- feature の受け渡しは、入口の crate から target ごとの依存へそのまま書ける。`acl` を外した時に未使用になる内部の関数にも `cfg` が要る
- アイコンの取り出しに AppKit は要らない。最初の 1 回は 10〜27 ms かかるので、収集のたびに取るより、アプリのキャッシュに無い時だけ取る形が向く

## 検証の詳細

### 依存の木とビルドの時間

手順:

1. リポの作業コピーを、`target`、`.jj`、`.git` を除いて一時ディレクトリに 2 つ複製する (A、B)
2. どちらにも試験用の crate `crates/probe` を足す。依存は `procline` (path) と `serde_json` だけで、`main` は `collect_pid(自分の pid, &CollectOptions { env: 既定, redaction: 既定, icon: false, digest: false, signature: true, signature_budget: None, all_names: false, max_ancestors: 32 })` の結果を `serde_json::to_string` で出すだけ
3. B では、`crates/procline-macos/Cargo.toml` から `procline-acl.workspace = true` を消し、`crates/procline-macos/src/lib.rs` から `mod os_items;` と `pub fn os_items` を消し、`crates/procline/src/lib.rs` の再公開から `os_items` を消す
4. それぞれで次を実行する (target は複製ごとに別のディレクトリ)
   - `cargo tree -p probe -e normal --prefix none --no-dedupe | sort -u | wc -l`
   - `/usr/bin/time -p cargo build --release -p probe --target-dir <別の target>` を、`cargo clean --target-dir <同じ target>` を挟んで 2 回
   - `ls -l <target>/release/probe`
   - `nm <target>/release/probe | rg -c -i -e regex -e globset -e chrono -e procline_acl` と `nm … | rg -c -e procline_macos -e procline_core`
5. A と B の `cargo tree` の出力の差 (`comm -23`) で、A にだけ入る crate を出す

| | A: 今の依存 | B: procline-acl なし |
|---|---|---|
| 通常の依存の crate の数 | 53 | 42 |
| ビルド 1 回目 (wall / user / sys) | 10.49 / 58.61 / 4.97 s | 6.81 / 27.25 / 3.00 s |
| ビルド 2 回目 (wall / user / sys) | 9.93 / 57.93 / 4.41 s | 6.16 / 26.93 / 2.92 s |
| バイナリ | 904,752 バイト | 904,912 バイト |
| ACL 側のシンボル | 0 | 0 |

B の試験用のバイナリを走らせ、自分の列が JSON で出ることを確かめた (列の先頭は自分、親子は unique ID で繋がった)。

### feature の受け渡し (C)

A をもう 1 つ複製し、次のように変えた。

- `crates/procline-macos/Cargo.toml`: `procline-acl = { workspace = true, optional = true }`、`[features] acl = ["dep:procline-acl"]`、`icon = []`
- `crates/procline-macos/src/lib.rs`: `mod os_items;` と `pub fn os_items` に `#[cfg(feature = "acl")]`。`#[cfg(feature = "icon")] pub fn icon_png(&Path, u32) -> Option<Vec<u8>>` (中身は `None` を返すだけ)
- `crates/procline/Cargo.toml`: `[features] acl = ["procline-macos/acl"]`、`icon = ["procline-macos/icon"]`
- `crates/procline/src/lib.rs`: `#[cfg(all(target_os = "macos", feature = "acl"))] pub use procline_macos::os_items;`、同じ形で `icon_png`

`features = ["acl", "icon"]` で procline に依存する試験用の crate が `os_items().len()` と `icon_png(…)` を呼んで、`os_items=5 icon=false` を出した。feature を指定しない `crates/probe` もビルドでき、`warning: function wake_time_secs is never used` (`crates/procline-macos/src/sys/proc.rs`) が出た。

### ImageIO での `.icns` の変換

C 言語の試験プログラム (約 40 行) を `clang -O2 … -framework CoreFoundation -framework ImageIO -framework CoreGraphics` でビルドした。要点:

- `CGImageSourceCreateWithURL` で `.icns` を開き、`CGImageSourceGetCount` の画像を全部 `CGImageSourceCreateImageAtIndex` で取り出して、幅が 64 に最も近いもの (64 未満は 4 倍の重みで遠い扱い) を選ぶ
- `CGImageDestinationCreateWithURL(…, "public.png", 1, NULL)` に `CGImageDestinationAddImage` して `CGImageDestinationFinalize`
- 開いてから書き終わるまでを `clock_gettime(CLOCK_MONOTONIC)` で測る
- 2 つ目の版は、引数の組を 1 つのプロセスで順に変換する

| 対象 | 結果 |
|---|---|
| Terminal、計算機、Ghostty の `.icns` (別々のプロセス) | 画像 4 枚、128px を選択、PNG 128x128 RGBA、17.37 / 9.58 / 8.93 ms |
| Terminal、計算機、テキストエディット、メモ、Terminal、計算機 (1 つのプロセス) | 27.49、2.58、2.52、2.60、1.72、3.33 ms |
| `otool -L` | CoreFoundation、ImageIO、CoreGraphics、libSystem.B |
| `DYLD_PRINT_LIBRARIES=1` で走らせた時の `AppKit` / `UIFoundation` を含む行 | `UIFoundation` の読み込みと `move loaded to delayed: UIFoundation` の 2 行。`AppKit` は無い |

### .app のアイコンの宣言の集計

`/Applications/*.app`、`/System/Applications/*.app`、`/System/Applications/Utilities/*.app` のそれぞれで、`/usr/libexec/PlistBuddy -c 'Print :CFBundleIconFile'` と `Print :CFBundleIconName` を `Contents/Info.plist` に対して読み、`CFBundleIconFile` があれば (`.icns` が無ければ付けて) `Contents/Resources/` にファイルがあるかを見た。

| 分類 | 数 |
|---|---|
| `CFBundleIconFile` の `.icns` がある | 131 |
| `CFBundleIconFile` はあるが `.icns` が無い (`Assets.car` も無い) | 4 |
| `CFBundleIconFile` も `CFBundleIconName` も無い | 4 |

## 未観測

- ImageIO での 64px への縮小 (観測は 128px の画像の取り出しまで)
- アセットカタログ (`Assets.car`) だけを持つ app bundle (手元に無かった)
- AppKit をユーザ権限の hardened runtime のプロセスに読み込んだ時の振る舞い
- ビルドの時間は試験用のバイナリ 1 つ、冷えた状態で 2 回ずつ。他のマシン、debug ビルド、差分のビルドは測っていない
