# ad-hoc 署名で entitlements に置ける入れ子は深さ 11 までで、未知の key を持つ entitlements のバイナリは起動した直後に殺される。深い入れ子の entitlements を持つ走っているプロセスは作れなかった

- Date: 2026-11-15

観測環境: macOS 26.5.2 (25F84)、カーネル `xnu-12377.121.10~1`、Apple silicon (arm64)。利用者 (uid 501) の権限だけで観測した。sudo は使っていない。

## 判明した事実

小さな C のプログラム (準備の合図として標準出力に 1 バイト書き、標準入力を待つ) を、XML の entitlements の plist を付けて `codesign --sign - --force --entitlements <plist>` で ad-hoc 署名し、署名できたものを起動した。plist はトップレベルの辞書に key を 1 つ置き、その値を次のどれかにした。

- 辞書の鎖: 深さ n の入れ子の辞書 (各段に key 1 つ)、末端は文字列
- 配列の鎖: 深さ n の入れ子の配列 (各段に要素 1 つ)、末端は文字列
- 幅: n 個の文字列を並べた配列 1 つ

| plist | codesign | 起動 |
|---|---|---|
| 辞書の鎖 / 配列の鎖、深さ 0、1、2、5、6、8、9、10、11 | 成功 | 起動した直後に SIGKILL (準備の合図に届かない) |
| 辞書の鎖 12、20 / 配列の鎖 12、100 | 失敗 (終了 1、`invalid entitlement plist`) | — |
| 辞書の鎖 30、40、50、60、70、80 | 35 秒で打ち切り (署名が終わらない) | — |
| 辞書の鎖 100 | 失敗 (`AMFIUnserializeXML: memory exhausted near line 1`) | — |
| 辞書の鎖 / 配列の鎖、深さ 1,000、10,000、100,000 | 失敗 (`unrecognized blob type (accepting blindly)` と `invalid length in entitlement …`) | — |
| 幅 100、1,000、20,000、100,000 | 成功 | 起動した直後に SIGKILL |
| 対照: 空の辞書 | 成功 | 起動する |
| 対照: `com.apple.security.get-task-allow` = true だけ | 成功 | 起動する。CLI での収集は成功し、結果の `code_signing.entitlements` にこの key がある。所要 0.03 秒、最大 RSS 約 14 MB (2 回) |

- 署名できても、未知の key を持つ entitlements (深さ 0 や 1、幅だけのものを含む) のバイナリは、起動した直後にカーネル / AMFI に SIGKILL された。深さ 0 のものに `codesign --verify --strict` は `valid on disk` を返した。署名の検証が通ることは、起動できることを意味しない
- 署名に失敗した後のファイルには、元の linker の署名が残ることがあった。その後の `codesign -v` の成功は、entitlements を付ける署名の操作が成功したことを意味しない
- binary plist の entitlements は、単純なもの (`com.apple.security.get-task-allow` = true だけ。XML なら署名して起動できる内容) でも `codesign` が拒んだ (終了 1、`Could not create string from entitlements data`)。同じオブジェクトを何度も参照する binary plist (各段の配列が次の段を 2 回参照する鎖、深さ 2、8、16、40、100) も同じエラー
- 深い入れ子の entitlements を持つ走っているプロセスは作れなかった。収集でスタックがあふれる深さは観測できていない

## 観測から言える規則

`codesign` の ad-hoc 署名、XML と binary の plist、この OS の範囲で:

- `codesign` が entitlements として受け付けた入れ子の深さは 11 まで。12 以上は拒むか終わらない
- binary plist の entitlements は `codesign` が受け付けない
- 未知の key を持つ entitlements の ad-hoc 署名のバイナリは、起動した直後に SIGKILL される。entitlements が空、または `com.apple.security.get-task-allow` だけのものは起動する
- 幅 (1 つの配列の要素数) は 100,000 まで `codesign` が受け付けた

## 実用的な示唆

ここからは観測からの推論。

- `codesign` で署名し、起動できたプロセスの entitlements の入れ子は、観測の範囲で深さ 11 まで。収集の `to_json` の再帰が深さ 11 であふれることは無い (CLI は main のスレッドで同期に収集する。1 段あたりのスタックの使用量は測っていない)
- 同じ uid のプロセスが深い入れ子の entitlements を持つプロセスを起動するには、`codesign` を使わずに署名の blob を組むか、Apple が定義した key の値に深い入れ子を置いて起動を通す必要がある。どちらも観測していない
- 深い入れ子を拒んでいるのは `codesign` と AMFI の受理の境界で、procline の側の上限ではない

## 検証の詳細

### 手順

- 対象: C のプログラム (3 行)。起動すると標準出力に 1 バイト書き、標準入力から 1 バイト読んで終わる
- plist の生成と署名と起動: Python のスクリプト。plist を書き、対象をコピーして `codesign --sign - --force --entitlements <plist> <copy>` を 35 秒の上限で実行した。署名できたら起動し、4 秒以内に準備の 1 バイトが届かなければ起動の失敗とし、終了の状態を記録した
- 準備の 1 バイトが届いたものは、リポの CLI (`procline <pid>`) を `/usr/bin/time -l` の下で走らせて収集し、結果の `code_signing.entitlements` に key があるかを確かめた
- binary plist: 別の Python のスクリプトで、オブジェクトの表と offset の表を直接書いて作った (標準の plist の読み手で読み戻し、深さを確かめてから署名した)

### 収集の再帰の箇所

- `crates/procline-macos/src/sys/cf.rs` の `to_json` (55 行目) が値を JSON にする。配列は要素ごとに `to_json` を呼び (79 行目)、辞書は `dictionary_to_json` (88 行目) を通して値ごとに `to_json` を呼ぶ (96 行目)。深さを数えない
- 入口: `crates/procline-macos/src/sys/security.rs` の `entitlements` (253〜257 行目) が `kSecCodeInfoEntitlementsDict` を `dictionary_to_json` に渡し、`crates/procline-macos/src/signing.rs` (70 行目) が収集の結果の `entitlements` に入れる
- CLI (`crates/procline-cli/src/main.rs`) は main のスレッド (macOS の既定で約 8 MiB のスタック) で同期に収集する。収集の経路にスレッドの生成は無い (`spawn` はテストの中だけ)

## 未観測

- `codesign` を使わずに署名の blob を組んだバイナリ (深い XML の entitlements を直接入れる) が起動できるか
- Apple が定義した key の値に深い入れ子を置いた時に、署名と起動が通るか
- `to_json` の 1 段あたりのスタックの使用量と、あふれる深さ
- 辞書の鎖の深さ 30〜80 で `codesign` が 35 秒の後に終わるか
- 他の版の macOS、Developer ID などの ad-hoc でない署名
