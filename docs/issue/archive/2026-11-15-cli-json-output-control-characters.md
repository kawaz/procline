---
title: CLI が端末に出す JSON に入る argv やパスの制御文字を扱うか
status: resolved
category: design
created: 2026-11-15T18:42:00+09:00
origin: 自リポ TODO
close_reason: implemented
---

# CLI が端末に出す JSON に入る argv やパスの制御文字を扱うか

## 概要

procline-cli は収集の結果 (`ProcessChain`) を `serde_json::to_string_pretty` で JSON にし、標準出力に書く (`crates/procline-cli/src/main.rs`)。argv、cwd、実行パスなどはプロセスの持ち主が決められる値で、`serde_json` のエスケープが対象にしない制御文字を含められる。出力先が端末なら、それらの文字は生のまま端末に届く。

## 背景 (事実)

`serde_json` 1.0.154 (リポの `Cargo.lock` の版) で、全部の Unicode スカラー値 (U+0000〜U+10FFFF、サロゲートを除く) を 1 文字ずつ `serde_json::to_string` に通し、出力が入力と変わる文字を数えた。

- エスケープされるのは 34 文字だけ: U+0000〜U+001F (U+0008 → `\b`、U+0009 → `\t`、U+000A → `\n`、U+000C → `\f`、U+000D → `\r`、それ以外は `\u00XX`) と、U+0022 → `\"`、U+005C → `\\`
- 次の文字を含む文字列を `to_string_pretty` と `to_string` で出した結果は、どちらもその code point がそのまま出力に入った:
  - DEL: U+007F
  - C1: U+0080、U+0085、U+009B (CSI)、U+009F
  - bidi の制御文字: U+200E、U+202A、U+202E、U+2066、U+2069
  - その他: U+2028、U+2029、U+FEFF
- 入力の code point の列 `U+0041 U+0000 U+001F U+007F U+0080 U+0085 U+009B U+009F U+200E U+202A U+202E U+2066 U+2069 U+2028 U+2029 U+FEFF U+0042` に対し、文字列の部分の出力は `A` `\u0000` `\u001f` の後に U+007F〜U+FEFF の 13 個がそのままの code point で続き、`B` で終わった

表示用の無害化は procline の責務外で、ライブラリの crate は値を生のまま返す。CLI の出力は procline-cli の責務。

## 結果

- CLI が出す JSON の文字列の中の次の文字を、出力先が端末かどうかに関わらず常に `\uXXXX` (16 進 4 桁、小文字。`serde_json` が U+0000〜U+001F に使う形) で書く。JSON として読んだ値は変わらない
  - U+007F、U+0080〜U+009F (C1)
  - bidi の制御文字 12 個: U+061C、U+200E、U+200F、U+202A〜U+202E、U+2066〜U+2069
  - 行の区切り U+2028、U+2029
- それ以外の文字 (日本語などの非 ASCII、U+FEFF を含む) はそのまま出す。U+0000〜U+001F、`"`、`\` は `serde_json` の書き方のまま。整形 (インデント、キーの順) は変わらない。CLI のオプションは足していない
- 実装は procline-cli の中だけ (`crates/procline-cli/src/lib.rs` の `is_terminal_control` と `escape_terminal_controls`)。`serde_json` が書いた JSON の文字を書き換える。文字列の外で `serde_json` が書くのは ASCII だけなので、書き換わるのは文字列の中だけになる。`serde_json` の `Formatter` で書く形は、serializer を formatter で動かすのに `serde` の crate への依存が要るので採っていない
- テスト (`crates/procline-cli/tests/procline.rs`): 対象の文字を argv に持つプロセスを起こして CLI で集め、出力に対象の文字が生のまま無く、読んだ argv が元と同じこと (`control_characters_in_argv_are_escaped_in_the_output`)、日本語がそのまま出ること (`japanese_in_argv_is_printed_as_it_is`)、対象の全部の文字が `\uXXXX` になること (`every_terminal_control_becomes_a_unicode_escape`)、集合の端の隣と JSON の構文の文字と整形が変わらないこと (`characters_outside_the_set_are_kept`)。エスケープを外すと 1 つ目と 3 つ目が、非 ASCII を全部エスケープすると 2 つ目と 4 つ目が落ちる
- 文書: README (ja/en) の CLI の説明と、DESIGN (ja/en) の「API の骨格」の CLI のコメントに 1 文ずつ

## 受け入れ条件

- [x] 扱いを決め、DESIGN か DR に書く
- [x] 扱う場合は、その制御文字を含む argv を持つプロセスを収集して、出力を確かめる

## 関連

- issue: [procline を CLI からも使えるようにする](../2026-11-15-procline-cli.md)
