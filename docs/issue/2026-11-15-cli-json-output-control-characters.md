---
title: CLI が端末に出す JSON に入る argv やパスの制御文字を扱うか
status: open
category: design
created: 2026-11-15T18:42:00+09:00
origin: 自リポ TODO (DR-0017 の Consequences が CLI の側に残した論点)
---

# CLI が端末に出す JSON に入る argv やパスの制御文字を扱うか

## 概要

procline-cli は収集の結果 (`ProcessChain`) を `serde_json::to_string_pretty` で JSON にし、そのまま標準出力に書く (`crates/procline-cli/src/main.rs`)。argv、cwd、実行パスなどはプロセスの持ち主が決められる値で、`serde_json` のエスケープが対象にしない制御文字を含められる。出力先が端末なら、それらの文字は生のまま端末に届く。

## 背景 (事実)

`serde_json` 1.0.154 (リポの `Cargo.lock` の版) で、全部の Unicode スカラー値 (U+0000〜U+10FFFF、サロゲートを除く) を 1 文字ずつ `serde_json::to_string` に通し、出力が入力と変わる文字を数えた。

- エスケープされるのは 34 文字だけ: U+0000〜U+001F (U+0008 → `\b`、U+0009 → `\t`、U+000A → `\n`、U+000C → `\f`、U+000D → `\r`、それ以外は `\u00XX`) と、U+0022 → `\"`、U+005C → `\\`
- 次の文字を含む文字列を `to_string_pretty` と `to_string` で出した結果は、どちらもその code point がそのまま出力に入った:
  - DEL: U+007F
  - C1: U+0080、U+0085、U+009B (CSI)、U+009F
  - bidi の制御文字: U+200E、U+202A、U+202E、U+2066、U+2069
  - その他: U+2028、U+2029、U+FEFF
- 入力の code point の列 `U+0041 U+0000 U+001F U+007F U+0080 U+0085 U+009B U+009F U+200E U+202A U+202E U+2066 U+2069 U+2028 U+2029 U+FEFF U+0042` に対し、文字列の部分の出力は `A` `\u0000` `\u001f` の後に U+007F〜U+FEFF の 13 個がそのままの code point で続き、`B` で終わった

表示用の無害化 (`sanitize_for_display`) は CLI の JSON の出力を通らない。[DR-0017](../decisions/DR-0017-sanitize-for-display.md) (提案) の Consequences は、JSON の文字列のエスケープは JSON の構文のためのものでその DR の対象と同じではなく、端末に出す JSON に入る argv やパスの扱いは CLI の側で決める、としている。

## 問い

端末に出す JSON に入る argv やパスの制御文字を、CLI が扱うか。候補 (決めていない):

- 出力先が端末の時だけ変える
- 出力先によらず、常に `\u` で書く (JSON としては同じ値)
- 何もせず、CLI の出力は生の値を含みうることを境界として書く

## 受け入れ条件

- [ ] 扱いを決め、DESIGN か DR に書く
- [ ] 扱う場合は、その制御文字を含む argv を持つプロセスを収集して、出力を確かめる

## 関連

- [DR-0017](../decisions/DR-0017-sanitize-for-display.md): `sanitize_for_display` の仕様 (提案)
- issue: [procline を CLI からも使えるようにする](2026-11-15-procline-cli.md)

## 解決時の記録先

- 設計判断を伴う: `decisions/DR-NNNN-...md`
