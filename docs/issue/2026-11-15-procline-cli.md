---
title: procline を CLI からも使えるようにする (収集の出力と、subject での照合)
status: open
category: design
created: 2026-11-15T14:00:00+09:00
origin: kawaz の提案 (2026-11-15)
---

# procline を CLI からも使えるようにする (収集の出力と、subject での照合)

## 概要

kawaz の提案 (2026-11-15): `procline <pid>` で収集の結果がそのまま取れ、ACL や subject の形式も CLI から使えると、プロセスを照合するツールとして便利。

今あるもの: `crates/procline/examples/dump.rs` (`cargo run -p procline --example dump -- <pid>` で `ProcessChain` の JSON を出す) と `examples/bench.rs`。配る形のコマンドは無い。

## 形の案

| 段 | コマンド | 中身 | 前提 |
|---|---|---|---|
| 1 | `procline <pid>` | 対象と祖先を集めて JSON で出す (今の `dump` と同じ) | なし。すぐ作れる |
| 2 | `procline match <subject> <pid>` | subject (JSON) を、集めた列に照合して、当たったか・どの項目で外れたかを出す。タグの定義も渡せる | subject と値の型を JSON から読めること (procline-acl の型の読み込み。一覧の読み込み `Policy::load_verified` と同じ土台) |
| 3 | `procline explain …` | rule と grant まで含めて、評価の結果と trace を出す | 一覧と grant の読み込み |

## 決めること

- **置き場**: 入口の crate (`procline`) に bin を足すと、収集だけを使うアプリにも ACL の crate が入る (提案中の DR-0013 と逆向き)。CLI は別の crate (`procline-cli`、コマンド名は `procline`) にして、`procline` と `procline-acl` に依存させる案
- **照合の対象**: CLI が自分で集めた列だけにするか、保存した JSON の列にも照合できるようにするか。後者は「評価に渡せる列は自分で収集したものに限る」(提案中の DR-0014、QUESTIONS の HO-Q1 / HO-Q2) と衝突する。前者なら収集した型の読み込みは要らない
- **CLI の形**: サブコマンド、`--help`、補完は reference の `cli-design/preferences` に従う。`procline <pid>` を既定の動作にするか、`procline collect <pid>` にするか
- **出力**: 既定で env を出さない、証明書の DER を出すか要約だけにするか、`--digest` / `--all-names` / `--no-signature` の扱い
- **配り方**: 署名 (hardened runtime) と配布 (homebrew tap) をいつ入れるか

## 決めたこと (段 1)

- **置き場**: 別の crate `crates/procline-cli` (package 名 `procline-cli`、バイナリ名 `procline`)。依存は `procline` と `serde_json` だけで、`procline-acl` には直接依存しない (kawaz 裁定 2026-11-15)
- **コマンドの形**: `procline [options] [--] <pid>` を既定の動作にする。サブコマンドは名前で、pid は数字だけなので、先頭の語で区別でき、段 2 の `match` / 段 3 の `explain` を足しても衝突しない。引数が無ければ `--help` を出す
- **オプション** (ロングだけ、pid の後ろにも置ける、`--` でオプションを終える):

  | オプション | 中身 | 既定 |
  |---|---|---|
  | `--env` | 全部の環境変数を集める (秘密らしい名前の値は伏せる) | 集めない |
  | `--digest` | 実行ファイルの sha256 | 取らない |
  | `--all-names` | uid / gid の全部の名前 | 代表の名前だけ |
  | `--no-signature` | 署名の検証を飛ばす (`code_signing` が null) | 検証する |
  | `--max-ancestors <N>` (`=` でも渡せる) | 祖先の上限 | 64 |
  | `--help` / `--version` | グローバルオプション (どの段でも効く) | |

- **パーサ**: 手書き。オプション・サブコマンド・シェルの表 (`src/lib.rs`) を、パーサ、`--help` の節 (Commands / Options / Global options)、補完の 3 者が共有する。clap は使わない (CLI の決まりの節構成を自分で組むことになり、表が二重になるため)
- **補完**: 段 1 から入れる。`procline completion zsh` が、同じ表から zsh の補完を出す (`source <(procline completion zsh)` で読む)
- **終了コード**: 成功 0、収集の失敗 1 (原因と次にどうするかを標準エラーに出す)、使い方の誤り 2 (`--help` を案内する)
- **出力**: アイコンと署名の予算は CLI から選べない (アイコンは取らず、予算は無し)

## 受け入れ条件

- [x] 段 1 を入れる (置き場と CLI の形を決めてから)
- [ ] 段 2 は、procline-acl の型の読み込みが入った後に、形を決めて入れる
