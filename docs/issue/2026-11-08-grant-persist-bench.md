---
title: grant 永続化のベンチ (advance ごとの署名 + 書き込みコスト)
status: open
category: task
created: 2026-11-08T21:34:35+09:00
last_read:
open_entered: 2026-11-08T21:34:35+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: 自リポ TODO
---

# grant 永続化のベンチ (advance ごとの署名 + 書き込みコスト)

## 概要

`uses` の advance ごとに grant 1 件を署名して書き直すコストを、実装時にベンチで確かめる。grant 単位の永続化 (DR-0004) は書き込みが軽い前提で採っているので、評価 1 回あたりの署名 + 書き込みの所要時間を実機で測り、docs/findings/ に記録する。

## 背景

DR-0004 の前提 (書き込みが軽い) が実測で裏付けられていない。遅ければ書き込みの非同期化や署名方式の見直しを検討する材料にする。

## 受け入れ条件

- [ ] 評価 1 回あたりの署名 + 書き込みの所要時間を実機で測定した
- [ ] 結果を docs/findings/ に記録した
- [ ] 遅い場合、非同期化・署名方式見直しの検討材料が findings に含まれている
