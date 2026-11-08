---
title: 消費型 condition を表す印を Condition trait に足すか決める
status: open
category: design
created: 2026-11-09T04:32:23+09:00
last_read:
open_entered: 2026-11-09T04:32:23+09:00
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

# 消費型 condition を表す印を Condition trait に足すか決める

## 概要

consumable-condition-marker 評価の採用順 (DR-0008「advance で変わらない grant を優先」) を実装では「`uses` を持たない grant を優先」で近似している (`policy.rs` の `consumes`)。advance を呼んで確かめると「採用された grant にだけ呼ぶ」の契約に反するため。アプリが足した消費型の condition はこの順位付けに反映されない。

`Condition` trait に消費型を表す印 (例: `kind()` の値か `consumes() -> bool`) を足すかを決め、DR-0008 の文言と揃える。

あわせて `TaggedChain.undecidable_tags` が列全体の集合でプロセスごとでない点 (evaluate 内で対象の位置で判定し直して回避中、`matching.rs` の `ChainTags`) も、型をプロセスごとにするか検討する。

## 受け入れ条件

- [ ] 消費型の印を trait に足すか否かを決め、DR-0008 の文言と実装を揃える
- [ ] `undecidable_tags` をプロセスごとの型にするか決め、必要なら `ChainTags` の回避を解消する
