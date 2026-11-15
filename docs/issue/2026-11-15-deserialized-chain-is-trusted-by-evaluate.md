---
title: JSON から読み込んだ ProcessChain を、評価がそのまま信用する
status: open
category: design
created: 2026-11-15T09:10:00+09:00
origin: pam-passkey のセッションから (実装のレビューで見つかった)
---

# JSON から読み込んだ ProcessChain を、評価がそのまま信用する

## 概要

`ProcessChain` と `CodeSigning` は `Deserialize` を実装していて、JSON から作れる。`CodeSigning` の読み込みが確かめるのは、`mark` と JSON の中の署名者の情報の整合だけで、`runtime` (hardened runtime、debugged) や `entitlements`、証明書の根が、実際に検証された値かどうかは確かめられない (JSON からは確かめようがない)。`Policy::evaluate` は、渡された chain の出どころを問わない。

そのため、外から受け取った JSON を chain として評価に渡す使い方をすると、送り手が `hardened_runtime: true`、`debugged: false`、`entitlements: null` と書くだけで、保護の状態が「保護あり」と判定され (`crates/procline-acl/src/matchers.rs`)、署名由来の条件が強になり、制約なしの `allow` が採用されうる (`crates/procline-acl/src/policy.rs`)。

レビュー (2026-11-15、読み取りによる確認。再現のテストは書いていない) での指摘。評価するアプリが、自分で収集した chain だけを評価に渡す限りは起きない。

## 検討すること

- 「評価に渡せるのは、このプロセスが `collect_*` で収集した chain だけ」を、文書の約束でなく型で強制できるか (例: JSON から読んだものは表示用の別の型にし、`Policy::tag` / `evaluate` が受け取る型は収集の結果からしか作れないようにする)
- JSON から読んだ chain を評価に使いたい利用者があるか (あるなら、chain に署名を付けて検証する入口が要る)
- DESIGN の脅威モデルの前提に、chain の出どころの信頼境界を書く

## 受け入れ条件

- [ ] 外から受け取った JSON を読み込むだけでは、評価に渡せる chain (`ProcessChain`) にならない (型で止まる)。chain を組むのは、収集の入口と、アプリのコードが「収集した値」と表明する 1 つの関数だけ
- [ ] 信頼境界 (止めるのは外から受け取った値を読み込むだけで評価に渡すこと。アプリのコードが明示して組み立てる chain と、アプリが渡す観測値は範囲外) が DESIGN と DR に書かれている
