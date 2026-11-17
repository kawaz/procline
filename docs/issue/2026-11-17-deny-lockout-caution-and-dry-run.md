---
title: deny で自分を締め出す事故への注意書きと、足す前に結果を試せる口
status: open
category: design
created: 2026-11-17T02:00:00+09:00
origin: 自リポ TODO (kawaz 2026-11-17)
---

# deny で自分を締め出す事故への注意書きと、足す前に結果を試せる口

## 概要

評価は deny > allow > ask の順で決まる。deny は allow より強いので、広すぎる deny を足すと、利用者が自分の操作 (許可を直す操作を含む) まで拒まれ、最悪何もできなくなる。

procline の API でこれを防ぐことには限界がある (どの操作が締め出しに当たるかは、アプリの作りで決まる)。procline がすることは 2 つ (kawaz 2026-11-17):

- 利用する側への注意書き: deny を足す時は、自分を締め出さないかに注意する。承認の画面に deny を出さない方が安全
- 足す前に試せる口: 「この rule (grant) を足したら、このプロセスには allow / deny / ask のどれが返るか」を確かめられるようにする (API と CLI のコマンド)

承認の画面に deny を出すかどうかは procline の責務外。

## 背景 (事実)

- `Policy::evaluate` / `explain` はメモリ上の Policy を変えない。grant は `add_grant` で効く ([DR-0008](../decisions/DR-0008-evaluation-semantics.md))
- 候補の rule や grant を、Policy に足さずに「足したとしたら」で評価する口があるかは確かめていない
- CLI の照合のコマンドは [issue](2026-11-15-procline-cli.md) の段 2 にある (subject とプロセスの照合)。effect まで返すコマンドは無い

## 決めること

- 試す口の形 (候補を足した Policy の写しを作って `explain` を呼べば足りるか、専用の関数を持つか)
- CLI のコマンドの形 (一覧と候補の rule と pid を受け、effect と理由を出す)
- 試せるのは、今走っているプロセスに対してだけ。後から起動する復旧の道具が締め出されるかは、この口では分からない。注意書きにそう書く
- 注意書きの置き場 (DESIGN、`Effect::Deny` と `add_grant` の doc)

## 受け入れ条件

- [ ] 注意書きを DESIGN (ja/en) と doc に書く
- [ ] 試す口を API と CLI に足す
