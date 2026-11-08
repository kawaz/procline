---
title: p_puniqueid の reparent 時の挙動を実機確認する
status: open
category: tech-memo
created: 2026-11-08T19:16:35+09:00
last_read: 2026-11-09T03:37:43+09:00
open_entered: 2026-11-08T19:16:35+09:00
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

# p_puniqueid の reparent 時の挙動を実機確認する

## 概要

`p_puniqueid` の reparent 時の挙動を実機確認する。親が先に終了して launchd に引き取られたとき、元の親の値のままか launchd の値に変わるか。

## 背景

procline-macos の祖先の辿り方と「ここで途切れた」の判定に影響する。実装前に実機で確かめて docs/findings/ に記録する。

確認手順の案: 子を spawn して親を kill し、子の `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` の `p_puniqueid` と `ppid` を前後で比べる。

## 受け入れ条件

- [ ] 前後の `p_puniqueid` と `ppid` を比較した結果が docs/findings/ に記録されている
- [ ] 祖先走査の「途切れた」判定への影響が結論として書かれている
