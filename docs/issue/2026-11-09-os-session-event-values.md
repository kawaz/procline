---
title: os.session の各段階の事象固有の値を macOS 実機で確かめる
status: open
category: tech-memo
created: 2026-11-09T00:57:57+09:00
last_read:
open_entered: 2026-11-09T00:57:57+09:00
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

# os.session の各段階の事象固有の値を macOS 実機で確かめる

## 概要

`os.session` の各段階の事象固有の値 (`boot` = `kern.bootsessionuuid`、`awake` = `kern.waketime`、`unlocked` = 直近の解錠の時刻) を macOS の実機でどの API から取れるか確かめる。特に `unlocked` の解錠時刻は sysctl に無いので、`CGSessionCopyCurrentDictionary` や IOKit / SkyLight 系の API の候補を試し、ロック中・スリープ中に「期間の外」と判定できる値が取れるかも含めて docs/findings/ に記録する。

## 背景

DR-0009 の世代の定義の前提。

## 受け入れ条件

- [ ] `boot` / `awake` / `unlocked` それぞれの取得 API を実機で確認した
- [ ] `unlocked` について複数の API 候補を試し、ロック中・スリープ中の値を観測した
- [ ] 結果を docs/findings/ に記録した
