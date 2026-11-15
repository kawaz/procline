---
title: os.session の各段階の事象固有の値を macOS 実機で確かめる
status: open
category: tech-memo
created: 2026-11-09T00:57:57+09:00
origin: 自リポ TODO
---

# os.session の各段階の事象固有の値を macOS 実機で確かめる

## 概要

`os.session` の各段階の事象固有の値 (`boot` = `kern.bootsessionuuid`、`awake` = `kern.waketime`、`unlocked` = 直近の解錠の時刻) を macOS の実機でどの API から取れるか確かめる。特に `unlocked` の解錠時刻は sysctl に無いので、`CGSessionCopyCurrentDictionary` や IOKit / SkyLight 系の API の候補を試し、ロック中・スリープ中に「期間の外」と判定できる値が取れるかも含めて docs/findings/ に記録する。

## 背景

DR-0009 の世代の定義の前提。

## 分かったこと

解錠中・起きている状態の観測 (詳細は [docs/findings/2026-11-15-os-session-event-values.md](../findings/2026-11-15-os-session-event-values.md)):

- `boot` は `sysctl kern.bootsessionuuid` (UUID の文字列) で取れる
- `awake` は `sysctl kern.waketime` (`struct timeval`) で取れる。スリープを経ていない起動では `kern.waketime` と `kern.sleeptime` が両方とも `{sec = 0, usec = 0}` だった。今の実装 (`procline_macos::wake_time_secs()`) は 0 を返し、`os.session` の `observe` は 0 を `awake` の世代としてそのまま返す
- `unlocked` について、解錠中に「直近の解錠の時刻」を直接返す API は、試した中 (`CGSessionCopyCurrentDictionary`、IORegistry の root の property、`notify(3)`、分散通知、`last`、`log show`) には無かった

## 問い

- `awake` が 0 の値を、「起動してから最初のスリープまでの期間」の値としてそのまま使ってよいか
- `unlocked` の世代の値を OS の状態から読めない (解錠の時刻を返す API が無く、通知を受けていなかった間の解錠は後から分からない)。`os.session` の `unlocked` を、通知を受け続けるプロセスが記録した値で観測する形にするか (その値を誰が持つか)、段階を「今ロック中でない」という状態の条件に変えるか

## 受け入れ条件

済んだ分:

- [x] `boot` と `awake` の取得 API を実機で確認した
- [x] `unlocked` の候補を、解錠中の状態で試した
- [x] 解錠中の観測を docs/findings/ に記録した

残る分:

- [x] `unlocked` の候補を、ロック中とロックをまたいで観測した (解錠の時刻を返す値は無く、解錠は分散通知で知るしかない)
- [ ] スリープと起床をまたいで観測した
- [ ] 最初の起床の後と DarkWake での `kern.waketime` の値を観測した
- [ ] GUI のセッションの外 (ssh のシェル、LaunchDaemon) からの各 API を観測した
- [ ] `unlocked` の取り方を決めた
