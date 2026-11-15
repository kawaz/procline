---
title: OS に依らない収集結果の型 (Identity) が、macOS の識別子 (audit_token、asid) を field に持つ
status: open
category: design
created: 2026-11-16T00:30:00+09:00
origin: 自リポ TODO (収集の入口を pid と audit token にした時に残した点)
---

# OS に依らない収集結果の型 (Identity) が、macOS の識別子 (audit_token、asid) を field に持つ

## 概要

procline-core の `Identity` は OS に依らない収集結果の型だが、`audit_token` と `asid` という macOS の概念を field に持つ。収集の入口は OS ごとの crate にあり ([DR-0018](../decisions/DR-0018-collect-by-pid-or-audit-token.md))、audit token で対象を指す入口は procline-macos だけが持つ。

今の利用は macOS だけで、実害は無い。別の OS の crate を足す時に、OS ごとの識別子を core の型でどう持つか (今の形のまま空にする、OS ごとの識別子を 1 つの field にまとめる、など) を決める。

## 受け入れ条件

- [ ] 別の OS の crate を足す時に、`Identity` の OS ごとの識別子の持ち方を決める
