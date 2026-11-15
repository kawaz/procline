---
title: ユーザ権限の収集で取れない対象の情報を、呼び出し元が渡して補う入口を決める
status: open
category: design
created: 2026-11-15T08:32:54+09:00
origin: 自リポ TODO (pam-passkey のセッションからの起票)
---

# ユーザ権限の収集で取れない対象の情報を、呼び出し元が渡して補う入口を決める

## 概要

pam-passkey は、祖先の収集と署名の検証を root の PAM モジュールでなく、ユーザ権限の helper で procline を使って行う方針になった。PAM モジュールが helper に渡すのは、自分 (走っている `sudo`) の pid・識別子・argv・cwd だけにする。ユーザ権限の収集では、実効 uid が root のプロセスの argv と cwd が取れないため。procline の入口に、呼び出し元が自分の情報を渡して列の先頭を補う形が要るか、要るならどう受けるかを決める。

## 背景 (事実)

- argv (`KERN_PROCARGS2`) と cwd (`PROC_PIDVNODEPATHINFO`) は同じ uid か root からしか取れない (DESIGN-ja「収集する情報」、[findings](../findings/2026-11-09-collect-pid-observations.md): 別 uid では `EPERM`)
- 観測 (2026-11-15): 走っている `sudo` (uid 0 / ruid 501 / svuid 0) をユーザ権限から `dump` で集めると、argv と cwd は取れず、署名も取れなかった。`codesign -dv <pid>` も `Permission denied`
- 署名は、通常の方法では SecCode が得られない (100013) が、`kSecGuestAttributeDynamicCode` を足した検証 (カーネルが持つ署名を使う) ならユーザ権限から `anchor apple` まで評価できた (別リポ pam-passkey の findings `2026-11-15-running-code-identity.md`)。[DR-0011](../decisions/DR-0011-verified-signature-and-trust-mark.md) の手順はこれを使う
- `kinfo_proc` (ppid、uid、起動時刻、名前)、`PROC_PIDUNIQIDENTIFIERINFO`、`proc_pidpath` は uid を問わず読める (findings)
- 呼び出し元が渡す値は、呼び出し元が自分について主張するもので、procline が収集したものではない

## 確かめること

- 入口の形: 対象の識別子 (unique_id / pid と起動時刻) と、渡された argv・cwd を受け、列の先頭のプロセスに入れる。識別子が一致しなければ捨てる
- 渡された値と収集した値を、型で区別するか (照合に使ってよいか、表示だけか。渡すのが root の PAM モジュールなら、同じ uid の攻撃者より強い出どころだが、procline からは確かめられない)
- 強さのクラス: 渡された argv と cwd は、どちらにしても弱 (今の `argv` と `cwd` と同じ) で足りるか
- 列の 2 番目以降 (root の祖先) の argv と cwd は取れないままでよいか

## 関連

- DESIGN-ja「収集する情報」「収集の整合性」
- [DR-0011](../decisions/DR-0011-verified-signature-and-trust-mark.md): ユーザ権限から走っている `sudo` の署名を検証する手順
- pam-passkey (別リポ kawaz/pam-passkey) の helper の方針
