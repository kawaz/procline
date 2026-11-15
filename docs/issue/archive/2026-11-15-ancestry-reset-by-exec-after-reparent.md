---
title: 親が終わった後に exec したプロセスは p_puniqueid が launchd になり、系譜が途切れずに消える
status: resolved
category: design
created: 2026-11-15T08:32:54+09:00
origin: 自リポ TODO (pam-passkey のセッションからの起票)
close_reason: implemented
---

# 親が終わった後に exec したプロセスは p_puniqueid が launchd になり、系譜が途切れずに消える

## 概要

祖先の walk は `p_puniqueid` と親の `p_uniqueid` の一致で親子関係を確かめ、付け替えられたプロセスで `truncated: ancestor_exited` を出す (DESIGN-ja「収集の整合性」の 4)。ところが、親が終わって launchd に付け替えられた後でそのプロセスが exec すると、`p_puniqueid` は launchd の値 (1) に書き換わる。walk はそのプロセスを launchd の直接の子として繋ぎ、`truncated` を出さない。元の系譜は列から消える。

## 背景 (事実)

- 観測 ([findings](../../findings/2026-11-15-puniqueid-after-reparent-and-exec.md)): 付け替えだけなら `p_puniqueid` は元の親のまま (親の終わり方、対象が setuid root かによらない)。付け替えの後に exec すると、どの組でも `p_puniqueid` は 1 になった
- XNU の公開ソースでも、exec は `pinsertchild(…, in_exec = true)` を通り、`p_puniqueid` をその時の親の `p_uniqueid` で書き直す
- fork して親が終わってから exec するのは、同じ uid のプロセスが自分でできる (デーモン化の普通の形)
- 祖先への条件は肯定の条件で、系譜を消すと allow は当たらなくなるだけ (単調。DR-0008)。一方、祖先を条件にした deny は、系譜を消すことで当たらなくできる。途切れた列なら `undecidable` に出るが、この場合は途切れないので出ない
- 観測 (2026-11-15、1 例): 親 (サブシェル) が普通に終了した後の走っている `sudo` を `dump` で集めたら、`parent_unique_id` が 1 で、列は launchd に繋がり `truncated` は無かった。sudo の exec がサブシェルの終了より後だった場合と合う (推定)

## 確かめること

- 「launchd が直接起動した」と「付け替えの後に exec した」を、ユーザ権限で区別する手段があるか (`p_orig_ppidversion`、起動時刻と親の起動時刻の比較、`responsibility_get_pid_responsible_for_pid`、asid 等。どれも観測していない)
- 区別できない場合、DESIGN-ja「収集の整合性」の 4 と DR-0008 の `undecidable` の説明を、「付け替えの後に exec したプロセスは launchd の子に見え、途切れとして出ない」に合わせて書き直すか
- 祖先を条件にした deny を、このことを前提にどう扱うか (承認画面の系譜の表示の言葉を含む)

## 結果

- 区別する手段: `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` の `p_orig_ppidversion` (fork された時の親の pid version。exec でも付け替えでも変わらない) を launchd の `p_idversion` と比べると、launchd が直接起動したプロセスでは一致し、付け替えの後に exec したプロセスでは終わった元の親の版のままで一致しなかった ([findings](../../findings/2026-11-15-orig-ppidversion-tells-reparented-exec.md)。macOS 26.5.2 の 1 つの版での観測と、XNU の公開ソースの fork / exec の実装との照合)。coalition の id、pgid、sid、audit session id などは区別に使えなかった
- walk (`crates/procline-macos/src/collect.rs` の `is_parent_of`): 親子の両方で識別子が取れ、親が launchd の時に限り、子の `p_orig_ppidversion` と launchd の `p_idversion` の一致も確かめる。一致しなければ列をその行で `AncestorExited` で終える (launchd を親として繋がない)。launchd 以外の親では比べない (親が fork の後に自分で exec すると親の版は変わり、本物の親子でも一致しない。`/bin/sh` の組で観測)。公開の型、`Truncated` の値、収集の最後の確かめ直しは変えていない
- テスト (`crates/procline-macos/tests/collect_pid.rs`): `a_process_that_ran_exec_after_reparenting_ends_the_chain` (付け替えの後に exec したプロセスを実際に作って集め、列はそのプロセスだけで `AncestorExited`。比較を外すと落ちる)、`a_reparented_process_ends_the_chain` (対照: exec なし)、`processes_launchd_started_reach_launchd` (ppid が 1 のプロセスを全部集め、launchd が直接起動したプロセスの列が launchd に届く)
- 文書: DESIGN (ja/en)「収集の整合性」の 4 と DR-0014 を今の挙動に合わせた
- 残る範囲は [findings](../../findings/2026-11-15-orig-ppidversion-tells-reparented-exec.md) の「未観測」と DESIGN-ja「収集の整合性」の 4 に書いてある: 識別子 (SPI) が取れない環境では確かめられず、付け替えの後に exec したプロセスも launchd に繋がる。他の版の macOS、pid version の一巡、launchd 自身が exec し直した後、親が root の組と setuid の組は観測していない

## 関連

- [findings: 親が終わった後の p_puniqueid](../../findings/2026-11-15-puniqueid-after-reparent-and-exec.md)
- [findings: p_orig_ppidversion で付け替えの後の exec を見分ける](../../findings/2026-11-15-orig-ppidversion-tells-reparented-exec.md)
- [findings: collect_pid の観測](../../findings/2026-11-09-collect-pid-observations.md) (付け替えだけの場合)
- [DR-0008](../../decisions/DR-0008-evaluation-semantics.md): 途切れた列と `undecidable`
