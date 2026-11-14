---
title: 親が終わった後に exec したプロセスは p_puniqueid が launchd になり、系譜が途切れずに消える
status: open
category: design
created: 2026-11-15T08:32:54+09:00
origin: 自リポ TODO (pam-passkey のセッションからの起票)
---

# 親が終わった後に exec したプロセスは p_puniqueid が launchd になり、系譜が途切れずに消える

## 概要

祖先の walk は `p_puniqueid` と親の `p_uniqueid` の一致で親子関係を確かめ、付け替えられたプロセスで `truncated: ancestor_exited` を出す (DESIGN-ja「収集の整合性」の 4)。ところが、親が終わって launchd に付け替えられた後でそのプロセスが exec すると、`p_puniqueid` は launchd の値 (1) に書き換わる。walk はそのプロセスを launchd の直接の子として繋ぎ、`truncated` を出さない。元の系譜は列から消える。

## 背景 (事実)

- 観測 ([findings](../findings/2026-11-15-puniqueid-after-reparent-and-exec.md)): 付け替えだけなら `p_puniqueid` は元の親のまま (親の終わり方、対象が setuid root かによらない)。付け替えの後に exec すると、どの組でも `p_puniqueid` は 1 になった
- XNU の公開ソースでも、exec は `pinsertchild(…, in_exec = true)` を通り、`p_puniqueid` をその時の親の `p_uniqueid` で書き直す
- fork して親が終わってから exec するのは、同じ uid のプロセスが自分でできる (デーモン化の普通の形)
- 祖先への条件は肯定の条件で、系譜を消すと allow は当たらなくなるだけ (単調。DR-0008)。一方、祖先を条件にした deny は、系譜を消すことで当たらなくできる。途切れた列なら `undecidable` に出るが、この場合は途切れないので出ない
- 統括の観測 (2026-11-15、1 例): 親 (サブシェル) が普通に終了した後の走っている `sudo` を `dump` で集めたら、`parent_unique_id` が 1 で、列は launchd に繋がり `truncated` は無かった。sudo の exec がサブシェルの終了より後だった場合と合う (推定)

## 確かめること

- 「launchd が直接起動した」と「付け替えの後に exec した」を、ユーザ権限で区別する手段があるか (`p_orig_ppidversion`、起動時刻と親の起動時刻の比較、`responsibility_get_pid_responsible_for_pid`、asid 等。どれも観測していない)
- 区別できない場合、DESIGN-ja「収集の整合性」の 4 と DR-0008 の `undecidable` の説明を、「付け替えの後に exec したプロセスは launchd の子に見え、途切れとして出ない」に合わせて書き直すか
- 祖先を条件にした deny を、このことを前提にどう扱うか (承認画面の系譜の表示の言葉を含む)

## 関連

- [findings: 親が終わった後の p_puniqueid](../findings/2026-11-15-puniqueid-after-reparent-and-exec.md)
- [findings: collect_pid の観測](../findings/2026-11-09-collect-pid-observations.md) (付け替えだけの場合)
- [DR-0008](../decisions/DR-0008-evaluation-semantics.md): 途切れた列と `undecidable`
