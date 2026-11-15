# 親が終わった後の p_puniqueid: 付け替えだけなら元の親のまま、その後に exec すると launchd の値になる

- Date: 2026-11-15

観測環境: macOS 26.5.2 (25F84)、カーネル `xnu-12377.121.10~1/RELEASE_ARM64_T6000`、Apple silicon (arm64)。利用者 (uid 501) の権限だけで観測した。sudo は使っていない。

## 判明した事実

- 親が終わって launchd に付け替えられたプロセスの `p_puniqueid` は、付け替えだけでは元の親の `p_uniqueid` のまま変わらない。親の終わり方 (普通の終了 / `SIGKILL`) にも、対象が setuid root か (実効 uid が 0) にもよらない (4 通りで同じ)
- 付け替えられた後でそのプロセスが exec すると、`p_puniqueid` はその時点の親 (launchd) の `p_uniqueid` = 1 になる。親の終わり方にも、exec する先が setuid root かにもよらない (4 通りで同じ)。`p_uniqueid` は exec の前後で変わらない
- XNU の公開ソースでも、exec は親の一覧への入れ直し (`pinsertchild(…, in_exec = true)`) を通り、そこで `p_puniqueid` をその時の親の `p_uniqueid` で書き直す (下の引用)
- [2026-11-09 の findings](./2026-11-09-collect-pid-observations.md) の「付け替えの後も `p_puniqueid` は元の親のまま」は、付け替えの後に exec していない場合の観測で、今回も同じ結果だった。exec を挟むと結果が変わる
- この測定とは別の観測 (2026-11-15、1 例) で、親 (サブシェル) が普通に終了した後の走っている `sudo` の `parent_unique_id` が 1 で、列が launchd に繋がっていたのは、`sudo` の exec がサブシェルの終了より後だった場合と合う (推定。その時の順序は記録が無い)

## 実用的な示唆

- `p_puniqueid` と親の `p_uniqueid` の一致で親子関係を確かめる walk は、「付け替えの後に exec したプロセス」を launchd の直接の子として繋ぎ、`truncated` を出さない。元の親の系譜は消え、列からは分からない
- fork して親が終わってから exec する (二重 fork の後の exec。デーモン化の普通の形) だけで、同じ uid のプロセスは自分を launchd の直接の子に見せられる。祖先への肯定の条件 (allow の `ancestors`) は系譜を消しても当たらなくなるだけだが、祖先を条件にした deny は、系譜を消すことで当たらなくできる。列が途切れた時の「判定できない」(`undecidable`) にもならない
- 祖先の列を根拠にする判断 (承認画面の系譜の表示、祖先を条件にした deny) は、「列の先頭が launchd に繋がっている」ことを「そのプロセスを launchd が直接起動した」とは読めない
- 「launchd が直接起動した」と「付け替えの後に exec した」を `p_orig_ppidversion` で区別した観測と、それを使う walk: [findings: p_orig_ppidversion で付け替えの後の exec を見分ける](./2026-11-15-orig-ppidversion-tells-reparented-exec.md)

## 検証の詳細

### 方法

C の小さな実験プログラム 2 つ。どれも対象 B は実験プログラムの孫で、その親 A を終わらせる前後で B を読む。

- harness: A が B を `posix_spawn` し (B は最初から目的のプログラム)、その後 A が終わる
- harness2: A が B を `fork` し (B は実験プログラムのまま待つ)、A が終わった後に B が目的のプログラムに `execv` する。exec の完了は `FD_CLOEXEC` の pipe の EOF で待つ

A の終わり方は 2 通り: 普通の終了 (pipe で合図して `_exit(0)`) と `SIGKILL` (`waitpid` で回収)。目的のプログラムは 2 通り: 同じ uid の `/bin/sleep`、setuid root の `/usr/bin/top -l 30 -s 1 -n 0` (読むだけで、実効 uid 0 / 実 uid 501 / saved uid 0、`P_SUGID` あり)。読むのは `sysctl(KERN_PROC_PID)` の ppid と uid、`proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` の `p_uniqueid` / `p_puniqueid` / `p_idversion` (どれも利用者の権限で、実効 uid 0 の B についても読めた)。B は観測の後に止めた。

### 結果

| exec の時機 | A の終わり方 | B | A が終わる前の B の puniqueid | A が終わった後 | exec の後 |
|---|---|---|---|---|---|
| A が終わる前 (harness) | `SIGKILL` | `/bin/sleep` | 7172093 (= A) | ppid 1、puniqueid 7172093 (変わらない) | - |
| A が終わる前 (harness) | 普通の終了 | `/bin/sleep` | 7172145 (= A) | ppid 1、puniqueid 7172145 (変わらない) | - |
| A が終わる前 (harness) | 普通の終了 | setuid root の `top` | 7172197 (= A) | ppid 1、puniqueid 7172197 (変わらない) | - |
| A が終わる前 (harness) | `SIGKILL` | setuid root の `top` | 7172249 (= A) | ppid 1、puniqueid 7172249 (変わらない) | - |
| A が終わった後 (harness2) | 普通の終了 | setuid root の `top` | 7172712 (= A) | ppid 1、puniqueid 7172712 (変わらない) | **puniqueid 1**、uniqueid 7172713 (変わらない)、uid 0 |
| A が終わった後 (harness2) | `SIGKILL` | `/bin/sleep` | 7172764 (= A) | ppid 1、puniqueid 7172764 (変わらない) | **puniqueid 1**、uniqueid 7172765 (変わらない) |
| A が終わった後 (harness2) | 普通の終了 | `/bin/sleep` | 7172921 (= A) | ppid 1、puniqueid 7172921 (変わらない) | **puniqueid 1**、uniqueid 7172922 (変わらない) |
| A が終わった後 (harness2) | `SIGKILL` | setuid root の `top` | 7172973 (= A) | ppid 1、puniqueid 7172973 (変わらない) | **puniqueid 1**、uniqueid 7172974 (変わらない)、uid 0 |

`p_idversion` は exec で 1 増えた (例: 13261097 → 13261098)。launchd の `p_uniqueid` は 1。

実出力の例 (harness2、普通の終了、setuid root の `top`):

```
A              pid=52648 comm=harness2 ppid=52647 uid=501 ruid=501 uniqueid=7172712 puniqueid=7172711 idversion=13261096 (proc_pidinfo=56)
B before       pid=52649 comm=harness2 ppid=52648 uid=501 ruid=501 uniqueid=7172713 puniqueid=7172712 idversion=13261097 (proc_pidinfo=56)
A ended: exit
B after A      pid=52649 comm=harness2 ppid=1 uid=501 ruid=501 uniqueid=7172713 puniqueid=7172712 idversion=13261097 (proc_pidinfo=56)
B after exec   pid=52649 comm=top ppid=1 uid=0 ruid=501 uniqueid=7172713 puniqueid=1 idversion=13261098 (proc_pidinfo=56)
```

### 一次資料

XNU `bsd/kern/kern_proc.c` の `pinsertchild` (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_proc.c)。exec の時は、新しい proc を元の proc の親の子として入れ直し、`p_puniqueid` をその親の `p_uniqueid` にする:

```c
 * Notes:	Insert a child process into the parents children list, assign
 *		the child the parent process pointer and PPID of the parent...
 */
void
pinsertchild(proc_t parent, proc_t child, bool in_exec)
{
	LIST_INIT(&child->p_children);
	proc_t sibling = parent;

	/* For exec case, new proc is not a child of old proc, but its replacement */
	if (in_exec) {
		parent = proc_parent(parent);
		...
	child->p_pptr = parent;
	child->p_ppid = proc_getpid(parent);
	child->p_puniqueid = proc_uniqueid(parent);
```

この Mac のカーネルは `xnu-12377.121.10` で、公開されている最も近い版 `xnu-12377.121.6` を読んだ。

## 未観測

- 別 uid (root) のプロセスが親で、その親が終わる組 (利用者の権限では、root の親を作って終わらせられない)
- 親が終わる前に exec し、その後にもう一度 exec した場合 (2 回目の exec でも launchd の値になると読めるが、確かめていない)
- `posix_spawn` の属性 (`POSIX_SPAWN_SETEXEC` 等) で exec した場合
- 上の別の観測での `sudo` の起動の順序 (サブシェルの終了と `sudo` の exec のどちらが先だったか)
