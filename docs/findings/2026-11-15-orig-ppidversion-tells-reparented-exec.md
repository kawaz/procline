# launchd が直接起動したプロセスと、付け替えの後に exec したプロセスは、p_orig_ppidversion と launchd の p_idversion の一致で区別できる

- Date: 2026-11-15

観測環境: macOS 26.5.2 (25F84)、カーネル `xnu-12377.121.10~1`、Apple silicon (arm64)。利用者 (uid 501) の権限だけで観測した。sudo は使っていない。以下の観測は全部この 1 つの版の macOS でのもので、他の版では確かめていない。

## 判明した事実

- `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` が返す `p_orig_ppidversion` を launchd (pid 1) の `p_idversion` と比べると、「launchd が直接起動したプロセス」と「親が終わって launchd に付け替えられた後に exec したプロセス」を区別できた。どちらも `p_puniqueid` は launchd の `p_uniqueid` (1) で、`p_puniqueid` だけでは区別できない ([findings: 親が終わった後の p_puniqueid](./2026-11-15-puniqueid-after-reparent-and-exec.md))
- launchd が直接起動したプロセスでは一致した: 一時的な LaunchAgent 2 組、既に走っている Dock、`launchctl submit` で起動したもの 1 組、`open -n` で起動した app 2 組の全部で、`p_orig_ppidversion` は launchd の `p_idversion` (この起動では 605) と同じだった
- 付け替えの後に exec したプロセスでは一致しなかった: `p_orig_ppidversion` は終わった元の親の `p_idversion` のままだった (LaunchAgent の子孫から作った 2 組、端末から作った 4 組以上)。exec の前後で `p_puniqueid` は元の親の値から 1 に変わり、`p_orig_ppidversion` は変わらなかった
- 対照 (付け替えだけで exec していない): `p_puniqueid` は元の親の値のまま、`p_orig_ppidversion` は元の親の版だった
- `p_idversion` は fork でも exec でも新しい値になる (fork した子の版は親の版と違い、exec の後の版は前の版と違う)。親が子を fork した後に自分で exec すると、親の `p_idversion` は変わり、子の `p_orig_ppidversion` は fork の時の親の版のまま残る (`/bin/sh` が子のサブシェルを fork した後に exec した組で観測)。launchd 以外の親子では、本物の親子でも 2 つは一致するとは限らない
- 区別に使えなかった値:
  - resource / jetsam の coalition の id (`PROC_PIDCOALITIONINFO`): LaunchAgent の子孫から作った「付け替えの後に exec したプロセス」は、その LaunchAgent と完全に同じ値になった
  - pgid、sid、制御端末、`proc_bsdinfo` の `pbi_flags`、`kinfo_proc` の `p_flag` と `e_jobc`、audit session id (同じ値になった)
  - 起動時刻: 終わった元の親の起動時刻は後から読めない
  - `responsibility_get_pid_responsible_for_pid`: 観測した組では違ったが、同じ uid の権限で揃えられるかは確かめていない
  - `proc_pidoriginatorinfo` は `EINVAL`、`launchctl procinfo` は root を要求した。`launchctl print gui/<uid>/<service>` の `pid` は service として登録されたものに限る
- launchd の子 (ppid が 1) を全部、上の比較を入れた procline の walk で集めると (署名なし、祖先 1 つまで)、871 の列が launchd に届き、37 の列がそのプロセスだけで `ancestor_exited` で終わった。途切れた 37 は全部 `parent_unique_id` が 1 でない (付け替えだけのプロセス) で、`parent_unique_id` が 1 なのに比較で途切れたものは無かった (この時点で付け替えの後に exec したプロセスは無かった、と読める)

## 実用的な示唆

- 祖先の walk は、launchd を親として繋ぐ時に子の `p_orig_ppidversion` と launchd の `p_idversion` を比べ、一致しなければ「元の親は終わっている」として `ancestor_exited` で列を終えられる。付け替えだけのプロセスを `p_puniqueid` の食い違いで途切れさせるのと同じ規則の、exec を挟んだ場合
- 比べるのは launchd を親として繋ぐ時だけにする。launchd 以外の親は fork の後に自分で exec していることがあり、本物の親子でも版が一致しない (上の `/bin/sh` の組)。親子は `p_puniqueid` で繋がっている
- 識別子 (この SPI) が取れない環境では比べられず、付け替えの後に exec したプロセスも、付け替えだけのプロセスも launchd に繋がる
- 推論 (観測していない): launchd 自身が exec し直すと launchd の `p_idversion` が変わり、それより前に launchd が起動したプロセスは全部比較で途切れる側になる。`p_idversion` は 32 bit の数で、一巡すれば元の親の版が launchd の版と偶然一致しうる

## 検証の詳細

### 方法

C の小さな試験プログラム 1 つ。読むのは `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` (flavor 17、56 バイト) の `p_uniqueid` / `p_puniqueid` / `p_idversion` / `p_orig_ppidversion` と、区別の候補として試した値 (上の「区別に使えなかった値」)。

- 付け替えの後に exec するプロセスの作り方: 親 A が子 B を fork し、pipe の書き込み側を閉じて終わる。B は pipe の EOF で A が端を閉じたことを知り、自分の `getppid()` が 1 になったことを確かめてから、自分自身に exec する。exec の前 (付け替えの後) と後に、B が自分を読んで記録する
- 対照: B が exec しない
- launchd が直接起動したプロセス: 一時的な LaunchAgent (試験プログラム自身。自分を読んで記録し、上の A の役もする)、`launchctl submit`、`open -n` で起動した app (自分を読んで記録する)、既に走っている Dock (別のプロセスから読む)
- 端末から作った組は、A を端末のシェルの子孫として起動した。LaunchAgent の子孫から作った組は、LaunchAgent が fork した子が A になった

### 結果

値が記録に残っている組 (launchd の `p_idversion` はこの起動で 605、`p_uniqueid` は 1):

| 組 | 状態 | `p_uniqueid` | `p_puniqueid` | `p_idversion` | `p_orig_ppidversion` | launchd の `p_idversion` と |
|---|---|---|---|---|---|---|
| LaunchAgent | launchd が起動 | 8228017 | 1 | 15095029 | 605 | 一致 |
| `open -n` の app 1 | launchd が起動 | 8232409 | 1 | 15104048 | 605 | 一致 |
| `open -n` の app 2 | launchd が起動 | 8232411 | 1 | 15104053 | 605 | 一致 |
| LaunchAgent の子 (A) | fork された | 8228034 | 8228017 (= LaunchAgent) | 15095053 | 15095029 (= LaunchAgent) | - |
| A の子 (B) | 付け替えの後・exec の前 | 8228035 | 8228034 (= A) | 15095054 | 15095053 (= A) | 不一致 |
| A の子 (B) | exec の後 | 8228035 | **1** | 15095055 | 15095053 (= A) | **不一致** |
| 端末の子孫 (A) | fork と exec の後 | 8231426 | 8231422 | 15102125 | 15102115 | - |
| A の子 (B) | 付け替えの後・exec の前 | 8231427 | 8231426 (= A) | 15102126 | 15102125 (= A) | 不一致 |
| A の子 (B) | exec の後 | 8231427 | **1** | 15102130 | 15102125 (= A) | **不一致** |

Dock、`launchctl submit` の組、残りの LaunchAgent と端末の組は、一致・不一致の結果だけを記録し、値の行は残していない。

### procline の walk での確認

- 付け替えの後に exec したプロセスを `collect_pid` で集めると、列はそのプロセスだけで `ancestor_exited` になり、launchd の行は無い。比較を外すと、列は そのプロセス → launchd で途切れの印が無い (`crates/procline-macos/tests/collect_pid.rs` の `a_process_that_ran_exec_after_reparenting_ends_the_chain`。プロセスはテストのバイナリを補助の役で起こして作る)
- `/bin/sh` が子のサブシェルを fork した後に `exec /bin/sleep` した組: exec の前は 子の `p_orig_ppidversion` = sh の `p_idversion` = 15136289、exec の後は sh の `p_idversion` が 15136291 になり、子の `p_orig_ppidversion` は 15136289 のまま。子の `p_puniqueid` は exec の前後とも sh の `p_uniqueid` だった。比較を launchd 以外の親子にも当てると、このテストの足場 (`crates/procline-macos/src/collect.rs` の `the_recheck_tells_an_ancestor_exec_from_an_ancestor_exit`) で、exec した sh の手前で列が途切れて落ちる

### XNU の公開ソースとの照合

この Mac のカーネルは `xnu-12377.121.10` で、公開されている最も近い版 `xnu-12377.121.6` を読んだ。観測と合う。

- `bsd/kern/kern_fork.c` (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_fork.c#L979-L1001): fork では、子の `p_idversion` を全体の数 (`nextpidversion`) から新しく取り、`p_orig_ppidversion` にその時の親の `p_idversion` を保存する。exec のための proc の写しでは、どちらも元の proc の値を引き継ぐ

  ```c
  		proc_ro_data.p_idversion = OSIncrementAtomic(&nextpidversion);
  		...
  		/* Retain our parent's current pid and pidversion */
  		proc_ro_data.p_orig_ppid = proc_getpid(parent_proc);
  		proc_ro_data.p_orig_ppidversion = proc_pidversion(parent_proc);
  		...
  	} else {
  		/* For exec copy of the proc, copy the PID identifiers of original proc */
  		...
  		proc_ro_data.p_orig_ppidversion = proc_orig_ppidversion(parent_proc);
  ```

- `bsd/kern/kern_exec.c`: exec の時に `p_idversion` を前の値と違う新しい値にする (`OSIncrementAtomic(&nextpidversion)` を前の値と違うまで繰り返して `proc_setpidversion`)。`p_orig_ppidversion` はここで変えない
- `bsd/kern/kern_proc.c` の `pinsertchild` (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_proc.c#L2895-L2925): exec の時は `p_puniqueid` をその時の親の `p_uniqueid` で書き直す。同じ関数は、exec の時に親が launchd で `p_orig_ppid` が 1 でなければ、カーネルの中の印 `P_LIST_DEADPARENT` を立てる。読んだ `proc_info.c` の範囲では、この印も `p_orig_ppid` も呼び出し側に返していない
- `bsd/kern/proc_info.c` の `proc_piduniqidentifierinfo` (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/proc_info.c#L1539-L1547): `p_orig_ppidversion` を `proc_orig_ppidversion(p)` で呼び出し側に返す
- 同じ uid のプロセスが自分の `p_orig_ppidversion` を launchd の版に書き換える経路は、観測にも、読んだ fork / exec の実装にも見当たらなかった。どんな状況でも偽れないことを示したものではない

## 未観測

- 他の版の macOS
- `p_idversion` が一巡した時
- launchd 自身が exec し直した後 (launchd の `p_idversion` が変わる)
- 親が root の組、setuid の組
- 識別子 (この SPI) が取れない環境
