# collect_pid の実装で観測した macOS の API の挙動

- Date: 2026-11-09

観測環境: macOS 26.5.2 (25F84)、Apple silicon (arm64)、MacOSX 26 SDK。実機では自分が使う最新の macOS だけで確かめる方針 (DESIGN-ja「収集する情報」)。

## 判明した事実

- `proc_pidinfo(PROC_PIDTBSDINFO)` は、別 uid のプロセス (launchd uid 0、WindowServer uid 88) に対して `EPERM` で失敗する。同じ uid のプロセスは読める。
- `sysctl({CTL_KERN, KERN_PROC, KERN_PROC_PID, pid})` (`struct kinfo_proc`) は、uid を問わず読める。ppid、実効 uid、group 一覧 (`cr_groups`、最大 16 件、先頭が実効 gid)、起動時刻、`p_comm`、制御端末を含む。存在しない pid には、成功 (戻り値 0) と書き込み 0 バイトで答える (`errno` は立たない)。
- `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)`、`proc_pidinfo(17 = PROC_PIDUNIQIDENTIFIERINFO)`、`proc_pidpath` は、uid を問わず読める。`PROC_PIDVNODEPATHINFO` (cwd) は、別 uid では `EPERM`。存在しない pid では、どれも `ESRCH`。
- `PROC_PIDUNIQIDENTIFIERINFO` (flavor 17) と `struct proc_uniqidentifierinfo` は公開 SDK に無い (`#ifdef PRIVATE`。SDK の flavor の並びは 16 の次が 19)。定義は xnu の `bsd/sys/proc_info_private.h` にある。公開 SDK の `<kern/kcdata.h>` の `struct crashinfo_proc_uniqidentifierinfo` は、56 バイトで先頭 3 field (`p_uuid`、`p_uniqueid`、`p_puniqueid`) の配置が同じ。launchd の `p_uniqueid` は 1。起動の早いプロセスは `p_uniqueid` が pid と同じ値になる。
- `p_idversion` は exec のたびに 1 増え、`p_uniqueid` は exec で変わらない。
- 親が終了して launchd に付け替えられたプロセスは、`e_ppid` が 1 になる。一方 `p_puniqueid` は元の親の `p_uniqueid` のまま変わらない (`p_orig_ppidversion` も変わらない)。
- `KERN_PROCARGS2` は、platform binary (`/bin/sleep`、`/usr/bin/tail`) に対しては、同じ uid でも env と dyld 向けの文字列を返さない。領域は argv の直後で終わる。platform binary でないもの (リンカの ad-hoc 署名のバイナリ、nix の coreutils) には、env と、その後に空文字列で区切られた dyld 向けの文字列 (`executable_path=`、`ptr_munge=` など) を返す。
- `responsibility_get_pid_responsible_for_pid` (私的 API) は、別 uid のプロセス (launchd、WindowServer) には -1 を返す。同じ uid のプロセス (zsh、Finder、端末内のプロセス) には自分の pid を返す。
- `SecCodeCheckValidity` で requirement `anchor apple generic` を評価した結果:
  - platform binary (zsh、launchd、Finder) と Developer ID の署名 (2 本): 成功
  - ad-hoc 署名 (リンカの署名、Homebrew でビルドしたもの): `errSecCSReqFailed` (-67050)
- `/bin`、`/usr/bin`、`/usr/libexec`、`/sbin`、`/usr/sbin` の platform binary 1344 本のうち、ad-hoc 署名のものは 0 本。
- App Store 配布のアプリ 3 本の leaf 証明書の名前は、どれも `Apple Mac OS Application Signing`。中間 CA は `Apple Worldwide Developer Relations Certification Authority`。

## 実用的な示唆 / ベストプラクティス

- 祖先を辿る取得元は `kinfo_proc` にする。`PROC_PIDTBSDINFO` では、別 uid の祖先 (launchd など) の ppid も起動時刻も取れない。`pbi_name` (32 バイト) は、同じ uid のときだけ名前の補いに使える。
- 祖先の親子関係は `p_puniqueid` と親の `p_uniqueid` の一致で確かめる。付け替えられたプロセスでは一致しない。そのため、列はそのプロセスで `Truncated::AncestorExited` で終わる。元の親が終了していることの正しい表現であり、launchd を親として繋ぐと実在しない親子関係を書くことになる。二重 fork したデーモンや、元の親が先に終わった端末内のプロセスを祖先に持つと、列はいつも launchd の手前で途切れる。
- exec の検出には `p_idversion` の比較が使える。audit token が無い `collect_pid` でも、収集の最初と最後で対象が exec していないことを確かめられる。
- platform binary の env は取れない。この場合の env は「空」(`Some({})`) でなく「読めなかった」(`None`) にする。領域が argv の直後で終わっていることで見分けられる。空の env には、終端の空文字列と dyld 向けの文字列が続く。
- 署名の信頼度を名前の文字列だけで決めると偽装できる。`SecCodeCheckValidity` を requirement なしで呼んでも、Apple のルートへの連鎖は確かめない。`anchor apple generic` の評価結果を併せて持ち、連鎖が確かめられたときだけ Platform / AppStore / DeveloperId / Notarized を名乗らせる。`errSecCSReqFailed` は「連鎖しない」(false)、それ以外のエラーは「評価できなかった」(None) と区別できる。
- OS の platform binary は ad-hoc で署名されていない。したがって、ad-hoc の判定を Apple への連鎖の判定より先に置いても、OS のバイナリに誤った警告は出ない。

## 検証の詳細

### プロセスの情報の読み取り (uid ごと)

C の小さな probe で、各 API を 4 つの対象に呼んだ。

| API | launchd (uid 0) | WindowServer (uid 88) | 自分のシェル (uid 501) | 存在しない pid |
|---|---|---|---|---|
| `PROC_PIDTBSDINFO` | `EPERM` | `EPERM` | 成功 (136 バイト) | `ESRCH` |
| `PROC_PIDT_SHORTBSDINFO` | 成功 | 成功 | 成功 | `ESRCH` |
| `PROC_PIDUNIQIDENTIFIERINFO` (17) | 成功 (uniqueid 1) | 成功 | 成功 | `ESRCH` |
| `KERN_PROC_PID` (`kinfo_proc`) | 成功 (648 バイト) | 成功 | 成功 | 成功で 0 バイト |
| `proc_pidpath` | 成功 | 成功 | 成功 | `ESRCH` |
| `PROC_PIDVNODEPATHINFO` | `EPERM` | `EPERM` | 成功 | `ESRCH` |
| `KERN_PROCARGS2` | 失敗 (dump で argv が null) | 失敗 (同) | 成功 | 未計測 |
| `responsibility_get_pid_responsible_for_pid` | -1 | -1 | 自分の pid | -1 |

`kinfo_proc` の size と offset は、SDK ヘッダを C でコンパイルし、`sizeof` / `offsetof` で測った。

| field | offset |
|---|---|
| size | 648 |
| `kp_proc.p_starttime` | 0 (`tv_usec` は 8) |
| `kp_proc.p_comm` | 243 |
| `kp_eproc.e_ucred.cr_uid` | 420 |
| `kp_eproc.e_ucred.cr_ngroups` | 424 |
| `kp_eproc.e_ucred.cr_groups` | 428 |
| `kp_eproc.e_ppid` | 560 |
| `kp_eproc.e_tdev` | 572 |
| `kp_eproc.e_flag` | 612 |

考察: 祖先を辿るのに必要な ppid と起動時刻は、uid を問わない取得元からしか得られない。argv と cwd が同じ uid でしか取れないのは、DESIGN-ja の記載どおり。

### exec をまたぐ識別子

手順: fork した子を pipe で待たせ、`p_idversion` を読む。その後に子を `/bin/sleep` に exec させる。exec の完了は、`FD_CLOEXEC` を付けた pipe の EOF で待つ (時間待ちをしない)。完了後にもう一度読む。

| 項目 | exec 前 | exec 後 |
|---|---|---|
| `p_uniqueid` | 73519248 | 73519248 |
| `p_idversion` | 139134314 | 139134315 |

考察: 個体は exec をまたいで同じ unique_id を保ち、コードの入れ替わりは `p_idversion` に出る。

### 親の終了による launchd への付け替え

手順: probe → A → B の 3 段を作る。B は pipe の読み取りで止めておく。A を `SIGKILL` して `waitpid` で回収し、その前後で B を読む。最後に、付け替え後の B を `collect_pid` で集める。

| 項目 | A の終了前 | A の終了後 |
|---|---|---|
| B の `e_ppid` | A の pid | 1 |
| B の `p_uniqueid` | 73556557 | 73556557 |
| B の `p_puniqueid` | 73556556 (= A の `p_uniqueid`) | 73556556 (変わらない) |
| B の `p_orig_ppidversion` | 139210966 (= A の `p_idversion`) | 139210966 (変わらない) |
| launchd の `p_uniqueid` | 1 | 1 |

付け替え後の B を `collect_pid` で集めた結果は、B だけの列で `truncated: ancestor_exited`。

考察: 付け替えの後は、`e_ppid` が指す launchd と、`p_puniqueid` が指す元の親が食い違う。親子関係を unique_id で確かめる walk は、ここで「祖先が途中で終了した」と判定する。このセッションの実際の祖先にも、元の親が終了して launchd に付け替えられたプロセスがあり、自プロセスの列はその手前で同じく `ancestor_exited` で終わった。

### KERN_PROCARGS2 の env

手順: env を `posix_spawn` で 2 変数だけに決めた子を起こし、その直後に領域を読む。`posix_spawn` は exec の完了後に戻る。数百ミリ秒おいて読み直しても結果は同じだった。

| 対象 | 署名 | 返った領域 |
|---|---|---|
| `/bin/sleep` | platform | 34 バイト。exec path、詰め物、argv で終わる |
| `/usr/bin/tail` | platform | 37 バイト。argv で終わる |
| リンカの ad-hoc 署名の sleeper | ad-hoc | 572 バイト。argv、渡した 2 変数、空文字列、dyld 向けの文字列 |

考察: 領域の長さはカーネルが決めていて、platform binary では env が意図的に外されている。時間の経過では変わらないので、競合ではない。

### Apple のルートへの連鎖 (`anchor apple generic`)

| 対象 | leaf 証明書 | 結果 |
|---|---|---|
| zsh、launchd、Finder | Software Signing | 満たす |
| 端末アプリ、AI エージェントの CLI | Developer ID Application | 満たす |
| Homebrew でビルドしたツール | なし (ad-hoc) | `errSecCSReqFailed` |
| テストのバイナリ | なし (リンカの ad-hoc) | `errSecCSReqFailed` |

Apple のルートに連鎖しない、自作の証明書の署名は試していない (未検証)。自作の証明書をキーチェーンに入れる必要があるため。

### platform binary の ad-hoc 署名

手順: `/bin`、`/usr/bin`、`/usr/libexec`、`/sbin`、`/usr/sbin` の実行ファイルに `codesign -dvv` をかけ、`Platform identifier` を持つものを数える。その中で `Signature=adhoc` を持つものを数える。

| 項目 | 本数 |
|---|---|
| platform binary | 1344 |
| そのうち ad-hoc | 0 |
