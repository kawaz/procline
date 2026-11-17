# os.session の段階の世代の値は、boot と awake が sysctl で取れる。解錠中に「直近の解錠の時刻」を返す API は試した中に無かった。スリープを経ていない起動では awake の元の値 (kern.waketime) が 0 だった

- Date: 2026-11-15

観測環境: macOS 26.5.2 (25F84)、カーネル `xnu-12377.121.10~1`、Apple silicon (arm64)。利用者の権限だけで観測した。画面のロックとスリープは起こしていない。観測は解錠中・起きている状態だけで、ロック中とスリープ中の値は観測していない。

背景は `docs/issue/2026-11-09-os-session-event-values.md` と `docs/DESIGN-ja.md` の `os.session` の説明。段階は `boot` < `awake` < `unlocked` で、pin 値は選んだ段階以下の世代の複合。

## 判明した事実

### 実装の現状 (コードを読んで確かめた)

- `procline_macos::boot_session_uuid()` は `sysctlbyname("kern.bootsessionuuid")` を読み、空なら `NotFound` で失敗する
- `procline_macos::wake_time_secs()` は `sysctlbyname("kern.waketime")` の `struct timeval` を読み、`tv_sec` (マイクロ秒は捨てる) を返す。サイズが `struct timeval` と違えば `InvalidData` で失敗する。値が 0 でも検査せずそのまま返す
- `procline_acl_macos` の `os.session` の `observe` は `{"boot": <uuid>, "awake": <wake_time_secs>}` を返す。`unlocked` の field は無く、段階 `unlocked` の pin は `Unobservable` で失敗する。`check` は pin した field が観測値と全部一致した時だけ真

### boot と awake

| 段階 | API | 読めたか | 今の値の形 | 時刻か状態か | 公開か |
|---|---|---|---|---|---|
| `boot` | `sysctl kern.bootsessionuuid` | 読めた | UUID の文字列 | 起動ごとの識別子 (時刻ではない) | 公開の sysctl |
| `boot` (参考) | `sysctl kern.boottime` | 読めた | `struct timeval` | 起動の時刻 | 公開の sysctl |
| `awake` | `sysctl kern.waketime` | 読めた | `struct timeval`。`{sec = 0, usec = 0}` | 起床の時刻 | 公開の sysctl |
| `awake` (参考) | `sysctl kern.sleeptime` | 読めた | `struct timeval`。`{sec = 0, usec = 0}` | スリープに入った時刻 | 公開の sysctl |

- 観測した起動は、起動してから一度もスリープしていない (`pmset -g log` で今の起動に Sleep / Wake / DarkWake が 0 件)。この起動で `kern.waketime` と `kern.sleeptime` は両方とも 0 だった
- 今の実装では、この起動の `os.session` の `observe` は `awake` を 0 として返す (0 は「起床していない」の値で、起床の時刻ではない)
- sysctl は GUI のセッションに依らない API なので、GUI のセッションの外でも読める見込み。ただし観測していない

### unlocked の候補

| API | 読めたか | 今の値の形 | 時刻そのものか状態だけか | 公開か | GUI のセッションの外の見込み |
|---|---|---|---|---|---|
| `CGSessionCopyCurrentDictionary()` | 読めた。11 個の key | 辞書 | 解錠の時刻を持つ key は無かった。`kCGSSessionOnConsoleKey` と `kCGSessionLoginDoneKey` は true (状態) | 関数と on-console / login-done の key は SDK の `CoreGraphics/CGSession.h` にある公開のもの。他の key は公開の約束として確かめていない | ヘッダは「Quartz の GUI のセッションの外では NULL を返す」と書いている |
| IORegistry の root の property (`IORegistryEntryCreateCFProperty`) | 読めた | `IOConsoleLocked` = false、`IOConsoleUsers` はセッションの辞書 1 件、`CGSSessionScreenLockedTime` は null | `IOConsoleLocked` は今ロック中かの状態で、時刻ではない | property の名前と意味は公開の API の約束として確かめていない | 未観測 |
| `notify(3)` (`notify_register_check` + `notify_get_state`) | 12 個の名前すべてで登録と取得が status 0 | state はどれも 0 | 状態の取得では時刻は得られない (state 0 のみ) | `com.apple.coregraphics.*` の 2 つだけ `CGSession.h` に載る。他は探索の候補 | 未観測 |
| 分散通知 (`CFNotificationCenterGetDistributedCenter`) の `com.apple.screenIsLocked` / `com.apple.screenIsUnlocked` | observer の登録はできた。観測の間に事象は無く、配達は未確認 | 通知は時刻を運ばない | 事象の通知 (時刻は受けた側が記録する) | 未確認 | 未観測 |
| `last` | 読めた | 直近の記録は tty のログイン | 画面の解錠ではない | 公開のコマンド | 未観測 |
| `log show` | 読めた (ユーザ権限で loginwindow のロックに関わる記録と時刻) | ログの履歴 | 履歴で、解錠の世代を返す API ではない | 公開のコマンド | 未観測 |

`CGSessionCopyCurrentDictionary()` が返した 11 個の key:

- `CGSSessionUniqueSessionUUID`
- `kCGSSessionAuditIDKey`
- `kCGSSessionGroupIDKey`
- `kCGSSessionLoginwindowSafeLogin`
- `kCGSSessionOnConsoleKey`
- `kCGSSessionSystemSafeBoot`
- `kCGSSessionUserIDKey`
- `kCGSSessionUserNameKey`
- `kCGSessionLoginDoneKey`
- `kCGSessionLongUserNameKey`
- `kSCSecuritySessionID`

`CGSSessionScreenIsLocked` と解錠の時刻を持つ key は、解錠中の今は無かった。

`notify(3)` で試した 12 個の名前:

- `com.apple.screenIsLocked`
- `com.apple.screenIsUnlocked`
- `com.apple.screensaver.didstart`
- `com.apple.screensaver.didstop`
- `com.apple.screensaver.screenIsLocked`
- `com.apple.loginwindow.lockstate`
- `com.apple.loginwindow.screenIsLocked`
- `com.apple.system.loginwindow.lockstate`
- `com.apple.sessionagent.lockstate`
- `com.apple.springboard.lockstate`
- `com.apple.coregraphics.GUIConsoleSessionChanged`
- `com.apple.coregraphics.GUISessionUserChanged`

登録できたことは、OS がその名前で通知を出すことを意味しない。

## 観測から言えること

- 解錠中に「直近の解錠の時刻」を直接返す API は、試した中には無かった
- 通知を受けた時刻を記録する方法は、記録するプロセスが動いていない間の解錠を後から知れない (推論)
- `kern.waketime` は、スリープを経ていない起動で 0 になる

## ロックと解錠をまたいだ観測

通知を受けた時にだけ値を記録するプログラム (分散通知、`notify(3)` の 12 の名前、`IORegisterForSystemPower` を登録し、受けた時点の値を 1 行ずつ書く) を動かしたまま、利用者の普段の操作でロック 2 回と解錠 1 回を記録した。その間にスリープは無かった (`kern.waketime` と `kern.sleeptime` は 0 のまま)。

| 事象 (受けた通知) | `IOConsoleLocked` (IORegistry の root) | `CGSessionCopyCurrentDictionary` のロックの key |
|---|---|---|
| 記録の開始 (解錠中) | false | 無い |
| ロック 1 回目 (`com.apple.screenIsLocked`) | true | `CGSSessionScreenIsLocked` = true、`CGSSessionScreenLockedTime` = ロックの時刻 (epoch 秒) |
| 解錠 (`com.apple.screenIsUnlocked`) | false | `CGSSessionScreenIsLocked` = true、`CGSSessionScreenLockedTime` = 1 回目のロックの時刻のまま |
| ロック 2 回目 (`com.apple.screenIsLocked`) | true | `CGSSessionScreenIsLocked` = true、`CGSSessionScreenLockedTime` = 2 回目のロックの時刻 |

- 分散通知 `com.apple.screenIsLocked` と `com.apple.screenIsUnlocked` は、ロックと解錠のたびに届いた。`notify(3)` の 12 の名前からの通知は、この間 1 つも届かなかった
- ロック中は、`CGSessionCopyCurrentDictionary` に `CGSSessionScreenIsLocked` と `CGSSessionScreenLockedTime` が現れ、後者はロックした時刻。IORegistry の root の `CGSSessionScreenLockedTime` は無いままだった
- 解錠の通知を受けた時点では、`IOConsoleLocked` は false に戻っていたが、`CGSessionCopyCurrentDictionary` のロックの key はまだ残っていた。解錠からしばらく経った状態 (記録の開始の行) では無い。いつ消えるかは測っていない
- 解錠の時刻を持つ値は、どの時点にも無かった
- 記録を 2 日続け、ロック 5 回と解錠 5 回を受けた。解錠の通知を受けた時点の値は揃わなかった: `IOConsoleLocked` は 4 回が false で 1 回は true のまま、`CGSessionCopyCurrentDictionary` のロックの key は 3 回が残り 2 回は消えていた。解錠の通知の直後に読む値は、解錠が済んだ状態を表すとは限らない
- この 2 日の間、スリープは一度も記録されなかった (`kern.waketime` と `kern.sleeptime` は 0 のまま、電源の通知も無い)

観測から言えること: OS の状態として読めるのは「今ロック中か」(`IOConsoleLocked`) と、ロック中の「ロックした時刻」。解錠の時刻は読めず、解錠は通知で知るしかない。通知を受けていなかった間の解錠の時刻を、後から OS に問う方法は、試した中に無い。

## 未観測

ロックとスリープをまたぐ観測が要るもの:

- 解錠の後、`CGSessionCopyCurrentDictionary` のロックの key がいつ消えるか
- スリープと起床をまたいだ値 (最初の起床の後と DarkWake での `kern.waketime` / `kern.sleeptime`、電源の通知の配達)
- スクリーンセーバーだけ (ロックなし) の時の値と通知

別の環境:

- GUI のセッションの外 (ssh のシェル、LaunchDaemon) からの各 API
- 他の版の macOS
