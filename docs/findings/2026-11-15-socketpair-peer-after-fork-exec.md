# UNIX ドメインソケットの相手の pid と audit token は、getsockopt した時点で相手側の端を最後に送受信に使ったプロセスを指し、資格情報はその時点の値になる

- Date: 2026-11-15

観測環境: macOS 26.5.2 (25F84)、カーネル `xnu-12377.121.10~1`、Apple silicon (arm64)。利用者 (uid 501) の権限だけで観測した。sudo は使っていない。

## 判明した事実

役の名前: A = ソケットを作ったプロセス (名前付きのソケットでは connect した側)、R = 片方の端だけを持つ読み手 (名前付きでは accept した側)、W = 相手側の端を持つ、A とは別のプロセス。R が自分の端で `getsockopt(SOL_LOCAL, …)` の `LOCAL_PEERPID`、`LOCAL_PEEREPID`、`LOCAL_PEERTOKEN`、`LOCAL_PEERCRED` を読む。

SOCK_STREAM の socketpair、SOCK_DGRAM の socketpair、名前付きの SOCK_STREAM (bind / listen / connect / accept) の 3 種類のそれぞれで、下の 12 組を 2 回ずつ (計 72 回) 測った。R の測定は 276 点で、3 種類・2 回の全部で同じ遷移になった。

| 組 | 観測 |
|---|---|
| 1. A が作る → fork で R → 何も書かずに R が読む | A |
| 2. A が作る → fork で R → R が自分自身を exec → 読む | A。pidversion は、A が fork の前に自分の端で読んだ相手 (A 自身) の値と同じ |
| 3. A が write する前 → write した後 → R がそのバイトを read した後 | A → A → A |
| 4. A が作る → fork で R と W → W が write する前 / 後 → A が write した後 | A → W → A。token の pidversion もそれぞれのプロセスの値 |
| 4 の詳細: 相手側の端での操作ごと | W の `getsockopt` だけ: 変わらない (A のまま)。W の read: A → W。W の write: A → W。W の sendmsg: A → W。A の write: W → A。A の sendmsg: W → A。W の recvmsg: W のまま (直前が既に W で、recvmsg だけで変わることは切り分けていない)。R 自身の read / recvmsg / `getsockopt` では変わらない |
| 5. A が端に触れずに、setuid でないバイナリ (`/bin/sleep`) を exec | pid は A のまま。token の pidversion が変わる (例: 14556031 → 14556033)。euid / ruid は 501 / 501 のまま |
| 5 の補助: A が write してから exec → R がそのバイトを read | pidversion は exec の境目で変わり、exec の前に書かれたバイトを read した後も exec の後の値 |
| 6. A が端に触れずに、setuid root のプログラム (`/usr/bin/top`) を exec | pid は A のまま。token の euid / ruid が 501 / 501 → 0 / 501 になり、pidversion が変わる。asid は同じ。`LOCAL_PEERCRED` の uid は 501 のまま |
| 6 の補助: A が write → setuid root のプログラムを exec → R が先のバイトを read | token の euid: 書く前 501 → 書いた後 501 → exec の後 0 → exec の前に書かれたバイトを read した後も 0 |
| 7. 相手側の端を持つプロセスが全部終わってから R が読む | `LOCAL_PEERPID` / `LOCAL_PEEREPID` / `LOCAL_PEERTOKEN` は errno 57 (`ENOTCONN`)。SOCK_STREAM の socketpair と名前付きでは、`LOCAL_PEERCRED` の uid 501 が残る |
| 8. A が相手側の端を `SCM_RIGHTS` で W に渡す (W は A の子でなく、A がソケットを作る前に fork したプロセス) → W が write | A → W |
| 9. SOCK_DGRAM の socketpair | 1〜8 と同じ遷移。`LOCAL_PEERCRED` は常に errno 22 (`EINVAL`) |
| 10. 名前付きのソケット (R が accept した端、A が connect した端) | 1〜8 と同じ遷移 |

- 正常に読めた測定では、常に `LOCAL_PEERPID` = `LOCAL_PEEREPID` = token の pid だった (委譲の設定はしていない)
- A が作った直後に自分の端で読んだ相手の pid は A 自身だった (組 2 で fork の前に測った。この時、両方の端を A しか持っていない)
- pipe の読み側の fd に `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` を呼ぶと、`ENOTSOCK` (errno 38、Socket operation on non-socket) で失敗した。pipe からは、書き込み側を持つプロセスをカーネルに問えない (この点は今回の組では測り直していない。1 回の観測)

## 観測から言える規則

観測した操作 (read / write / sendmsg / recvmsg / getsockopt / exec / `SCM_RIGHTS` での受け渡し)、同じ uid、この OS の範囲で:

- 接続が続いている間、`LOCAL_PEERPID` と `LOCAL_PEERTOKEN` は、相手側の端で最後に送受信 (write / read / sendmsg / recvmsg) をしたプロセスに対応する。どのプロセスも送受信していない間は、作ったプロセス (名前付きでは connect したプロセス)
- token の euid・ruid・pidversion は、読み手が `getsockopt` した時点の、そのプロセスの値。そのプロセスが exec していれば exec の後の値になる。書かれたバイトがいつ書かれたかには結び付かない
- `LOCAL_PEERCRED` の uid は、接続の時 (socketpair を作った時、connect した時) の値のまま変わらない。SOCK_DGRAM の socketpair では取れない
- 相手側の端を持つプロセスが全部終わると、`LOCAL_PEERPID` / `LOCAL_PEERTOKEN` は `ENOTCONN` で失敗する

## 実用的な示唆

ここからは観測からの推論。

- 読み手が相手の token から知れるのは、「`getsockopt` した時点で、相手側の端を最後に送受信に使ったと記録されているプロセスの、その時点の資格情報」。接続に要求を書いたプロセス、または書いた時の実行イメージと一致するとは限らない
  - 書いた後に exec すれば、token は exec の後の実行イメージと資格情報になる (組 5、組 6 の補助)
  - 相手側の端を持つ別のプロセスが送受信すれば、token はそのプロセスになる (組 4、組 8)
- 「相手が root である」「相手が特定のバイナリである」ことは、要求を書いたのがその root、そのバイナリであることを示さない。権限の無いプロセスが、書いた後に自分で setuid のプログラムや他のバイナリを exec すれば、token はその条件を満たす (組 6 の補助は、uid 501 のプロセスが書いた後に setuid root のプログラムを exec して euid 0 の token になった観測)
- 端を作ったプロセスを、読み手が後からカーネルの値で名指す手段にはならない。名指せるのは「今、相手側の端を最後に使ったと記録されているプロセス」
- `LOCAL_PEERCRED` と `LOCAL_PEERTOKEN` は、同じ接続について別の時点の資格情報を返しうる (組 6 では uid 501 と euid 0)
- pipe でも socketpair でも、書き込み側の端を持てるのは、作ったプロセスと、それが fork で引き継がせたか fd を渡したプロセスだけ (fd の性質で、ここでは観測していない)。pipe では書き込み側をカーネルに問えず、「書いたのは自分を起動した側」は起動の手順から言うことになる

## 検証の詳細

### 手順

C の試験プログラム 1 つ (約 220 行、`clang … -lbsm`)。引数でソケットの種類 (SOCK_STREAM の socketpair / SOCK_DGRAM の socketpair / 名前付き) と組を選び、組ごとに 2 回動かした。

- 起動したプロセスが A を fork し、A がソケットを作ってから R を fork する。名前付きでは、A が一時ディレクトリの下のパスに bind / listen し、R が accept、A が別のソケットで connect する。R は A が作った端 (名前付きでは accept した端) だけを持ち、相手側の端を閉じる
- W は、組 4 では A が R の後に fork し、相手側の端を引き継ぐ。組 8 では、起動したプロセスが A より先に fork した W に、A が `SCM_RIGHTS` で相手側の端を渡す
- R の 1 回の測定で、自分の端に `LOCAL_PEERPID`、`LOCAL_PEEREPID`、`LOCAL_PEERTOKEN` (`audit_token_to_pid`、`audit_token_to_pidversion`、`audit_token_to_euid`、`audit_token_to_ruid`、`audit_token_to_asid`)、`LOCAL_PEERCRED` (`cr_uid`) を読み、それぞれの errno も記録する
- A、R、W は、それぞれ専用の pipe で 1 バイトの命令を受け、操作を終えてから同じ 1 バイトの ack を返す (操作は read / write / sendmsg / recvmsg / `getsockopt` / 測定)。起動したプロセスが命令を 1 つ送って ack を待ってから次を送るので、操作と測定の順序は命令の順に固定される。R の測定結果は別の pipe で起動したプロセスに送って出力する
- 組 7 は、相手側の端を持つプロセスを全部 `_exit` させ、`waitpid` で回収してから R に測らせた
- A の exec (組 5、組 6) は、起動したプロセスが先に A の `kqueue` の `EVFILT_PROC` (`NOTE_EXEC`) を登録してから A に exec を命じ、`NOTE_EXEC` を受けたうえで `proc_pidpath(A)` が exec 先のパスに変わったことを確かめてから R に測らせた。setuid root の `top` は `-l 999 -s 60` で起動して出力を `/dev/null` に向け、測定の後に `SIGKILL` で止めた

### 実出力の例

組 6 の補助 (SOCK_STREAM の socketpair)。A = 97274。測定は順に「A が書く前」「A が書いた後」「exec の後」「R が先のバイトを read した後」。

```
R snapshot1 self=97275 peerpid=97274/0 peerepid=97274/0 tokenpid=97274 pidversion=14556061 euid=501 ruid=501 asid=100596/0 xucred_uid=501/0
R snapshot2 self=97275 peerpid=97274/0 peerepid=97274/0 tokenpid=97274 pidversion=14556061 euid=501 ruid=501 asid=100596/0 xucred_uid=501/0
exec-confirmed A=97274 note=0x20000000 path=/usr/bin/top expected=/usr/bin/top
R snapshot3 self=97275 peerpid=97274/0 peerepid=97274/0 tokenpid=97274 pidversion=14556063 euid=0 ruid=501 asid=100596/0 xucred_uid=501/0
R snapshot4 self=97275 peerpid=97274/0 peerepid=97274/0 tokenpid=97274 pidversion=14556063 euid=0 ruid=501 asid=100596/0 xucred_uid=501/0
```

組 8 (SOCK_STREAM の socketpair)。A = 97235、W = 97234 (A より先に起動)。測定は順に「W が書く前」「W が書いた後」「R が read した後」。

```
R snapshot1 self=97236 peerpid=97235/0 peerepid=97235/0 tokenpid=97235 pidversion=14556004 euid=501 ruid=501 asid=100596/0 xucred_uid=501/0
R snapshot2 self=97236 peerpid=97234/0 peerepid=97234/0 tokenpid=97234 pidversion=14556003 euid=501 ruid=501 asid=100596/0 xucred_uid=501/0
R snapshot3 self=97236 peerpid=97234/0 peerepid=97234/0 tokenpid=97234 pidversion=14556003 euid=501 ruid=501 asid=100596/0 xucred_uid=501/0
```

`/0` の後ろは errno (0 は成功)。

### XNU の公開ソースとの照合

この Mac のカーネルは `xnu-12377.121.10` で、公開されている最も近い版 `xnu-12377.121.6` を読んだ。版が違うので、観測と矛盾しないかを見る資料として扱う。

- `bsd/kern/uipc_usrreq.c` の `uipc_ctloutput` (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/uipc_usrreq.c):
  - `LOCAL_PEERPID` は、接続先の socket (`unp->unp_conn->unp_socket`) の `last_pid` を返す。`LOCAL_PEEREPID` は、接続先に委譲の印 (`SOF_DELEGATED`) があれば `e_pid`、無ければ同じく `last_pid`
  - `LOCAL_PEERTOKEN` は、接続先の `last_pid` を `proc_find` し、その時点の task から `task_info(…, TASK_AUDIT_TOKEN, …)` で token を取る。接続の時に保存した token を返す形ではない。`proc_find` が失敗すると `EINVAL`
  - `unp_conn` が無ければ (接続が切れていれば) 3 つとも `ENOTCONN`
  - `LOCAL_PEERCRED` は、自分の端の `unp_peercred` を返す。無い時は SOCK_STREAM なら `ENOTCONN`、それ以外は `EINVAL`。`unp_peercred` は接続の時に書く (`unp_connect` で connect した側の資格情報と listen した側の資格情報を写し、`unp_connect2` は SOCK_STREAM の socketpair でだけ作ったプロセスの資格情報を両方の端に写す)。SOCK_DGRAM の socketpair が `EINVAL` になる観測と合う
- `bsd/kern/uipc_socket.c` の `so_update_last_owner_locked` (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/uipc_socket.c) が、その socket の `last_pid` と `last_upid` を呼んだプロセスの値に書き換える。呼ぶのは `sosend` と `soreceive` (read / write / sendmsg / recvmsg が通る) のほか、`sobindlock`、`solisten`、`soacceptlock`、`soconnectlock`、`soconnectxlocked`、`sosend_list`、`soreceive_m_list`。`getsockopt` は通らない
- 観測の規則 (相手側の端を最後に送受信に使ったプロセス、資格情報は読んだ時点の値、exec しても pid は同じなので exec の後の値) は、このソースの読みと合う

ソースからの推測 (観測していない):

- `LOCAL_PEERPID` と `LOCAL_PEERTOKEN` は `last_upid` を見ず、`last_pid` だけで引く。最後に送受信に使ったプロセスが終わり、相手側の端を別のプロセスがまだ開いている間は、`LOCAL_PEERTOKEN` は `EINVAL` になるか、その pid を後から使ったプロセスの token になりうる
- `last_pid` は bind / listen / accept / connect でも書き換わる

## 未観測

- 作ったプロセスが root で、子が降格して exec した組
- 委譲 (`LOCAL_PEEREPID` が別の pid になる設定)
- 最後に送受信に使ったプロセスが終わり、相手側の端を別のプロセスがまだ持っている間に読んだ値 (上の推測)
- 上に挙げた以外の syscall (`sendfile`、`writev` / `readv`、list 版の送受信、`shutdown` など)
- 別の uid のプロセスが相手側の端を使う組
- 他の版の macOS
- crate の `collect_peer` を通した照合 (収集の最初と最後で token を読み比べる処理を含む)
- pipe の `ENOTSOCK` の測り直し
