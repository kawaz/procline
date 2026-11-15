# socketpair の相手の pid と audit token は、fork と exec の後も socketpair を作ったプロセスを指す

- Date: 2026-11-15

観測環境: macOS 26.5.2、Apple M1 Max。利用者の権限だけで、1 回観測した。

## 判明した事実

- 親が `socketpair(AF_UNIX, SOCK_STREAM)` を作って fork し、子が片方の端だけを持って自分自身を exec した後、子の端の `LOCAL_PEERPID` と `LOCAL_PEERTOKEN` (の pid) は、socketpair を作った親の pid を返した。pidversion は、親が自分の端で読んだ値と同じだった
- 親が作った直後に自分の端 (`sv[0]`) で読んでも、相手の pid は親自身だった。socketpair の相手の資格情報は、作ったプロセスのもので、その時に相手の端を持っているプロセスではない

## 実用的な示唆

- 呼び出し元が socketpair を作って片方の端を子 (helper) に渡せば、子はその端の audit token から、作ったプロセスをカーネルの値で知れる。procline の `collect_peer` はこの audit token で対象を決める
- 指すのは「作ったプロセス」で、「今、相手の端に書いているプロセス」ではない。端を別のプロセスに渡す (fd を渡す、作った後に fork した別の子が書く) と食い違う

## 検証の詳細

C 言語の試験プログラム (約 50 行、`clang -O2 … -lbsm`):

1. 親が `socketpair` を作り、自分の端 `sv[0]` で `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` と `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` を読む (`audit_token_to_pid`、`audit_token_to_pidversion`)
2. fork し、子は `sv[0]` を閉じて、`sv[1]` の番号を引数に自分自身を `execl` する
3. exec した子が `sv[1]` で同じ 2 つを読む

```
parent pid=24854
parent-end0 pid=24854 ppid=24850 peerpid=24854(r=0) token_pid=24854(r=0) token_pidversion=13559630
child-after-exec pid=24862 ppid=24854 peerpid=24854(r=0) token_pid=24854(r=0) token_pidversion=13559630
```

## 未観測

- 作ったプロセスが root (setuid の `sudo` の中の PAM モジュール) で、子が降格して exec した組
- 作ったプロセスが終わった後に、相手の端で読んだ値
- 端を `SCM_RIGHTS` で別のプロセスに渡した場合
- この audit token で `collect_peer` を呼んだ時の列 (pidversion の照合を含む)
