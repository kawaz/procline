---
title: 接続相手の audit token は、読んだ時点で相手側の端を最後に使ったプロセスを表し、要求を書いたプロセスを表さない
status: open
category: design
created: 2026-11-15T18:12:25+09:00
origin: 自リポ TODO (UNIX ドメインソケットの相手の観測から)
---

# 接続相手の audit token は、読んだ時点で相手側の端を最後に使ったプロセスを表し、要求を書いたプロセスを表さない

## 概要

設計文書は、`collect_peer` が集める対象を「接続相手」と呼び、audit token を「強」の識別子として、接続相手のプロセスを特定するものとして扱っている。観測 ([findings](../findings/2026-11-15-socketpair-peer-after-fork-exec.md)) では、`LOCAL_PEERPID` / `LOCAL_PEERTOKEN` が表すのは「`getsockopt` した時点で、相手側の端を最後に送受信 (write / read / sendmsg / recvmsg) に使ったプロセスの、その時点の資格情報」だった。これは「接続相手のプロセス」より弱い。

- 要求を書いた後に相手が exec すると、token は exec の後の実行イメージと資格情報になる (setuid root のプログラムなら euid 0、pid は同じ)
- 相手側の端を持つ別のプロセス (fork で引き継いだ子、`SCM_RIGHTS` で受け取ったプロセス) が送受信すると、token はそのプロセスになる
- 「相手が root である」「相手が特定のバイナリである」は、要求を書いたのがその root・そのバイナリであることを示さない

DESIGN (ja/en) の「識別子」の表と「収集の整合性」の 3 は、この観測に合わせて事実の記述だけを直した。保証の言い方・強さ・対策は決めていない。

## 背景 (事実)

- 観測: 同じ uid (501)、SOCK_STREAM / SOCK_DGRAM の socketpair と名前付きの SOCK_STREAM の 3 種類、12 の組を 2 回ずつ。全部で同じ遷移 (findings の表)
- 観測 (findings の組 11・12): 相手側の端を別のプロセスが持ったまま、最後に送受信に使ったプロセスが終わると、`LOCAL_PEERTOKEN` は `EINVAL` (`ENOTCONN` ではない)。その pid が別のプロセスに割り当て直されると、そのプロセスの token が返る
- XNU の公開ソース (`xnu-12377.121.6`。実機の版とは違う): `LOCAL_PEERTOKEN` は接続先の socket の `last_pid` を `proc_find` し、その時点の task から token を取る。`last_pid` は `sosend` / `soreceive` などで書き換わる
- `collect_peer` (`crates/procline-macos/src/collect.rs`) は、最初に token を読んで pid と pidversion で対象を決め、収集の最後に token を読み直して、違えば `IdentityChanged` にする。この読み直しは、収集の間に相手側の端を別のプロセスが送受信に使った場合も `IdentityChanged` にする、とコードからは読める (`collect_peer` を通しては観測していない)
- 要求が書かれてから `collect_peer` が最初に token を読むまでの間の exec や送受信は、この読み直しでは分からない (token は最初から変わった後の値になる。観測からの推論)

## 設計上の問い (決めていない)

### (a) `collect_peer` が集めたプロセスについて、procline が保証することの言い方

「収集の時点で、相手側の端を最後に送受信に使ったプロセス」と言うか。「接続相手」「接続元プロセス」(DESIGN の題を含む) の語をそのまま使うか、定義を添えるか、言い換えるか。

### (b) 接続相手の token に依る記述・コードの一覧 (評価はしない)

DESIGN-ja (DESIGN.md も同じ箇所):

- 題「接続元プロセスの情報収集と ACL 設計」、概要の「収集の入口は UNIX ドメインソケットの接続相手(audit token)が主」、使い方の型の「接続相手を集め」
- 設計の柱 1「接続相手は audit token、祖先はプロセスごとに一意な ID で特定し、pid の再利用で取り違えない」。接続相手については観測と食い違う: token は相手側の端を最後に使ったプロセスの pid で引かれ、そのプロセスが終わった後に pid が再利用されると、無関係のプロセスの token が返る (findings の組 12)
- 「識別子」の表: audit token (強)、pid と起動時刻の備考 (pidversion で exec を検出する)、asid (強。audit token から取り、`os.login_session` の pin 値)
- 識別子の後の段落: audit token、unique\_id、pid と起動時刻が個体識別の `process` 1 項目に畳まれる (対象の行の `process` は token の pid で決めた個体)
- 「プロセスの属性」の uid・gid: 接続相手の行は、token の pid の `kinfo_proc` から取った、収集した時点の実効 uid (`LOCAL_PEERCRED` の接続の時の uid は使わない。findings の組 6)
- 「プロセスの属性」のコード署名と「署名の検証と信頼の印」の手順 1: 接続相手の SecCode は audit token で得る
- 「収集の整合性」の 1〜3
- 「部品」の表と「grant」の「承認の瞬間の接続相手」
- 条件の語彙: `os.not_remote` (接続相手の asid)、`os.login_session` (接続相手の asid を pin)、`Condition::pin` のコメント、状態型の表と説明

DR:

- [DR-0005](../decisions/DR-0005-process-identity-as-one-item.md): 接続相手には audit token がある、`process` 1 項目
- [DR-0008](../decisions/DR-0008-evaluation-semantics.md): `os.not_remote` の判定を接続相手の asid だけで行う、`os.login_session`
- [DR-0004](../decisions/DR-0004-rule-grant-split-and-condition-advance.md): grant は承認の瞬間の接続相手に適用する、`os.login_session` の pin
- [DR-0011](../decisions/DR-0011-verified-signature-and-trust-mark.md): 接続相手の SecCode を audit token (`kSecGuestAttributeAudit`) で得る
- [DR-0014](../decisions/DR-0014-chain-trust-boundary-and-caller-supplied-values.md): 送り手と受け渡しの経路、`collect_peer` を「アプリが決めること」の道具として挙げる箇所。Context の「同じ uid の別プロセスが評価に混ぜられるのは、アプリが外から受け取るバイト列だけ」

コード:

- `crates/procline-macos/src/collect.rs` の `collect_peer` (token で対象を決める、pidversion の照合、最後の読み直し)、`process_info` (対象の行の `identity.audit_token` と `identity.asid` を token から入れる)、`signatures` (対象の行の署名を `Guest::AuditToken` で検証する)
- `crates/procline-macos/src/lib.rs` の `collect_peer` の doc と `CollectError::Peer` の doc (「`ENOTCONN` when the peer has already exited」。観測では、相手側の端を持つプロセスが全部終わった時の値)
- `crates/procline-acl-macos/src/os_items.rs` の `os.login_session` (対象の行の asid を pin する)

### (c) 食い違いを procline が扱うか、アプリの責務として境界に書くか

要求を書いた後に別の実行イメージへ exec する、相手側の端を別のプロセスに使わせる、といった食い違いを、procline が扱うか、アプリのプロトコルの責務として DESIGN の境界に書くか。

脅威モデル (守る相手は同じ uid の別プロセス。root と評価するアプリ自身は範囲外) の上で、同じ uid の別プロセスにできること・できないこと:

- できる (観測): 要求を書いた後に、自分で別のバイナリを exec する。token の pid は同じまま、実行イメージ (pidversion) と資格情報が exec の後のものになる。setuid root のプログラムを exec すれば euid 0 になる。asid は変わらない
- できる (観測): fork で端を引き継いだ子や、`SCM_RIGHTS` で端を渡したプロセスが送受信すれば、token はそのプロセスになる
- 許可された他のプロセスに自分の端を使わせるには、そのプロセスに端を持たせ (fork で引き継がせるか、fd を渡して受け取らせる)、送受信させる必要がある (観測した遷移は、全部が端を持つプロセスの送受信によるもの)
- 推測 (観測していない): 自分の子に端を標準入出力として引き継がせ、許可されたバイナリを exec させれば、そのバイナリが普段どおり読み書きするだけで token はそのプロセスになる。fd を受け取って読み書きするプロトコルを持つプロセスにも同じことができる
- できる (観測): 相手側の端を自分で持ったまま、端に write した子を終わらせ、fork を繰り返して pid を一巡させる。子が終わった後は `LOCAL_PEERTOKEN` は `EINVAL` になり (`LOCAL_PEERPID` は終わった子の pid を返し続ける)、その pid が別のプロセスに割り当て直されると、ソケットで送受信していないそのプロセスの token が返る。pid の一巡は uid 501 のプロセスで約 9.8 万回の fork、48 秒で起きた (findings の組 11・12。XNU の公開ソースでも `LOCAL_PEERTOKEN` は `last_pid` を `proc_find` で引き、`last_upid` を照合しない)
- どのプロセスがその pid を得るかは選べない (推測)。ただし、自分の子に得させることはできる (観測: 一巡させたプロセス自身の子が得た。その子は fork で相手側の端の fd を引き継いでいた)
- 推測 (観測していない): その pid を得させた子に、許可されたバイナリを exec させれば、token はそのバイナリの実行イメージと資格情報になる (組 5・6 の exec の観測と組 12 の組み合わせ)
- 観測した中では、`getsockopt` だけ・読み手自身の送受信・読み手の exec では、token は変わらなかった

対策の案 (名前だけ。採否は書かない):

- 要求を読んだ直後に token を読む手順をアプリのプロトコルとして書く
- 要求の前後で token を読み比べる
- 送り手に自分の識別子を書かせて token と照らす
- `LOCAL_PEERCRED` と token の食い違いを印にする

## 受け入れ条件

- [ ] (a)〜(c) の採否を決める
- [ ] 決めたことを DESIGN (ja/en) と DR に反映する

## 関連

- [findings: UNIX ドメインソケットの相手](../findings/2026-11-15-socketpair-peer-after-fork-exec.md)
- [findings: audit token と kSecGuestAttributeDynamicCode](../findings/2026-11-15-audit-token-dynamic-code.md) (token を読んだ後に相手が exec した場合の検証)
- [DR-0014](../decisions/DR-0014-chain-trust-boundary-and-caller-supplied-values.md)
