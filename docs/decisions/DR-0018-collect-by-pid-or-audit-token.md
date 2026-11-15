# DR-0018: 収集の入口は、対象のプロセスを pid か audit token で受ける 2 つにする

- Status: Active
- Date: 2026-11-16

## Context

procline の収集は、指されたプロセスとその祖先を集める。呼ぶ側が対象を指す手段は、pid と audit token の 2 つ。audit token は、ソケットの相手、XPC のメッセージ、自分自身など、呼ぶ側の使い方によって出どころが違う。

- 目的: 呼ぶ側が指したプロセスとその祖先を集め、指された個体と集めた個体の取り違えを、確かめられる範囲で結果に出す
- 増やしたくないもの: 収集の入口が受け取る、プロセス以外のもの (ソケット、接続、メッセージのような通信路の知識)

## Decision

収集の入口は、対象のプロセスを pid か audit token で受ける 2 つにする。ソケットや接続を受ける入口は持たない。

```rust
pub fn collect_pid(pid: i32, options: &CollectOptions) -> Result<ProcessChain, CollectError>;
pub fn collect_audit_token(token: AuditToken, options: &CollectOptions) -> Result<ProcessChain, CollectError>;
```

`collect_audit_token` が保証すること:

- token の pid の個体を対象として集める。識別子が取れた時は、対象の `p_idversion` が token の pidversion と一致する。一致しなければ `IdentityChanged` (token を得た後に対象が exec した時や、token の pid が別のプロセスに割り当て直された時)
- 収集の最後の識別子の確認は `collect_pid` と同じ
- 対象の行の `identity.audit_token` と `identity.asid` は token から入り、対象の署名は audit token で検証する

保証しないこと: token が誰のものか、どこから得たか。それは procline の責務外。

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| ソケットを受ける入口 (`collect_peer`) を持つ | procline が扱うのはプロセスで、通信路ではない。token の出どころ (ソケット、XPC、自分自身) ごとに入口が増える |
| 対象を表す型 (enum) を足して入口を 1 つにする | 指し方が 2 つなら関数 2 つで足り、型を増やさない |

## Consequences

- アプリは token を自分で得て `collect_audit_token` に渡す
- ソケットの相手の token が何を表すか ([findings](../findings/2026-11-15-socketpair-peer-after-fork-exec.md) に観測がある) は、token を得るアプリが扱う
- `CollectError` は通信路の失敗を持たない

## 関連

- [DR-0014](DR-0014-chain-trust-boundary-and-caller-supplied-values.md): chain の出どころと、収集の入口が呼び出し元の値を受けないこと
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md): audit token で SecCode を得る署名の検証
- [DESIGN-ja の「概要」「識別子」「収集の整合性」「API の骨格」](../DESIGN-ja.md)
