# DR-0014: 評価に渡す chain は評価するプロセスが自分で収集したものに限り、型で JSON からの経路を閉じる。呼び出し元が渡す値は chain に入れず、受け取ったアプリが持つ

- Status: Proposed
- Date: 2026-11-15

## Context

評価 (`Policy::tag`、`grant`、`resolve_subject`、`evaluate`、`explain`、条件の `pin` / `check`) は、渡された chain の中身を事実として扱う。保護の状態 ([DR-0012](DR-0012-strength-class-from-protection.md)) と署名由来の条件は `CodeSigning::Verified` の `runtime` と `entitlements` から、途切れた列の判定 ([DR-0008](DR-0008-evaluation-semantics.md)) は `truncated` から、タグは `TaggedChain` から決まる。今の型は、収集していない値からもこれらを作れる。

- `ProcessChain`、`ProcessInfo`、`CodeSigning` は `Deserialize` を持つ。`CodeSigning` の読み込みが確かめるのは `mark` と事実の整合だけで ([DR-0011](DR-0011-verified-signature-and-trust-mark.md))、`runtime`、`entitlements`、証明書の根が実際に検証された値かは JSON からは確かめようがない。送り手が `hardened_runtime: true`、`debugged: false`、`entitlements: null` と書けば保護ありと判定され、署名由来の条件が強になり、制約なしの `allow` が採用されうる (issue `2026-11-15-deserialized-chain-is-trusted-by-evaluate`。レビューの読み取りによる指摘で、再現のテストは無い)
- `ProcessChain::new` は公開で、`boot_uuid` と `truncated` は公開の field。収集した chain の `truncated` を `None` にすれば、判定できない grant (`undecidable`) が判定できたことになる
- `TaggedChain` の field (`chain`、`tags`、`undecidable_tags`) は全部公開で、`Policy::tag` を通さずに任意のタグを付けた値を `evaluate` に渡せる

もう 1 つ、ユーザ権限で収集する時に取れない値の扱いが要る。pam-passkey は、祖先の収集と署名の検証を root の PAM モジュールからユーザ権限の helper に移す (pam-passkey の issue `2026-11-15-collect-in-helper-with-procline`)。

- argv (`KERN_PROCARGS2`) と cwd (`PROC_PIDVNODEPATHINFO`) は、同じ uid か root からしか取れない (別 uid では `EPERM`、[findings](../findings/2026-11-09-collect-pid-observations.md))。走っている `sudo` (実効 uid 0) の argv と cwd は helper から取れない。署名は、カーネルが持つ署名で検証する手順でユーザ権限から `anchor apple` まで確かめられる ([DR-0011](DR-0011-verified-signature-and-trust-mark.md))
- PAM モジュールは `sudo` のプロセスの中にいて、自分の argv と cwd を helper に渡せる。渡された値は呼び出し元が自分について主張するもので、procline が収集したものではない
- helper は PAM モジュールが fork し、子の中で降格して exec したもの (pam-passkey の DR-0003)。helper の親は走っている `sudo`
- 祖先の walk は、`kinfo_proc` の ppid で親を読み、親の `p_uniqueid` と子の `p_puniqueid` の一致で親子を確かめる。どちらも uid を問わず読め (実効 uid 0 のプロセスも、[findings](../findings/2026-11-15-puniqueid-after-reparent-and-exec.md))、`p_puniqueid` はカーネルが fork と exec の時に、その時の親の `p_uniqueid` で書く。自分の pid で `collect_pid` を呼ぶと、列の先頭が自分、2 番目が親になる (自分の列を集めて観測。親子は unique ID で繋がった)

chain を外から受け取って評価したい利用者は、今は見当たらない。pam-passkey は照合を使わず (DESIGN-ja「構成」)、cw は接続相手を自分で収集して評価する (DESIGN-ja「概要」。cw のリポは手元に無く、実装は確かめていない)。このリポで `ProcessChain` を JSON から読むのは、`collect_pid` の往復のテストだけ。

Rust の可視性では、ある crate の型の構築を別の特定の crate (OS ごとの収集の crate) にだけ許すことはできない。procline-macos が chain を組む関数は公開になり、アプリからも呼べる。

- 目的: 評価の判定が、評価するプロセスが自分で OS から確かめた事実だけに基づく。呼び出し元の主張は、確かめた事実と同じ型で運ばれない
- 増やしたくないもの:
  - 評価の入口と、chain を表す型の数
  - 収集の入口が受け取る呼び出し元の主張
  - 呼び出し元の主張を信じる箇所 (主張でなくカーネルの値で確かめられるものは、カーネルの値で確かめる)

## Decision

### 信頼境界

- 評価に渡す chain は、評価するプロセス自身が収集の入口 (`collect_peer`、`collect_pid`) で集めたもの。他のプロセスから受け取った chain や値 (JSON、引数、標準入力) は表示にだけ使う
- 型で止めるのは、アプリが外から受け取った値を評価に渡してしまう誤用。評価するアプリ自身は範囲外 (DESIGN-ja「脅威モデルの前提」) なので、アプリのコードが明示して組み立てた chain は止めない。明示の組み立ては、名前で呼び出し箇所を探せる 1 つの関数に限る

### 型

```rust
// procline-core
/// Deserialize を持たない。Serialize は表示、ログ、dump、他のプロセスへの受け渡しのために持つ
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessChain {
    processes: Vec<ProcessInfo>,
    boot_uuid: String,
    truncated: Option<Truncated>,
}

impl ProcessChain {
    /// 収集の入口とテストが使う。呼び出し側が「この値はこのプロセスが OS から収集した」と表明する。
    /// 外から受け取った値 (JSON 等) から chain を組むのには使わない
    pub fn from_collected(processes: Vec<ProcessInfo>, boot_uuid: String, truncated: Option<Truncated>) -> Self;
    pub fn processes(&self) -> &[ProcessInfo];
    pub fn boot_uuid(&self) -> &str;
    pub fn truncated(&self) -> Option<Truncated>;
}

// procline-acl
/// 作れるのは Policy::tag だけ (構築は crate の中に閉じる)
pub struct TaggedChain<'a> {
    vocab: &'a Vocabulary,
    chain: &'a ProcessChain,
    tags: Vec<BTreeSet<String>>,
    undecidable_tags: BTreeSet<String>,
}

impl<'a> TaggedChain<'a> {
    pub fn chain(&self) -> &'a ProcessChain;
    /// chain.processes() と添字が揃う
    pub fn tags(&self) -> &[BTreeSet<String>];
    pub fn undecidable_tags(&self) -> &BTreeSet<String>;
}
```

- `ProcessChain` から `Deserialize` を外し、field を全部非公開にする。JSON から読んだ値は `ProcessChain` にならず、評価の入口はコンパイルの段で受け付けない
- `ProcessChain::new` は `from_collected` にする。名前で、呼び出す側が収集した値だと表明していることが読める
- `TaggedChain` は field を非公開にし、作るのは `Policy::tag` だけにする (procline-acl の中で閉じるので、型で強制できる)
- `ProcessInfo`、`CodeSigning` などの `Deserialize` は残す。DR-0011 の JSON の読み込みの規則 (`mark` を事実から決め直し、一致しなければエラー) は変えない。読んだ値は表示に使えるが、`from_collected` を呼ばない限り chain にならない
- JSON から読んだ chain を評価に使う入口は持たない

### 呼び出し元が渡す値

- 収集の入口は、呼び出し元が渡す値 (argv、cwd など) を受け取らず、chain に入れない
- 値を受け取ったアプリが持ち、表示で「呼び出し元が渡した値」として出す。照合には使わない (強さのクラスを持たない)
- どのプロセスの値かは、アプリが chain の識別子で確かめる。呼び出し元が起動した helper は、自分の pid で `collect_pid` を呼ぶ。列の 2 番目が自分の親で、親子の関係は walk がカーネルの値 (`p_puniqueid` と親の `p_uniqueid`) で確かめている。呼び出し元の主張する識別子を信じずに済む
  - 親が収集の途中か前に終わっていれば、列は自分だけで `AncestorExited` で終わる。どう扱うか (要求を進めない等) はアプリが決める
  - 列の先頭 (自分) を表示に出すかはアプリが決める
- 列の 2 番目以降の、別 uid のプロセスの argv と cwd は取れないまま (`None`) にする

### DESIGN に書くこと

- 「脅威モデルの前提」: 評価に渡す chain は、評価するプロセスが自分で収集したもの。他のプロセスから受け取った chain や値は表示にだけ使い、型 (`ProcessChain` は JSON から作れない) でこの経路を閉じる
- 「収集する情報」: argv と cwd を取れない対象について、呼び出し元が渡す値は crate の外 (受け取ったアプリ) が持つこと
- 「API の骨格」: `ProcessChain` と `TaggedChain` のアクセサ

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 収集の入口が、対象の識別子と渡された argv・cwd を受け、識別子が一致すれば列の先頭に入れる (issue の案) | 収集した事実と呼び出し元の主張が同じ field に入り、`argv` と `cwd` の照合が主張をそのまま照合する。評価の入力は収集した事実だけ、という境界 (上) が崩れる。値を使うアプリ (pam-passkey) は、その値を既に自分で持っている (`details.argv`) |
| `ProcessInfo` に渡された値の別の field (`supplied: Option<Supplied>`) を足す | 照合とは混ざらないが、chain が主張を運ぶ型になり、JSON の形も増える。使うアプリは 1 つで、そのアプリが値を持っている。chain に入れて得るのは表示の時に 1 か所から読めることだけ |
| `argv` と `cwd` を出どころ付きの型 (`Collected(T)` / `Supplied(T)`) にする | 組み込みの項目とアプリの項目の全部が出どころを扱うことになり、扱い忘れた項目が主張を照合する。JSON の形も変わる |
| 対象の識別子 (`ProcessIdentity`) を受けて、その個体を集める入口 (`collect_process`) を足す | 「識別は pid より強いもので」に沿うが、今の利用者に要るものがいない。pam-passkey の helper は、呼び出し元の主張でなく自分の親子の関係 (カーネルの値) で対象を決められ、その方が強い。後から識別子で対象を渡すアプリが現れたら足す |
| `ProcessChain<S>` の型引数で、収集したもの (`Collected`) と受け取ったもの (`Received`) を分ける | `Collected` を作る関数は procline-macos のために公開になり、強制の強さは `from_collected` と同じ。受け取った chain を表示する利用者もいないので、型引数の手間 (`Condition` の `pin` / `check` を含む全部の署名) だけが増える |
| 収集の結果を OS ごとの crate の型にし、procline-acl は trait で受ける | procline-acl が trait を公開すれば誰でも実装でき、強制にならない。封じた trait は OS ごとの crate からも実装できない。procline-acl の入口が全部 generic になる |
| 構築関数を `unsafe fn` か `#[doc(hidden)]` にする | `unsafe` は Rust ではメモリ安全の印で、論理の約束に使うと読み手を誤らせる。`#[doc(hidden)]` は文書から隠すだけで、呼び出し箇所で表明として読めない |
| chain に収集したプロセスの鍵で署名 (MAC) を付け、評価の入口で検証する | 鍵が同じプロセスにあるので、プロセスの中では守りにならない。別のプロセスが集めた chain を評価する利用者もいない。要る利用者が現れたら、その時に別の入口として設計する |
| `ProcessInfo`、`CodeSigning` の `Deserialize` も全部外す | DR-0011 の読み込みの規則を覆す。評価の入口に入る道は `ProcessChain` の 1 か所なので、そこで閉じれば足りる |

## Consequences

- 評価の入口に渡る chain は、収集の入口か `from_collected` からしか来ない。外から受け取った JSON を評価に渡すコードは、コンパイルが止める
- `truncated` と `boot_uuid` を収集の後に書き換えられなくなり、タグは `Policy::tag` が付けたものだけになる
- アプリが `from_collected` に外から受け取った値を渡すことは止められない。それは誤用でなく明示の組み立てで、呼び出し箇所は名前で探せる
- テストは `from_collected` で chain を組む (名前が変わるだけ)。`collect_pid` の往復のテスト (JSON から `ProcessChain` に戻す) は、JSON の形を確かめるテストに変える
- procline-acl と procline-macos の `chain.boot_uuid`、`chain.truncated` の読み出しはアクセサに変わる
- `TaggedChain` は、作った Policy と別の Policy の `evaluate` に渡しても止まらない (語彙とタグの定義が違えば、付いたタグが評価する Policy のものと食い違う)。この DR では扱わない
- 収集の入口は今のまま (`collect_peer`、`collect_pid`) で、足す入口は無い
- pam-passkey の helper は、自分の列 (`[helper, sudo, …]`) を集め、`sudo` の行の argv と cwd に PAM モジュールから受け取った値を「渡された値」として添える。PAM モジュールが helper に渡すのは自分の argv と cwd (と、照合の補助に pid) だけで済み、root で動くコードに祖先の走査も識別子の読み出しも要らない (pam-passkey の側で決めること)
- 付け替えの後に exec したプロセスが launchd の子に見えること (issue `2026-11-15-ancestry-reset-by-exec-after-reparent`) は、この DR では変わらない。helper から見た親 (`sudo`) までの繋がりはカーネルの値で確かめられるが、`sudo` より上の列には同じことが起きうる
- 未観測の点:
  - helper (hardened runtime、Developer ID 署名) が自分の pid で集めた時の所要時間と、列の先頭 (自分) の署名の検証の結果
  - 走っている `sudo` の子として起動された helper から集めた列で、2 番目が `sudo` になること (同じ uid の親子では観測した。親が実効 uid 0 の組は、walk が使う値が uid を問わず読めることだけ観測済み)
  - cw の実装での chain の使い方 (cw のリポは手元に無い)

## 関連

- [DR-0008](DR-0008-evaluation-semantics.md): 途切れた列と `undecidable`
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md): `CodeSigning` の JSON の読み込み、ユーザ権限から走っている `sudo` の署名を検証する手順
- [DR-0012](DR-0012-strength-class-from-protection.md): 保護の状態とクラス (chain の `runtime` と `entitlements` を信じる側)
- [DR-0013](DR-0013-collect-only-dependencies.md): 収集だけのアプリの依存
- [DESIGN-ja の「脅威モデルの前提」「収集する情報」「収集の整合性」「API の骨格」](../DESIGN-ja.md)
- issue: [JSON から読み込んだ ProcessChain を評価が信用する](../issue/2026-11-15-deserialized-chain-is-trusted-by-evaluate.md)、[呼び出し元が渡して補う入口](../issue/2026-11-15-caller-supplied-own-info.md)、[付け替えの後の exec](../issue/2026-11-15-ancestry-reset-by-exec-after-reparent.md)
- [findings: 親が終わった後の p_puniqueid](../findings/2026-11-15-puniqueid-after-reparent-and-exec.md)、[findings: collect_pid の観測](../findings/2026-11-09-collect-pid-observations.md)
- pam-passkey (別リポ): DR-0003 (helper の起動)、issue `2026-11-15-collect-in-helper-with-procline`
