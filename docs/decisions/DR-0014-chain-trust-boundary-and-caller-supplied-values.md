# DR-0014: 評価に渡す chain は評価するプロセスが自分で収集したものとし、`ProcessChain` を JSON から読めなくして組み立てを `from_collected` に限る。呼び出し元が渡す値は chain に入れず、受け取ったアプリが持つ

- Status: Proposed
- Date: 2026-11-15

## Context

評価 (`Policy::tag`、`grant`、`resolve_subject`、`evaluate`、`explain`、条件の `pin` / `check`) は、渡された chain の中身を事実として扱う。保護の状態 ([DR-0012](DR-0012-strength-class-from-protection.md)) と署名由来の条件は `CodeSigning::Verified` の `runtime` と `entitlements` から、途切れた列の判定 ([DR-0008](DR-0008-evaluation-semantics.md)) は `truncated` から、タグは `TaggedChain` から決まる。今の型は、収集していない値からもこれらを作れる。

- `ProcessChain`、`ProcessInfo`、`CodeSigning` とその部品は `Deserialize` を持つ。`CodeSigning` の読み込みが確かめるのは `mark` と事実の整合だけで ([DR-0011](DR-0011-verified-signature-and-trust-mark.md))、`runtime`、`entitlements`、証明書の根が実際に検証された値かは JSON からは確かめようがない。外から受け取った JSON を chain として読んで評価に渡すと、送り手が `hardened_runtime: true`、`debugged: false`、`entitlements: null` と書くだけで保護ありと判定され、制約なしの `allow` が採用されうる (issue `2026-11-15-deserialized-chain-is-trusted-by-evaluate`。レビューの読み取りによる指摘で、再現のテストは無い)
- `ProcessChain::new` は公開で、`boot_uuid` と `truncated` は公開の field。`TaggedChain` の field (`chain`、`tags`、`undecidable_tags`) も全部公開で、`Policy::tag` を通さずに任意のタグを付けた値を `evaluate` に渡せる

守る相手は同じ uid の別プロセスで、root と評価するアプリ自身は範囲外 (DESIGN-ja「脅威モデルの前提」)。同じ uid の別プロセスが評価に混ぜられるのは、アプリが外から受け取るバイト列 (JSON、引数、標準入力) だけで、アプリのコードに `ProcessChain::new` を呼ばせることはできない。問題になるのは、アプリの書き手が受け取ったバイト列を、収集した事実の型として読んで評価に渡してしまう取り違え。

評価には chain のほかにも、アプリが値を渡す公開の入口がある。

- `EvalContext::new(now).with_observed(key, value)` は、条件の観測値を任意の値で与えられる (`crates/procline-acl/src/context.rs`。文書はテスト用とする)
- `MatchTarget { info: &ProcessInfo, boot_uuid: &str }` の field と `Matcher` の各メソッド、`Vocabulary::class(key, value, Option<&ProcessInfo>)` は公開で、アプリが任意の `ProcessInfo` を項目に当てられる (`crates/procline-acl/src/vocabulary.rs`)。これらは `Decision` を返さず、評価 (`Policy::evaluate`) の中で使う `MatchTarget` は Policy が chain から組む
- どちらも、アプリのコードが自分で値を選んで渡す入口で、設計どおりのもの

収集した事実の型を JSON から読んでいる所 (このリポ):

- 本体のコードには無い。JSON から読むのは `os.session` の引数 (`SessionLevel`) だけ。procline-acl は serde の `Deserialize` を使わない (grant と一覧の読み込みは未実装)
- テスト: `CodeSigning` の往復 (`json_round_trips_every_shape` と、書き出しの形のテストの最後の読み戻し)、読み込みが事実と違う印を拒むこと (`reading_rejects_a_mark_the_facts_do_not_give`)、`collect_pid` の列の往復 (`chain_round_trips_through_json`)
- pam-passkey は procline に依存していない。cw は接続相手を自分で収集して評価する (DESIGN-ja「概要」)。cw のリポは手元に無く、承認画面が評価するデーモンと別のプロセスで chain を JSON で受け取るかは確かめていない

もう 1 つ、ユーザ権限で収集する時に取れない値の扱いが要る。pam-passkey は、祖先の収集と署名の検証を root の PAM モジュールからユーザ権限の helper に移す (pam-passkey の issue `2026-11-15-collect-in-helper-with-procline`)。

- argv (`KERN_PROCARGS2`) と cwd (`PROC_PIDVNODEPATHINFO`) は、同じ uid か root からしか取れない (別 uid では `EPERM`、[findings](../findings/2026-11-09-collect-pid-observations.md))。走っている `sudo` (実効 uid 0) の argv と cwd は helper から取れない。PAM モジュールは自分の argv と cwd を helper に渡せる。渡された値は呼び出し元が自分について主張するもので、procline が収集したものではない
- helper は PAM モジュールが fork し、子の中で降格して exec したもの (pam-passkey の DR-0003)。今の起動時の入力 (pam-passkey の `protocol::HelperInput`) では、`details.processes[0]` が PAM モジュールのプロセスで、識別子は `pid` だけ

祖先の walk が隣り合う行を親子として繋ぐ強さは、識別子が取れたかで変わる (`crates/procline-macos/src/collect.rs` の `Recorded::read` と `is_parent_of`、DESIGN-ja「識別子」)。

- 識別子 (`PROC_PIDUNIQIDENTIFIERINFO`、`#ifdef PRIVATE` の SPI) が親と子の両方で取れた時: 子の `p_puniqueid` と親の `p_uniqueid` の一致で繋ぐ。どちらも uid を問わず読め、`p_puniqueid` はカーネルが fork と exec の時に、その時の親の `p_uniqueid` で書く。親が終わって付け替えられただけなら元の親の値のままで、launchd の `p_uniqueid` と合わないので、列は `AncestorExited` で途切れる ([findings](../findings/2026-11-15-puniqueid-after-reparent-and-exec.md))
- 取れなかった時: `kinfo_proc` の ppid と、親の起動時刻が子の起動時刻以前であることで繋ぐ。親の pid を後から使い回したプロセス (子より後に起動したもの) は外れるが、付け替えられたプロセスは launchd に繋がり、途切れの印は付かない
- どちらでも、親が終わって付け替えられた後に exec したプロセスは、`p_puniqueid` が launchd の値 (1) に書き換わるので launchd の子として繋がり、途切れの印は付かない (同じ findings)。これは列のどの行の間でも起きうる。例えば helper の exec の前に `sudo` が終わると、helper の列は helper → launchd になる
- どちらで繋いだかは、行の識別子 (`Identity.unique_id`、`parent_unique_id`) が `Some` か `None` かで分かる
- 自分の pid で `collect_pid` を呼ぶと、列の先頭が自分、2 番目が親になる (同じ uid の親子で観測。親子は unique ID で繋がった)

Rust の可視性では、ある crate の型の構築を別の特定の crate (OS ごとの収集の crate) にだけ許すことはできない。procline-macos が `ProcessInfo` と chain を組むので、組み立ての関数と field は公開になり、アプリのコードからも使える。

- 目的: 評価が chain から読む事実 (各プロセスの項目、署名と保護の状態、途切れの印、タグ) が、評価するプロセスが自分で収集したものか、アプリのコードが明示して組み立てたものに限られ、外から受け取ったバイト列を読み込むだけでは chain にならない。呼び出し元の主張は、収集した事実と同じ field で運ばれない
- 増やしたくないもの:
  - 評価の入口と、chain や収集の結果を表す型の数
  - 収集の入口が受け取る呼び出し元の主張
  - procline が保証できないことを保証するかのような文書の言い方

## Decision

### 保証の範囲

- この DR が保証するのは chain の出どころ: 評価の入口に渡る `ProcessChain` は、収集の入口 (`collect_peer`、`collect_pid`) か、アプリのコードが呼ぶ `ProcessChain::from_collected` からしか作れない。`TaggedChain` は `Policy::tag` からしか作れない
- 止めるのは、外から受け取ったバイト列を読み込むだけで chain ができること (アプリの書き手の取り違え)。アプリのコードが `ProcessInfo` を読み込みや手書きで用意して `from_collected` に渡すことは止めない。`from_collected` を呼ぶのはアプリ自身のコードで、評価するアプリ自身は脅威モデルの範囲外。呼び出し箇所は名前で探せる
- 範囲外の入口 (アプリのコードが自分で値を選んで渡すもので、設計どおり): `EvalContext::new` / `with_observed` で与える観測値、`MatchTarget` と `Matcher` / `Vocabulary::class` に直接渡す `ProcessInfo`。どの観測値を渡すかはアプリの責務 (本番は `EvalContext::capture`)

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
    /// 外から受け取った値から chain を組むのには使わない
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

- `ProcessChain` から `Deserialize` を外し、field を全部非公開にする。`ProcessChain` 型の値を JSON から読むコードはコンパイルが通らない
- `ProcessChain::new` は `from_collected` にする。名前で、呼び出す側が収集した値だと表明していることが読める
- `ProcessInfo`、`CodeSigning` などの `Deserialize` は残す。DR-0011 の JSON の読み込みの規則 (`mark` を事実から決め直し、一致しなければエラー) は、他のプロセスから受け取った収集の結果を表示する側を守る規則として変えない
- JSON から読んだ chain を評価に使う入口は持たない

### 呼び出し元が渡す値

- 収集の入口は、呼び出し元が渡す値 (argv、cwd など) を受け取らず、chain に入れない。値を受け取ったアプリが持ち、表示で「呼び出し元が渡した値」として出す。照合には使わない (強さのクラスを持たない)
- 列の 2 番目以降の、別 uid のプロセスの argv と cwd は取れないまま (`None`) にする

procline が保証すること / しないこと:

- 出すもの: 列の各行の識別子 (`pid`、`unique_id`、`parent_unique_id`、`start_time`)。隣り合う行は、識別子が取れた時は `p_puniqueid` と親の `p_uniqueid` の一致で、取れなかった時は ppid と起動時刻の順で繋いだもの。どちらで繋いだかは行の識別子の有無で分かる
- 保証しないこと:
  - 識別子が取れなかった時の繋がりは、付け替えを途切れとして出さない (起動時刻の順は付け替え先の launchd でも満たす)
  - 識別子が取れた時も、親が終わった後に exec したプロセスは launchd の子に見え、途切れの印 (`truncated`) は付かない。印が無いことは、どの行が期待する親であるかを示さない
  - 渡された値がどの行のものか、送り手が誰か
- アプリが決めること: 渡された値をどの行に添えるか、その行が期待する送り手であることをどう確かめるか (行の識別子との照合、照合に使う識別子を送り手に何まで渡させるか)、合わない時に進めるか。procline はそのための値 (行の識別子) を出し、`collect_peer` (ソケットの相手を audit token で決めて集める入口) を持つ。socketpair の相手は作ったプロセスを指した ([findings](../findings/2026-11-15-socketpair-peer-after-fork-exec.md)、同じ uid で 1 回)

### DESIGN に書くこと

- 「脅威モデルの前提」: 評価に渡す chain は、評価するプロセスが自分で収集したもの。他のプロセスから受け取った値は表示にだけ使う。`ProcessChain` は JSON から読めず、組み立ては `from_collected` (アプリのコードの表明) だけ。観測値と、項目に直接渡す `ProcessInfo` はアプリの責務
- 「収集の整合性」の 4: 識別子が取れなかった時の繋ぎ方と、付け替えの後の exec で途切れの印が付かないこと
- 「収集する情報」: argv と cwd を取れない対象について、呼び出し元が渡す値は crate の外 (受け取ったアプリ) が持つこと
- 「API の骨格」: `ProcessChain` と `TaggedChain` のアクセサ

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 収集した事実の型 (`ProcessInfo`、`CodeSigning`、`Signer`、`Root`、`RuntimeState` 等) からも `Deserialize` を外し、外から読む先を表示用の別の型にする | 追加で止まるのは、アプリの書き手が `ProcessInfo` を JSON から読み、`from_collected` の名前と文書に反してそれを渡す取り違えだけで、同じ uid の別プロセスにできることは増えも減りもしない (`from_collected` を呼ぶのはアプリのコード)。代わりに DR-0011 の読み込みの規則を失う。その規則は、他のプロセスから受け取った収集の結果を表示する側で、印と事実が食い違う値を通さないためのもの。表示する利用者 (cw の承認画面が別のプロセスなら) が現れると、`ProcessInfo` から証明書までの約 18 の型を写した表示用の型の組が要り、型の数が倍になる。`MatchTarget` と `Vocabulary::class` は `ProcessInfo` を直接受けるが、`Decision` を返さず、アプリのコードが値を選んで渡す範囲外の入口なので、この差を広げない |
| 収集の入口が、対象の識別子と渡された argv・cwd を受け、識別子が一致すれば列の先頭に入れる (issue の案) | 収集した事実と呼び出し元の主張が同じ field に入り、`argv` と `cwd` の照合が主張をそのまま照合する。値を使うアプリ (pam-passkey) は、その値を自分で持っている |
| `ProcessInfo` に渡された値の別の field (`supplied: Option<Supplied>`) を足す | 照合とは混ざらないが、chain が主張を運ぶ型になる。使うアプリは 1 つで、そのアプリが値を持っている |
| `argv` と `cwd` を出どころ付きの型 (`Collected(T)` / `Supplied(T)`) にする | 組み込みの項目とアプリの項目の全部が出どころを扱うことになり、扱い忘れた項目が主張を照合する |
| 対象の識別子 (`ProcessIdentity`) を受けて、その個体を集める入口 (`collect_process`) を足す | 「識別は pid より強いもので」に沿うが、今の利用者で要るものがいない。行の識別子との照合はアプリが収集の後にできる。識別子で対象を渡して集めたいアプリが現れたら足す |
| `ProcessChain<S>` の型引数で、収集したもの (`Collected`) と受け取ったもの (`Received`) を分ける | `Collected` を作る関数は procline-macos のために公開になり、強制の強さは `from_collected` と同じ。型引数の手間 (`Condition` の `pin` / `check` を含む全部の署名) だけが増える |
| 収集の結果を OS ごとの crate の型にし、procline-acl は trait で受ける | procline-acl が trait を公開すれば誰でも実装でき、強制にならない。封じた trait は OS ごとの crate からも実装できない |
| 構築関数を `unsafe fn` か `#[doc(hidden)]` にする | `unsafe` は Rust ではメモリ安全の印で、論理の約束に使うと読み手を誤らせる。`#[doc(hidden)]` は文書から隠すだけで、呼び出し箇所で表明として読めない |
| chain に収集したプロセスの鍵で署名 (MAC) を付け、評価の入口で検証する | 鍵が同じプロセスにあるので、プロセスの中では守りにならない。別のプロセスが集めた chain を評価する利用者もいない |
| `EvalContext` の `new` / `with_observed` を閉じる (テストだけに見せる) | 観測値を選ぶのはアプリの責務で、アプリが足す条件の試験や、観測を差し替えるアプリの構成にも使う。同じ uid の別プロセスが観測値を渡す経路ではない |

## Consequences

- `ProcessChain` 型の値を JSON から読むコードはコンパイルが通らない。外から受け取ったバイト列を読み込むだけでは、評価に渡せる chain にならない
- アプリのコードが `ProcessInfo` を JSON から読み、`from_collected` に渡すことは止められない。それはアプリ自身のコードの表明で、範囲外 (評価するアプリ自身は脅威モデルの範囲外)。呼び出し箇所は名前で探せる。issue の受け入れ条件はこの線に合わせて書き直す
- `truncated` と `boot_uuid` を収集の後に書き換えられなくなり、タグは `Policy::tag` が付けたものだけになる
- テスト: chain を組むテストは `from_collected` を使う。`collect_pid` の列の往復のテストは、`ProcessChain` に読み戻せないので、書き出した JSON の形と、`ProcessInfo` への読み戻しを確かめるテストに変わる (仕様の変更に伴う)
- procline-acl と procline-macos の `chain.boot_uuid`、`chain.truncated` の読み出しはアクセサに変わる
- `TaggedChain` は、作った Policy と別の Policy の `evaluate` に渡しても止まらない (語彙とタグの定義が違えば、付いたタグが評価する Policy のものと食い違う)。この DR では扱わない
- 収集の入口は今のまま (`collect_peer`、`collect_pid`) で、足す入口は無い
- 付け替えの後の exec で列が途切れずに launchd へ繋がること (issue `2026-11-15-ancestry-reset-by-exec-after-reparent`) は、列のどの行の間にも起き、この DR では変わらない。識別子が取れない環境では、付け替えだけでも同じことが起きる
- pam-passkey の helper が渡された値をどの行に添え、どう照合し、合わない時にどうするかは、pam-passkey の設計文書で決める
- 未観測の点:
  - 識別子 (SPI) が取れない macOS での walk (今の macOS では uid を問わず取れた)
  - helper (hardened runtime、Developer ID 署名) が自分の pid で集めた時の所要時間と、列の先頭 (自分) の署名の検証の結果
  - 走っている `sudo` の子として起動された helper から集めた列で、2 番目が `sudo` になること (同じ uid の親子では観測した。親が実効 uid 0 の組は、walk が使う値が uid を問わず読めることだけ観測済み)
  - socketpair を root のプロセスが作り、降格して exec した子が読む組と、その audit token での `collect_peer`
  - cw の実装での chain の使い方 (cw のリポは手元に無い)

## 関連

- [DR-0008](DR-0008-evaluation-semantics.md): 途切れた列と `undecidable`
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md): `CodeSigning` の JSON の形と読み込みの規則、ユーザ権限から走っている `sudo` の署名を検証する手順
- [DR-0012](DR-0012-strength-class-from-protection.md): 保護の状態とクラス (chain の `runtime` と `entitlements` を信じる側)
- [DR-0013](DR-0013-collect-only-dependencies.md): 収集だけのアプリの依存
- [DESIGN-ja の「脅威モデルの前提」「識別子」「収集する情報」「収集の整合性」「API の骨格」](../DESIGN-ja.md)
- issue: [JSON から読み込んだ ProcessChain を評価が信用する](../issue/2026-11-15-deserialized-chain-is-trusted-by-evaluate.md)、[呼び出し元が渡して補う入口](../issue/2026-11-15-caller-supplied-own-info.md)、[付け替えの後の exec](../issue/2026-11-15-ancestry-reset-by-exec-after-reparent.md)
- [findings: 親が終わった後の p_puniqueid](../findings/2026-11-15-puniqueid-after-reparent-and-exec.md)、[findings: collect_pid の観測](../findings/2026-11-09-collect-pid-observations.md)、[findings: socketpair の相手](../findings/2026-11-15-socketpair-peer-after-fork-exec.md)
- pam-passkey (別リポ): DR-0003 (helper の起動)、`crates/protocol` の `HelperInput` (helper の起動時の入力)、issue `2026-11-15-collect-in-helper-with-procline`
