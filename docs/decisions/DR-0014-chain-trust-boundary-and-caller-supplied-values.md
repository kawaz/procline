# DR-0014: 評価に渡す chain は評価するプロセスが自分で収集したものとし、収集した事実の型を JSON から読めなくして chain の組み立てを `from_collected` に限る。呼び出し元が渡す値は chain に入れず、受け取ったアプリが持つ

- Status: Active
- Date: 2026-11-15

## Context

評価 (`Policy::tag`、`grant`、`resolve_subject`、`evaluate`、`explain`、条件の `pin` / `check`) は、渡された chain の中身を事実として扱う。保護の状態 ([DR-0012](DR-0012-strength-class-from-protection.md)) と署名由来の条件は `CodeSigning::Verified` の `runtime` と `entitlements` から、途切れた列の判定 ([DR-0008](DR-0008-evaluation-semantics.md)) は `truncated` から、タグは `TaggedChain` から決まる。収集していない値からこれらを作れる経路は 2 つある。

- JSON からの読み込み: 収集した事実の型が `Deserialize` を持つと、外から受け取った JSON を chain として読んで評価に渡せる。`runtime`、`entitlements`、証明書の根が実際に検証された値かは、JSON からは確かめようがない。送り手が `hardened_runtime: true`、`debugged: false`、`entitlements: null` と書くだけで保護ありと判定され、制約なしの `allow` が採用されうる (issue `2026-11-15-deserialized-chain-is-trusted-by-evaluate`。レビューの読み取りによる指摘で、再現のテストは無い)
- 公開の組み立て: chain の `truncated` と `boot_uuid` が公開の field なら、収集の後に途切れの印や起動の UUID を書き換えられる。`TaggedChain` の field (`chain`、`tags`、`undecidable_tags`) が公開なら、`Policy::tag` を通さずに任意のタグを付けた値を `evaluate` に渡せる

守る相手は同じ uid の別プロセスで、root と評価するアプリ自身は範囲外 (DESIGN-ja「脅威モデルの前提」)。同じ uid の別プロセスが評価に混ぜられるのは、アプリが外から受け取るバイト列 (JSON、引数、標準入力) だけで、アプリのコードに chain の組み立ての関数を呼ばせることはできない。問題になるのは、アプリの書き手が受け取ったバイト列を、収集した事実の型として読んで評価に渡してしまう取り違え。

評価には chain のほかにも、アプリが値を渡す公開の入口がある。

- `EvalContext::new(now).with_observed(key, value)` は、条件の観測値を任意の値で与えられる (`crates/procline-acl/src/context.rs`。文書はテスト用とする)
- `MatchTarget { info: &ProcessInfo, boot_uuid: &str }` の field と `Matcher` の各メソッド、`Vocabulary::class(key, value, Option<&ProcessInfo>)` は公開で、アプリが任意の `ProcessInfo` を項目に当てられる (`crates/procline-acl/src/vocabulary.rs`)。これらは `Decision` を返さず、評価 (`Policy::evaluate`) の中で使う `MatchTarget` は Policy が chain から組む
- どちらも、アプリのコードが自分で値を選んで渡す入口で、設計どおりのもの

収集した事実の型と JSON:

- 本体のコードに、収集した事実の型を JSON から読む所は無い。JSON から読むのは `os.session` の引数 (`SessionLevel`) だけ
- `ProcessInfo` から JSON で届く procline の型は、`ProcessInfo` を含めて 19: `ProcessInfo`、`Identity`、`AuditToken`、`StartTime`、`Credentials`、`NamedId`、`CodeSigning`、`Mark`、`CdHash`、`Signer`、`Certificate`、`Root`、`CertificateKind`、`RuntimeState`、`VerifiedFrom`、`FailureReason`、`PathMeta`、`Bundle`、`ProcessIdentity` (`responsible`)。列の殻の `ProcessChain` と `Truncated` を足すと 21。このうち `ProcessIdentity`、`StartTime`、`CdHash` は、rule と grant の値 (`process` の pin 値、`binary` の `cdhash`) として外から書く型でもある
- `CodeSigning` は印を field に持たず、`mark()` が毎回事実から決める。JSON の `mark` は、書き出す時に `mark()` の値を写したもの。Rust の型で読む側が事実と違う印を表示しないことは、`mark()` が事実から決めることで成り立ち、読み込みの検査に依らない
- 読み込みで `mark` を事実から決め直して一致を確かめる検査が足すのは、`mark` のキーだけを書き換えた JSON を拒むこと (同じ JSON の `mark` のキーを Rust の型を通さずに表示する別の読み手との食い違いに、読み込みの側で気づける)。事実の側 (`signer.root`、`runtime`、`entitlements`) を偽り、`mark` をそれに合わせた JSON は通る。事実が検証されたかは守らない

収集の結果を JSON から読むことについて、procline の設計が言っていること:

- DESIGN-ja の柱 2 は「表示と照合を同じ型の上に置く: 画面で見ている情報から、そのままルールを作れるようにする」。画面と照合が同じプロセスにあるか、別のプロセスの画面が収集の結果を読むかには触れていない
- DESIGN-ja の「項目の登録」と「ルールの作成と強さの制約」: `SubjectBuilder` / `RuleBuilder` は収集結果を受け取らず、利用者が選んだ field を `true` (placeholder) で置いた subject を組むだけ。実値は `Policy::grant(rule, tagged, ctx)` が評価する側の chain (`tagged`) から埋め、承認画面のプレビュー (何が pin されるか) は `Policy::resolve_subject(subject, tagged)` が同じく chain から作る。画面が評価と別のプロセスにあっても、画面の側が chain を組み直して評価や pin に渡す経路は設計に無い。柱 2 の「画面からそのままルールを作れる」は、画面の側が評価の型を JSON から作ることを求めていない
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md) の目的は「収集結果の署名が、検証した事実だけを表し、表示と照合のどちらも確かめたことより強く言わない」。JSON から読んだ値を `CodeSigning::Verified` にすると、読んだプロセスは検証していないので、`Verified` が表すことが「検証した」から「検証したと書かれていた」に広がる

もう 1 つ、ユーザ権限で収集する時に取れない値の扱いが要る。

- ユーザ権限からは、別 uid のプロセスの argv と cwd が取れない。cwd (`PROC_PIDVNODEPATHINFO`) は `EPERM` ([findings](../findings/2026-11-09-collect-pid-observations.md))、argv (`KERN_PROCARGS2`) は uid 501 から launchd、configd、setuid root の `top` に対して `EINVAL` で、同じ uid のシェルには成功した (2026-11-15 の観測。`crates/procline-macos/src/sys/proc.rs` の `procargs2` のコメントも `EINVAL`)。走っている `sudo` (実効 uid 0) の argv と cwd も、ユーザ権限からは取れない。root からなら取れるかは観測していない
- 別 uid の呼び出し元は、自分の argv と cwd を、ユーザ権限で収集するプロセスに渡せる。渡された値は呼び出し元が自分について主張するもので、procline が収集したものではない

祖先の walk が隣り合う行を親子として繋ぐ強さは、識別子が取れたかで変わる (`crates/procline-macos/src/collect.rs` の `Recorded::read` と `is_parent_of`、DESIGN-ja「識別子」)。

- 識別子 (`PROC_PIDUNIQIDENTIFIERINFO`、`#ifdef PRIVATE` の SPI) が親と子の両方で取れた時: 子の `p_puniqueid` と親の `p_uniqueid` の一致で繋ぐ。どちらも uid を問わず読め、`p_puniqueid` はカーネルが fork と exec の時に、その時の親の `p_uniqueid` で書く。親が終わって付け替えられただけなら元の親の値のままで、launchd の `p_uniqueid` と合わないので、列は `AncestorExited` で途切れる ([findings](../findings/2026-11-15-puniqueid-after-reparent-and-exec.md))
- 取れなかった時: `kinfo_proc` の ppid と、親の起動時刻が子の起動時刻以前であることで繋ぐ。親の pid を後から使い回したプロセス (子より後に起動したもの) は外れるが、付け替えられたプロセスは launchd に繋がり、途切れの印は付かない
- どちらでも、親が終わって付け替えられた後に exec したプロセスは、`p_puniqueid` が launchd の値 (1) に書き換わるので launchd の子として繋がり、途切れの印は付かない (同じ findings)。これは列のどの行の間でも起きうる。例えば、走っている `sudo` が起動した子が exec する前に `sudo` が終わると、その子から集めた列は 子 → launchd になる (親が root の組は観測していない。同じ uid の親での観測と XNU の公開ソースからの推定)
- どちらで繋いだかは、行の識別子 (`Identity.unique_id`、`parent_unique_id`) が `Some` か `None` かで分かる
- 自分の pid で `collect_pid` を呼ぶと、列の先頭が自分、2 番目が親になる (同じ uid の親子で観測。親子は unique ID で繋がった)

Rust の可視性では、ある crate の型の構築を別の特定の crate (OS ごとの収集の crate) にだけ許すことはできない。procline-macos が `ProcessInfo` と chain を組むので、組み立ての関数と `ProcessInfo` の field は公開になり、アプリのコードからも使える。

- 目的: 評価が chain から読む事実 (各プロセスの項目、署名と保護の状態、途切れの印、タグ) が、評価するプロセスが自分で収集したものか、アプリのコードが明示して組み立てたものに限られ、外から受け取ったバイト列を読み込むだけでは chain にならない。収集した事実の型 (`CodeSigning::Verified` を含む) は、その値を作ったプロセスが収集・検証したことを表す。呼び出し元の主張は、収集した事実と同じ field で運ばれない
- 増やしたくないもの:
  - 評価の入口と、chain や収集の結果を表す型の数
  - 収集の入口が受け取る呼び出し元の主張
  - procline が保証できないことを保証するかのような文書の言い方

## Decision

### 保証の範囲

- この DR が保証するのは chain の出どころ: 評価の入口に渡る `ProcessChain` は、収集の入口 (`collect_peer`、`collect_pid`) か、アプリのコードが呼ぶ `ProcessChain::from_collected` からしか作れない。`TaggedChain` は `Policy::tag` からしか作れない
- 止めるのは、外から受け取ったバイト列を読み込むだけで chain や収集した事実の値ができること (アプリの書き手の取り違え)。アプリのコードが `ProcessInfo` の field を書いて用意し、`from_collected` に渡すことは止めない。`from_collected` を呼ぶのはアプリ自身のコードで、評価するアプリ自身は脅威モデルの範囲外。呼び出し箇所は名前で探せる
- 範囲外の入口 (アプリのコードが自分で値を選んで渡すもので、設計どおり): `EvalContext::new` / `with_observed` で与える観測値、`MatchTarget` と `Matcher` / `Vocabulary::class` に直接渡す `ProcessInfo`。どの観測値を渡すかはアプリの責務 (本番は `EvalContext::capture`)
- 脅威モデルの上での位置づけ: 同じ uid の別プロセスに対する守りは、型の切り方では変わらない。アプリが外から受け取った値を評価に渡さない限り安全で、渡せば危ない。型で決めるのは、アプリの書き手が受け取った値と収集した値を取り違えにくいことと、型が表す意味

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

- `ProcessChain` は `Deserialize` を持たず、field は全部非公開。`ProcessChain` 型の値を JSON から読むコードはコンパイルが通らない
- chain の組み立ては `from_collected` だけ。名前で、呼び出す側が収集した値だと表明していることが読める
- JSON から読んだ chain を評価に使う入口は持たない

### 収集した事実の型と JSON

- 収集した事実だけを表す 18 の型 (`ProcessChain`、`Truncated`、`ProcessInfo`、`Identity`、`AuditToken`、`Credentials`、`NamedId`、`PathMeta`、`Bundle`、`CodeSigning`、`FailureReason`、`Signer`、`Root`、`CertificateKind`、`RuntimeState`、`VerifiedFrom`、`Certificate`、`Mark`) は `Serialize` だけを持ち、`Deserialize` を持たない。収集の結果の JSON は書き出しの形で、procline の型には読み戻せない
- rule と grant の値や設定として外から書く型 (`ProcessIdentity`、`StartTime`、`CdHash`、`SessionLevel`、`Strength`、`EnvPolicy`) は `Deserialize` を持つ
- `CodeSigning` の JSON は [DR-0011](DR-0011-verified-signature-and-trust-mark.md) の書き出しの形だけを持つ。JSON から読まないので、読み込みで印と事実の食い違いを拒む規則は持たない
- procline は「他のプロセスが収集した結果を、Rust で procline の型として読んで表示する」使い方を支えない。Rust の表示側が要る時は、照合の型とは別に表示用の型を足し、印と事実の食い違いの扱いはその型の規則として決める
- 理由: `Verified` を持つのは、検証を行ったプロセスが作った値だけになる (DR-0011 の「確かめたことより強く言わない」を型の意味で保つ)。外のバイト列から収集した事実の型を作る読み込みの経路が無いので、アプリの書き手が受け取った値を収集した値と取り違えて `from_collected` や範囲外の入口に渡す経路も型の上で無い

### 呼び出し元が渡す値

- 収集の入口は、呼び出し元が渡す値 (argv、cwd など) を受け取らず、chain に入れない。値を受け取ったアプリが持ち、表示で「呼び出し元が渡した値」として出す。照合には使わない (強さのクラスを持たない)
- procline に、渡された値を受ける入口は足さない。収集の入口は `collect_peer` と `collect_pid`
- 列の 2 番目以降の、別 uid のプロセスの argv と cwd は取れないまま (`None`) にする

procline が保証すること / しないこと:

- 出すもの: 列の各行の識別子 (`pid`、`unique_id`、`parent_unique_id`、`start_time`)。隣り合う行は、識別子が取れた時は `p_puniqueid` と親の `p_uniqueid` の一致で、取れなかった時は ppid と起動時刻の順で繋いだもの。どちらで繋いだかは行の識別子の有無で分かる
- 保証しないこと:
  - 識別子が取れなかった時の繋がりは、付け替えを途切れとして出さない (起動時刻の順は付け替え先の launchd でも満たす)
  - 識別子が取れた時も、親が終わった後に exec したプロセスは launchd の子に見え、途切れの印 (`truncated`) は付かない。印が無いことは、どの行が期待する親であるかを示さない
  - 渡された値がどの行のものか、送り手が誰か
- アプリが決めること: 渡された値をどの行に添えるか、その行が期待する送り手であることをどう確かめるか (行の識別子との照合、照合に使う識別子を送り手に何まで渡させるか)、合わない時に進めるか。procline はそのための値 (行の識別子) を出し、`collect_peer` (ソケットの相手を audit token で決めて集める入口) を持つ
- 送り手と受け渡しの経路について言えること ([findings](../findings/2026-11-15-socketpair-peer-after-fork-exec.md)):
  - pipe でも socketpair でも、書き込み側の端を持てるのは、作ったプロセスと、それが fork で引き継がせたか fd を渡したプロセスだけ (fd の性質。観測はしていない)
  - pipe の読み側からは、書き込み側のプロセスをカーネルに問えない (`LOCAL_PEERPID` が `ENOTSOCK`、観測)。送り手が誰かは、起動の手順から言うことになる
  - socketpair の読み側からは、作ったプロセスの pid と pidversion をカーネルの値で読める (fork と exec の後も、同じ uid で 1 回観測)。親子の繋がりとは別に送り手の候補を決められるので、付け替えの後の exec で列が launchd に繋がった場合も、作ったプロセスを名指せる。作ったプロセスが終わった後と、root が作って降格した子が読む組は観測していない

### DESIGN に書くこと

- 「脅威モデルの前提」: 評価に渡す chain は、評価するプロセスが自分で収集したもの。他のプロセスから受け取った値は表示にだけ使う。収集した事実の型は JSON から読めず、chain の組み立ては `from_collected` (アプリのコードの表明) だけ。観測値と、項目に直接渡す `ProcessInfo` はアプリの責務
- 「収集の整合性」の 4: 識別子が取れなかった時の繋ぎ方と、付け替えの後の exec で途切れの印が付かないこと
- 「収集する情報」: argv と cwd を取れない対象について、呼び出し元が渡す値は crate の外 (受け取ったアプリ) が持つこと
- 「API の骨格」: `ProcessChain` と `TaggedChain` のアクセサ。収集の結果の JSON は書き出しの形で、読み戻せないこと

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 列の型 (`ProcessChain`) だけから `Deserialize` を外し、中身の型 (`ProcessInfo`、`CodeSigning` など) は JSON から読めるままにする (読み込みで印と事実の食い違いを拒む規則も残す) | JSON から読んだ値も `CodeSigning::Verified` になり、`Verified` が表すことが「このプロセスが検証した」から「検証したと書かれていた」に広がる (読んだプロセスは検証していない)。JSON から読んだ `Vec<ProcessInfo>` は収集した値と型の上で区別が付かず、`from_collected` や範囲外の入口に渡す取り違えを止めるのは名前と文書だけになる。読み込みの規則が拒むのは `mark` のキーだけの書き換えで、事実を偽った JSON は通る |
| 収集の入口が、対象の識別子と渡された argv・cwd を受け、識別子が一致すれば列の先頭に入れる | 収集した事実と呼び出し元の主張が同じ field に入り、`argv` と `cwd` の照合が主張をそのまま照合する。procline は渡された値を確かめられないので、chain に入れても確かめられたことは増えない。値は受け取ったアプリが既に持っている |
| `ProcessInfo` に渡された値の別の field (`supplied: Option<Supplied>`) を足す | 照合とは混ざらないが、収集した事実の型が収集していない主張を運ぶ型になり、型が表すことが「このプロセスが収集した」から広がる。procline は値を確かめられず、値は受け取ったアプリが既に持っている |
| `argv` と `cwd` を出どころ付きの型 (`Collected(T)` / `Supplied(T)`) にする | 組み込みの項目とアプリの項目の全部が出どころを扱うことになり、扱い忘れた項目が主張を照合する |
| 対象の識別子 (`ProcessIdentity`) を受けて、その個体を集める入口 (`collect_process`) を足す | 「識別は pid より強いもので」に沿うが、`collect_pid` で集めた列の行の識別子をアプリが収集の後に照合すれば同じことを確かめられる。既にある入口と行の識別子で表せるので、入口を足さない |
| `ProcessChain<S>` の型引数で、収集したもの (`Collected`) と受け取ったもの (`Received`) を分ける | `Collected` を作る関数は procline-macos のために公開になり、強制の強さは `from_collected` と同じ。型引数の手間 (`Condition` の `pin` / `check` を含む全部の署名) だけが増える |
| 収集の結果を OS ごとの crate の型にし、procline-acl は trait で受ける | procline-acl が trait を公開すれば誰でも実装でき、強制にならない。封じた trait は OS ごとの crate からも実装できない |
| 構築関数を `unsafe fn` か `#[doc(hidden)]` にする | `unsafe` は Rust ではメモリ安全の印で、論理の約束に使うと読み手を誤らせる。`#[doc(hidden)]` は文書から隠すだけで、呼び出し箇所で表明として読めない |
| chain に収集したプロセスの鍵で署名 (MAC) を付け、評価の入口で検証する | 鍵が同じプロセスにあるので、プロセスの中では守りにならない。評価に渡す chain は評価するプロセスが自分で収集したもので、別のプロセスが集めた chain を評価に受け入れる経路を持たない |
| `EvalContext` の `new` / `with_observed` を閉じる (テストだけに見せる) | 観測値を選ぶのはアプリの責務で、アプリが足す条件の試験や、観測を差し替えるアプリの構成にも使う。同じ uid の別プロセスが観測値を渡す経路ではない |

## Consequences

- 収集した事実の型の値を JSON から読むコードはコンパイルが通らない。外から受け取ったバイト列を読み込むだけでは、評価に渡せる chain にも、範囲外の入口に渡す `ProcessInfo` にもならない
- アプリのコードが `ProcessInfo` の field を書いて用意し、`from_collected` に渡すことは止められない。それはアプリ自身のコードの表明で、範囲外 (評価するアプリ自身は脅威モデルの範囲外)。呼び出し箇所は名前で探せる
- chain の `truncated` と `boot_uuid` は収集の後に書き換えられず、タグは `Policy::tag` が付けたものだけになる
- 収集の結果の JSON (`ProcessChain`、`CodeSigning` の形) を読むのは procline の外の型。承認画面が評価と別のプロセスにあるアプリでは、ルールに実値を埋める `resolve_subject` と `Policy::grant` を chain を持つプロセスが呼び、画面の側は受け取った JSON を自分の型か `serde_json::Value` で読んで表示する。JSON の `mark` のキーだけを書き換えた値に、procline の側で気づく経路は無い
- テスト: chain を組むテストは `from_collected` を使う。収集の結果と `CodeSigning` の JSON は、書き出した形を確かめる
- `TaggedChain` は、作った Policy と別の Policy の `evaluate` に渡しても止まらない (語彙とタグの定義が違えば、付いたタグが評価する Policy のものと食い違う)。この DR では扱わない
- 収集の入口は `collect_peer` と `collect_pid` で、足す入口は無い
- 付け替えの後の exec で列が途切れずに launchd へ繋がること (issue `2026-11-15-ancestry-reset-by-exec-after-reparent`) は、列のどの行の間にも起き、この DR では変わらない。識別子が取れない環境では、付け替えだけでも同じことが起きる
- 未観測の点:
  - 識別子 (SPI) が取れない macOS での walk (今の macOS では uid を問わず取れた)
  - 別 uid (root) の親が終わる組での `p_puniqueid` (findings `2026-11-15-puniqueid-after-reparent-and-exec.md` の未観測。利用者の権限では root の親を作って終わらせられない)。Context の例「走っている `sudo` が起動した子が exec する前に `sudo` が終わる」はこの組で、同じ uid の親で観測したことからの推定
  - root から別 uid のプロセスの argv と cwd が取れるか
  - hardened runtime の Developer ID 署名のプロセスが自分の pid で集めた時の所要時間と、列の先頭 (自分) の署名の検証の結果
  - 走っている `sudo` の子として起動されたプロセスが自分の pid で集めた列で、2 番目が `sudo` になること (同じ uid の親子では観測した。親が実効 uid 0 の組は、walk が使う値が uid を問わず読めることだけ観測済み)
  - socketpair を root のプロセスが作り、降格して exec した子が読む組と、その audit token での `collect_peer`

## 関連

- [DR-0008](DR-0008-evaluation-semantics.md): 途切れた列と `undecidable`
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md): `CodeSigning` の JSON の書き出しの形、ユーザ権限から走っている `sudo` の署名を検証する手順
- [DR-0012](DR-0012-strength-class-from-protection.md): 保護の状態とクラス (chain の `runtime` と `entitlements` を信じる側)
- [DR-0013](DR-0013-acl-layer-in-separate-crates.md): ACL の層を収集の層から crate で分ける
- [DESIGN-ja の「脅威モデルの前提」「識別子」「収集する情報」「収集の整合性」「API の骨格」](../DESIGN-ja.md)
- issue: [JSON から読み込んだ ProcessChain を評価が信用する](../issue/archive/2026-11-15-deserialized-chain-is-trusted-by-evaluate.md)、[呼び出し元が渡して補う入口](../issue/archive/2026-11-15-caller-supplied-own-info.md)、[付け替えの後の exec](../issue/2026-11-15-ancestry-reset-by-exec-after-reparent.md)
- [findings: 親が終わった後の p_puniqueid](../findings/2026-11-15-puniqueid-after-reparent-and-exec.md)、[findings: collect_pid の観測](../findings/2026-11-09-collect-pid-observations.md)、[findings: socketpair の相手](../findings/2026-11-15-socketpair-peer-after-fork-exec.md)
