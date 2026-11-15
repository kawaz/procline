# DR-0014: 評価に渡す chain は評価するプロセスが自分で収集したものに限る。収集した事実の型から Deserialize を外し、JSON から評価の型への読み込みを無くす。呼び出し元が渡す値は chain に入れず、受け取ったアプリが持つ

- Status: Proposed
- Date: 2026-11-15

## Context

評価 (`Policy::tag`、`grant`、`resolve_subject`、`evaluate`、`explain`、条件の `pin` / `check`) は、渡された chain の中身を事実として扱う。保護の状態 ([DR-0012](DR-0012-strength-class-from-protection.md)) と署名由来の条件は `CodeSigning::Verified` の `runtime` と `entitlements` から、途切れた列の判定 ([DR-0008](DR-0008-evaluation-semantics.md)) は `truncated` から、タグは `TaggedChain` から決まる。今の型は、収集していない値からもこれらを作れる。

- `ProcessChain`、`ProcessInfo`、`CodeSigning` とその部品 (`Signer`、`Root`、`RuntimeState` 等) は `Deserialize` を持つ。`CodeSigning` の読み込みが確かめるのは `mark` と事実の整合だけで ([DR-0011](DR-0011-verified-signature-and-trust-mark.md))、`runtime`、`entitlements`、証明書の根が実際に検証された値かは JSON からは確かめようがない。送り手が `hardened_runtime: true`、`debugged: false`、`entitlements: null` と書けば保護ありと判定され、署名由来の条件が強になり、制約なしの `allow` が採用されうる (issue `2026-11-15-deserialized-chain-is-trusted-by-evaluate`。レビューの読み取りによる指摘で、再現のテストは無い)
- `ProcessChain::new` は公開で、`boot_uuid` と `truncated` は公開の field。収集した chain の `truncated` を `None` にすれば、判定できない grant (`undecidable`) が判定できたことになる
- `TaggedChain` の field (`chain`、`tags`、`undecidable_tags`) は全部公開で、`Policy::tag` を通さずに任意のタグを付けた値を `evaluate` に渡せる

収集した事実の型を JSON から読んでいる所 (このリポ):

- 本体のコードには無い。JSON から読むのは `os.session` の引数 (`SessionLevel`) だけ。procline-acl は serde の `Deserialize` を使わない (grant と一覧の読み込みは未実装)
- テストは 3 つ: `CodeSigning` の往復 (`json_round_trips_every_shape` と、書き出しの形のテストの最後の読み戻し)、読み込みが事実と違う印を拒むこと (`reading_rejects_a_mark_the_facts_do_not_give`)、`collect_pid` の列の往復 (`chain_round_trips_through_json`。コメントは「承認画面やルールの保存に JSON で渡しても情報が落ちない」)
- pam-passkey は procline に依存していない。承認ページ (JavaScript) と `send_command` は、pam-passkey の形 (`details`) の JSON を読む
- cw は接続相手を自分で収集して評価する (DESIGN-ja「概要」)。cw のリポは手元に無く、承認画面が評価するデーモンと別のプロセスで、chain を JSON で受け取って表示するかは確かめていない

もう 1 つ、ユーザ権限で収集する時に取れない値の扱いが要る。pam-passkey は、祖先の収集と署名の検証を root の PAM モジュールからユーザ権限の helper に移す (pam-passkey の issue `2026-11-15-collect-in-helper-with-procline`)。

- argv (`KERN_PROCARGS2`) と cwd (`PROC_PIDVNODEPATHINFO`) は、同じ uid か root からしか取れない (別 uid では `EPERM`、[findings](../findings/2026-11-09-collect-pid-observations.md))。走っている `sudo` (実効 uid 0) の argv と cwd は helper から取れない。署名は、カーネルが持つ署名で検証する手順でユーザ権限から `anchor apple` まで確かめられる ([DR-0011](DR-0011-verified-signature-and-trust-mark.md))
- helper は PAM モジュールが fork し、子の中で降格して exec したもの (pam-passkey の DR-0003)。PAM モジュールは helper の標準入力に 1 行の JSON を書く。今の形 (pam-passkey の `protocol::HelperInput`) では、`details.processes[0]` が PAM モジュールのプロセス (`getpid()`) で、識別子は `pid` だけ、ほかに `uid`、`cwd`、`path`、`argv`、`signature` を持つ
- 祖先の walk は、`kinfo_proc` の ppid で親を読み、親の `p_uniqueid` と子の `p_puniqueid` の一致で親子を確かめる。どちらも uid を問わず読める (実効 uid 0 のプロセスも、[findings](../findings/2026-11-15-puniqueid-after-reparent-and-exec.md))。自分の pid で `collect_pid` を呼ぶと、列の先頭が自分、2 番目が親になる (同じ uid の親子で観測。親子は unique ID で繋がった)
- `p_puniqueid` は、親が終わって付け替えられただけでは元の親の値のままだが、付け替えの後に exec すると launchd の値 (1) に書き換わる (同じ findings)。PAM モジュールが fork した後、helper が exec する前に `sudo` が終わると、helper の列は helper → launchd と繋がり、`truncated` は付かない。exec の後に終わると、ppid が 1 になり、launchd の `p_uniqueid` と helper の `p_puniqueid` が合わないので、列は helper だけで `AncestorExited` で終わる
- socketpair の相手の pid と audit token (`LOCAL_PEERPID`、`LOCAL_PEERTOKEN`) は、fork と exec の後も socketpair を作ったプロセスを指した ([findings](../findings/2026-11-15-socketpair-peer-after-fork-exec.md)、同じ uid で 1 回)

Rust の可視性では、ある crate の型の構築を別の特定の crate (OS ごとの収集の crate) にだけ許すことはできない。procline-macos が `ProcessInfo` と chain を組むので、組み立ての関数と field は公開になり、アプリからも使える。型で閉じられるのは、外のバイト列から評価の型を作る自動の経路 (serde の読み込み) までで、アプリのコードが値を 1 つずつ書いて組み立てることは止められない。

- 目的: 評価の判定が、評価するプロセスが自分で OS から確かめた事実だけに基づく。外から受け取った値が、読み込むだけで確かめた事実の型にならない。呼び出し元の主張は、確かめた事実と同じ型で運ばれない
- 増やしたくないもの:
  - 評価の入口と、chain を表す型の数
  - 収集の入口が受け取る呼び出し元の主張
  - 呼び出し元の主張を信じる箇所 (主張でなくカーネルの値で確かめられるものは、カーネルの値で確かめる)

## Decision

### 信頼境界

- 評価に渡す chain は、評価するプロセス自身が収集の入口 (`collect_peer`、`collect_pid`) で集めたもの。他のプロセスから受け取った chain や値 (JSON、引数、標準入力) は表示にだけ使う
- 型で閉じるのは、外のバイト列を読み込むだけで評価の型 (`ProcessChain` とその中身) ができる経路。評価するアプリ自身は範囲外 (DESIGN-ja「脅威モデルの前提」) なので、アプリのコードが値を 1 つずつ書いて組み立てた chain は止めない。chain を組む関数は名前で呼び出し箇所を探せる 1 つ (`from_collected`) にする

### 型

収集した事実だけを表す型から `Deserialize` を外す。`Serialize` は表示、ログ、dump、他のプロセスへの受け渡しのために残す。

| 扱い | 型 |
|---|---|
| `Deserialize` を外す (収集した事実だけを表す) | `ProcessChain`、`Truncated`、`ProcessInfo`、`Identity`、`AuditToken`、`Credentials`、`NamedId`、`PathMeta`、`Bundle`、`CodeSigning`、`FailureReason`、`Signer`、`Root`、`CertificateKind`、`RuntimeState`、`VerifiedFrom`、`Certificate`、`Mark` |
| `Deserialize` を残す (rule と grant の値や設定として外から書く) | `ProcessIdentity` と `StartTime` (`process` の pin 値)、`CdHash` (`binary` の `cdhash`)、`SessionLevel`、`Strength`、`EnvPolicy` |

```rust
// procline-core
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessChain {
    processes: Vec<ProcessInfo>,
    boot_uuid: String,
    truncated: Option<Truncated>,
}

impl ProcessChain {
    /// 収集の入口とテストが使う。呼び出し側が「この値はこのプロセスが OS から収集した」と表明する
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

- JSON の書き出しの形 (DR-0011 の `code_signing` の形、`mark` を添える) は変えない。読み込み (`mark` を事実から決め直し、一致しなければエラー) は、読み込む型が無くなるので持たない
- 他のプロセスから受け取った収集の結果を Rust で表示したい利用者が現れたら、表示用の別の型 (評価の入口が受け付けない型) を足し、DR-0011 の読み込みの規則はその型に置く。その型から評価の型へ変える関数は持たない
- JSON から読んだ chain を評価に使う入口は持たない

### 呼び出し元が渡す値

- 収集の入口は、呼び出し元が渡す値 (argv、cwd など) を受け取らず、chain に入れない。値を受け取ったアプリが持ち、表示で「呼び出し元が渡した値」として出す。照合には使わない (強さのクラスを持たない)
- 列の 2 番目以降の、別 uid のプロセスの argv と cwd は取れないまま (`None`) にする

procline が決めること (提供するもの):

- 列の各行の識別子 (`pid`、`unique_id`、`parent_unique_id`、`start_time`) と、隣り合う行の親子の関係をカーネルの値 (`p_puniqueid` と親の `p_uniqueid`) で確かめた列
- ソケットの相手を audit token で決めて集める入口 (`collect_peer`)。socketpair なら相手は作ったプロセスになる (観測 1 回)
- 列が途切れた印 (`truncated`) は、途切れたと分かった時だけ付く。付け替えの後の exec のように、途切れずに別の親へ繋がる場合は付かない。印が無いことは、列の 2 番目が期待する対象であることを示さない

アプリが決めること (pam-passkey なら helper):

- 渡された値の発信元がどの行かを、発信元が名乗る識別子 (今の形では PAM モジュールの `pid`) と列の行の識別子の照合で確かめる。合わなければ要求を進めない
- この照合は `truncated` の有無と独立に行う。次のどれでも、照合が止める
  - helper の exec の前に `sudo` が終わった: 列は helper → launchd で、2 番目は pid 1
  - exec の後に終わった: 列は helper だけで、2 番目が無い
  - helper を `sudo` 以外 (同じ uid のプロセス) が直接起動した: 2 番目は起動したプロセスで、名乗る pid と違う。名乗る pid を起動したプロセス自身のものにすれば照合は通るが、その時の値は起動したプロセスが自分について渡したもので、それを受け取る PAM モジュールもいない
- 名乗る識別子に何を足すか (`pid` だけか、`unique_id` か起動時刻も渡すか)、発信元をカーネルの値で決めるか (標準入力を socketpair にし、`collect_peer` で集める) は、アプリが決める。標準入力が pipe のままでは、発信元が名乗る識別子を信じることになる (helper の親が `sudo` であることは列で確かめられるが、1 行を書いたのが親であることはカーネルの値では確かめられない)

### DESIGN に書くこと

- 「脅威モデルの前提」: 評価に渡す chain は、評価するプロセスが自分で収集したもの。他のプロセスから受け取った chain や値は表示にだけ使い、収集した事実の型は JSON から読めない
- 「収集する情報」: argv と cwd を取れない対象について、呼び出し元が渡す値は crate の外 (受け取ったアプリ) が持ち、どの行の値かはアプリが識別子で確かめること。`truncated` が付かない繋ぎ替え (付け替えの後の exec)
- 「API の骨格」: `ProcessChain` と `TaggedChain` のアクセサ、`Deserialize` を持たない型

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| `ProcessChain` だけから `Deserialize` を外し、`ProcessInfo` と `CodeSigning` の読み込みは残す。目的と Consequences と issue の受け入れ条件の言い方を「誤用を止め、明示の組み立ては止めない」に揃える | JSON → `Vec<ProcessInfo>` → `from_collected` → `Policy::tag` が 2 行で通り、読み込んだ値を検証なしに評価に渡せる。読み込んだ `ProcessInfo` は収集した値と型の上で区別が付かないので、`from_collected` に渡すのは「誤り」と見分けにくい。外せば、評価の型を作るにはアプリが field を 1 つずつ書くことになり、それは読み込みでなく組み立て (表明) になる。残すことで守れるのは、DR-0011 の読み込みの規則と 3 つのテストだけで、本体のコードと pam-passkey には読む所が無い |
| 収集の入口が、対象の識別子と渡された argv・cwd を受け、識別子が一致すれば列の先頭に入れる (issue の案) | 収集した事実と呼び出し元の主張が同じ field に入り、`argv` と `cwd` の照合が主張をそのまま照合する。評価の入力は収集した事実だけ、という境界が崩れる。値を使うアプリ (pam-passkey) は、その値を自分で持っている |
| `ProcessInfo` に渡された値の別の field (`supplied: Option<Supplied>`) を足す | 照合とは混ざらないが、chain が主張を運ぶ型になる。使うアプリは 1 つで、そのアプリが値を持っている。chain に入れて得るのは表示の時に 1 か所から読めることだけ |
| `argv` と `cwd` を出どころ付きの型 (`Collected(T)` / `Supplied(T)`) にする | 組み込みの項目とアプリの項目の全部が出どころを扱うことになり、扱い忘れた項目が主張を照合する |
| 対象の識別子 (`ProcessIdentity`) を受けて、その個体を集める入口 (`collect_process`) を足す | 「識別は pid より強いもので」に沿うが、今の利用者に要るものがいない。pam-passkey の helper は、自分の列と行の識別子の照合で足りる。識別子で対象を渡すアプリが現れたら足す |
| `ProcessChain<S>` の型引数で、収集したもの (`Collected`) と受け取ったもの (`Received`) を分ける | `Collected` を作る関数は procline-macos のために公開になり、強制の強さは `from_collected` と同じ。受け取った chain を表示する利用者もいないので、型引数の手間 (`Condition` の `pin` / `check` を含む全部の署名) だけが増える |
| 収集の結果を OS ごとの crate の型にし、procline-acl は trait で受ける | procline-acl が trait を公開すれば誰でも実装でき、強制にならない。封じた trait は OS ごとの crate からも実装できない |
| 構築関数を `unsafe fn` か `#[doc(hidden)]` にする | `unsafe` は Rust ではメモリ安全の印で、論理の約束に使うと読み手を誤らせる。`#[doc(hidden)]` は文書から隠すだけで、呼び出し箇所で表明として読めない |
| chain に収集したプロセスの鍵で署名 (MAC) を付け、評価の入口で検証する | 鍵が同じプロセスにあるので、プロセスの中では守りにならない。別のプロセスが集めた chain を評価する利用者もいない。要る利用者が現れたら、その時に別の入口として設計する |

## Consequences

- 外から受け取った JSON を読み込むだけでは、評価の型 (`ProcessChain`、`ProcessInfo`、`CodeSigning` 等) にならない。評価の入口に渡る chain は、収集の入口か `from_collected` からしか来ない
- アプリのコードが field を 1 つずつ書いて `ProcessInfo` を組み、`from_collected` に渡すことは止められない。それは読み込みでなく明示の組み立てで、呼び出し箇所は名前で探せる。issue の受け入れ条件「外から受け取った JSON を、検証なしに評価へ渡せない (型で止まる)」は、読み込みの経路について満たし、明示の組み立ては範囲外 (評価するアプリ自身は脅威モデルの範囲外) と読む
- `truncated` と `boot_uuid` を収集の後に書き換えられなくなり、タグは `Policy::tag` が付けたものだけになる
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md) の「JSON (`code_signing`)」のうち、読み込みの規則 (`mark` を決め直して一致しなければエラー) をこの DR が置き換える。書き出しの形は変わらない
- テスト: `CodeSigning` の往復と列の往復のテストは、書き出した JSON の形を確かめるテストに変わる。読み込みが印を拒むテストは、読み込みが無くなるので消える (仕様の変更に伴う。仕様を緩めて green にするのではない)。chain を組むテストは `from_collected` を使う
- procline-acl と procline-macos の `chain.boot_uuid`、`chain.truncated` の読み出しはアクセサに変わる
- cw の承認画面が評価するデーモンと別のプロセスで、chain を JSON で受け取っているなら、表示用の型が要り、プレビュー (`resolve_subject`) と grant の作成はデーモンの側で行う形になる (未確認)
- `TaggedChain` は、作った Policy と別の Policy の `evaluate` に渡しても止まらない (語彙とタグの定義が違えば、付いたタグが評価する Policy のものと食い違う)。この DR では扱わない
- 収集の入口は今のまま (`collect_peer`、`collect_pid`) で、足す入口は無い
- pam-passkey の helper は、自分の列 (`[helper, sudo, …]`) を集め、2 番目の行が PAM モジュールの名乗る識別子と合う時だけ要求を進め、その行に PAM モジュールから受け取った argv と cwd を「渡された値」として添える。root で動くコードに祖先の走査は要らない (pam-passkey の側で決めること)
- 付け替えの後の exec で列が別の親へ途切れずに繋がる問題 (issue `2026-11-15-ancestry-reset-by-exec-after-reparent`) は、helper と `sudo` の間にも、`sudo` より上の列にも起きうる。helper と `sudo` の間はアプリの照合で止まる。`sudo` より上は、この DR では変わらない
- 未観測の点:
  - helper (hardened runtime、Developer ID 署名) が自分の pid で集めた時の所要時間と、列の先頭 (自分) の署名の検証の結果
  - 走っている `sudo` の子として起動された helper から集めた列で、2 番目が `sudo` になること (同じ uid の親子では観測した。親が実効 uid 0 の組は、walk が使う値が uid を問わず読めることだけ観測済み)
  - socketpair を root のプロセスが作り、降格して exec した子が読む組と、その audit token での `collect_peer`
  - cw の実装での chain の使い方 (cw のリポは手元に無い)

## 関連

- [DR-0008](DR-0008-evaluation-semantics.md): 途切れた列と `undecidable`
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md): `CodeSigning` の JSON の形 (読み込みの規則をこの DR が置き換える)、ユーザ権限から走っている `sudo` の署名を検証する手順
- [DR-0012](DR-0012-strength-class-from-protection.md): 保護の状態とクラス (chain の `runtime` と `entitlements` を信じる側)
- [DR-0013](DR-0013-collect-only-dependencies.md): 収集だけのアプリの依存
- [DESIGN-ja の「脅威モデルの前提」「収集する情報」「収集の整合性」「API の骨格」](../DESIGN-ja.md)
- issue: [JSON から読み込んだ ProcessChain を評価が信用する](../issue/2026-11-15-deserialized-chain-is-trusted-by-evaluate.md)、[呼び出し元が渡して補う入口](../issue/2026-11-15-caller-supplied-own-info.md)、[付け替えの後の exec](../issue/2026-11-15-ancestry-reset-by-exec-after-reparent.md)
- [findings: 親が終わった後の p_puniqueid](../findings/2026-11-15-puniqueid-after-reparent-and-exec.md)、[findings: collect_pid の観測](../findings/2026-11-09-collect-pid-observations.md)、[findings: socketpair の相手](../findings/2026-11-15-socketpair-peer-after-fork-exec.md)
- pam-passkey (別リポ): DR-0003 (helper の起動)、`crates/protocol` の `HelperInput` (helper の起動時の入力)、issue `2026-11-15-collect-in-helper-with-procline`
