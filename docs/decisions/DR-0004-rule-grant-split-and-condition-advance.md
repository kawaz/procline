# DR-0004: 静的な rule と pin 済みの grant を分け、condition を observe / pin / check / advance で表す

- Status: Active
- Date: 2026-11-08

## Context

ACL の許可には 2 つの層がある。1 つは署名付きの一覧に入る静的な定義(誰が、何に、どんな条件で、どうなるか)で、条件は `{"os.session": "boot"}` や `{"age": "1h"}` のような記号のまま書く。もう 1 つは、それを承認の瞬間の接続相手に適用し、寿命型の条件にその時点の世代を記録したもので、評価が実際に見るのはこちら。

- 両者を同じ名前で呼ぶと、`uses`(残り回数)のように評価のたびに変わる値をどこが持つかが曖昧になる。静的な定義が持つなら、署名付きの一覧を評価のたびに書き換えることになる。
- 適用して pin したものを 1 件ずつ永続化すれば、変わる値の更新はその 1 件の書き込みで済み、一覧の再署名が要らない。
- 寿命型(scope)、消費型(`uses`)、状態型の条件はどれもアプリが足せる語彙で、同じ形の実装で表したい。消費型は「採用されたら減る」という、評価の結果に応じた更新を持つ。

## Decision

### 語彙: rule と grant

| 名前 | 中身 |
| --- | --- |
| rule | 静的な定義。effect、subject、targets、conditions を持つ。conditions は記号のまま。署名付きの一覧(subject、tag、rule)に入る |
| grant | rule を実際のプロセス(承認の瞬間の接続相手)に適用し、subject の placeholder を実値に、各 condition を具体値に pin したもの。評価の対象はこれ。永続化は 1 件ずつ |

- 保存した rule がそのまま再適用の対象になる。承認画面に rule の一覧を出し、選んで passkey を 1 回通せば grant ができる。
- `RuleBuilder::build()` は静的な rule を返すだけで、世代は記録しない。
- 承認画面でその場で条件を選んで許可する流れは「rule を組み立て、すぐ grant にする」の 2 段。rule を一覧に保存するかは利用者が選び、保存しなければ使い捨ての rule になる。
- 寿命型・消費型の condition を持たない rule から作った grant は pin 値が無く、失効しない(永続の grant)。deny は普通こちら。
- 静的な rule を評価に直接使うことはしない。評価が見るのは grant だけ。一覧の rule のうち寿命型・消費型の condition を持たないものは、読み込み時に自動で永続の grant になる(手書きの deny を「許可する」操作なしに効かせるため)。寿命型・消費型を含む rule は承認を経てだけ grant になる。
- grant は自己完結。effect、targets、pin 済みの conditions、placeholder を解決した subject を自分で持ち、元の rule の id を `rule_id` として持つ(表示と掃除に使う)。rule が後で変わっても既存の grant は変わらない。
- grant の subject は inline の `Subject`。rule の subject が名前で参照していれば、grant を作るときに展開する。subject の中のタグ名の参照だけは名前のまま残す。タグの定義は署名付きの一覧にあり、その更新は意図した変更なので、既存の grant にも及んでよい([DR-0008](DR-0008-evaluation-semantics.md))。
- grant の `id` は `Policy::grant` が一意に付ける(形式は実装時に決める。下の JSON の `g-…` は例示)。

grant の形:

```json
{
  "id": "g-2026-11-08-0001",
  "rule_id": "pj1-claude-usual",
  "effect": "allow",
  "subject": { "tags": ["claude-pj1"] },
  "targets": ["key:k1"],
  "conditions": [
    { "key": "os.session", "args": "unlocked", "pinned": { "boot": "7B1E…", "awake": "…", "unlocked": "…" } },
    { "key": "app.unlock", "pinned": 12 },
    { "key": "until", "pinned": "2026-11-08T13:00:00+09:00" },
    { "key": "uses", "pinned": 3 },
    { "key": "os.not_remote" }
  ],
  "created_at": "2026-11-08T12:00:00+09:00",
  "created_from": "approval-ui"
}
```

- `conditions` の各要素は `key`、元の引数 `args`(必要なら)、`pinned`(pin 値。状態型には普通は無く、`os.login_session` のように接続相手に依存する値を固定するものだけが持つ)。`age` は grant を作るときに `until` の pin 値に直す(`key` も `until` にする)。
- `os.session` の pin 値は段階以下の世代を全部持つ([DR-0006](DR-0006-structured-values-instead-of-depends.md))。世代は事象固有の値(`awake` は起床の時刻、`unlocked` は解錠の時刻。[DR-0009](DR-0009-strength-class-as-specificity.md))。

### condition の実装: observe / pin / check / advance

寿命型、消費型、状態型は、同じ trait の関数で表す。外の状態(世代、画面ロックの状態など)を読むのは `observe` だけで、`pin` / `check` / `advance` は渡された値から結果を決める。condition が触るのは自分の pin 値だけで、grant 全体は受け取らない。

```rust
/// この condition の観測値。EvalContext::capture が評価の最初に 1 回だけ観測し、評価の途中で変わらない
pub struct Observed<'a> {
    pub now: SystemTime,
    pub value: Option<&'a Value>,   // observe() の結果。無ければ None
}

trait Condition {
    fn kind(&self) -> ConditionKind;                                   // Lifetime / State
    /// 今の値を観測する (世代の uuid、画面ロックの状態など)。評価の最初に EvalContext::capture が全 condition に 1 回呼ぶ。観測するものが無い condition は None
    fn observe(&self) -> Option<Value>;
    /// grant を作るときに 1 回。pin 値を返す。接続相手の asid のように chain から取るものは chain を見る。状態型は普通 Ok(None) で、接続相手に依存する値を作成時に固定するもの(os.login_session)は pin 値を返す。寿命型で観測値が無ければ Err(PinError::Unobservable)。args が不正なら Err(PinError::InvalidArgs)
    fn pin(&self, args: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> Result<Option<Value>, PinError>;
    /// 判定。副作用なし
    fn check(&self, args: Option<&Value>, pinned: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> bool;
    /// 採用された grant にだけ呼ぶ。pin 値の新版。None なら変化なし
    fn advance(&self, pinned: Option<&Value>) -> Option<Value>;
    /// 引数の妥当性。読み込みと builder が呼ぶ
    fn validate_args(&self, args: Option<&Value>) -> Result<(), String>;
}

enum PinError { Unobservable, InvalidArgs { reason: String } }
```

| 項目 | observe | pin | check | advance |
| --- | --- | --- | --- | --- |
| 世代(`os.session`、`app.unlock` …) | 今の世代 | observed の値(無ければ Err)。`os.session` は段階以下の世代の複合 | pinned == observed。`os.session` は段階以下の世代が全部一致 | None |
| `until` | None | args の時刻 | obs.now < pinned | None |
| `age` | None | obs.now + args の期間(`until` の pin 値になる) | obs.now < pinned | None |
| `uses` | None | args の N | pinned > 0 | pinned − 1 |
| 状態型(`os.console_active` 等) | 今の状態(観測するものがあれば) | None | observed / args / chain を見る | None |
| 状態型 `os.login_session` | None | chain の接続相手の asid | chain の接続相手の asid == pinned | None |

- 世代を返す専用の trait は持たない。世代の観測は `observe` が受け持ち、pin 値は JSON の値 (`serde_json::Value`) で表す。語彙への登録は `Item::condition` に統一する。
- `ConditionKind` は Lifetime / State の 2 値。世代、`until`、`age`、`uses` は Lifetime で、`uses` も一度 0 になれば戻らない。
- `EvalContext` は `now` と「key → `observe()` の結果」を持つ。`EvalContext::capture` が評価の最初に全 condition の `observe` を 1 回ずつ呼び、評価の途中で値は変わらない。Policy が condition ごとに `Observed { now, value: ctx.observed(key) }` を組んで渡す(condition は自分の key を知らない)。
- 状態型の `check` には `args` が届くので、`time.window` の時間帯のような引数を判定に使える。
- 状態型も pin 値を持てる(接続相手に依存する値を作成時に固定する。`os.login_session` の asid)。寿命型の「偽 → 失効の確定」は観測値(世界の状態)と pin 値を比べる condition にだけ当てはまり、接続相手に依存する値の不一致は別の相手が来ただけなので、`os.login_session` は状態型。

### 評価と grant の更新

評価の順序、`ask`、失効の確定、途切れた列の扱いは [DR-0008](DR-0008-evaluation-semantics.md) が定める。要点:

1. 各 grant の条件を判定する。寿命型の `check` が偽になった grant はその場で失効を確定し(`Decision.expired`)、targets が対象に当たらない grant を除き、subject を照合して状態型の `check` を取る。列が途切れていれば `ancestors` を持つ grant と、`ancestors` で定義したタグを subject に持つ grant は判定できない(`Decision.undecidable`)。
2. deny > allow > ask の順で effect を決める。`allow` が当たれば、当たった allow のうち採用するのは 1 件。advance で変わらない grant(永続、または `uses` を持たない)を優先し、同順なら作成の古い順(他の grant で通るのに、限りある `uses` を減らさないため)。`ask` が当たれば `Effect::Ask`(`grant_id` は採用した ask の grant)、何も当たらなければ既定の effect。
3. 採用された grant にだけ、各 condition の `advance` をかける。1 つでも `Some` なら pin 値を差し替えた新しい grant を作る(grant は immutable)。
4. アプリが変わった grant を署名して永続化し、書けてから結果を使う。

```rust
pub struct Decision {
    pub effect: Effect,
    pub grant_id: Option<String>,        // 採用された grant(ask なら採用した ask の grant)。既定の effect なら None
    pub trace: Trace,
    pub updated_grant: Option<Grant>,    // advance で変わった grant の新版。アプリはこれを署名して書いてから add_grant で差し替え、値を渡す
    pub expired: Vec<String>,            // この評価で失効が確定した grant の id(DR-0008)
    pub undecidable: Vec<String>,        // 列が途切れていて判定できない grant の id(DR-0008)
}
impl Policy {
    pub fn evaluate(&self, tagged: &TaggedChain, target: &Target, ctx: &EvalContext) -> Decision;     // advance あり。新版を返すだけで、メモリ上の grant は変えない
    pub fn explain(&self, tagged: &TaggedChain, target: &Target, ctx: &EvalContext) -> Decision;      // advance なし (trace 表示用)。updated_grant は常に None
}
```

- 消費は `evaluate` の中の `advance` で行う。消費を記録する別の入口は持たない。
- アプリは `updated_grant` を署名して永続化し、書けてから `Policy::add_grant`(同じ id なら置換)で差し替えて値を渡す。書けなかったときは allow を使わない。
- `uses` が 0 になった grant は、次の評価で手順 1 により失効が確定し、`Decision.expired` に載る。削除はアプリが行う。

### grant の保存

- grant はメモリ上に持ち、デーモンの意図しない終了に備えて、作成時と更新時に 1 件ずつ署名して永続化し、起動時に全部読み直す。保存と署名はアプリの責務(一覧と同じ)。crate は `Grant` の JSON の形と、2 つの入口を持つ。
  - `Policy::load_grant(bytes, sig, &verifier) -> Grant`: 1 件のバイト列と署名を検証し、一覧と同じ検査(未登録の項目、値の妥当性)をする。落ちればエラー。
  - `Policy::add_grant(grant)`: grant をメモリ上の Policy に入れる。同じ id があれば置き換える。読み直した grant、`Policy::grant` で作って永続化した grant、永続化した `updated_grant` に使う。
  - 掃除には `Policy::remove_grant(id)` と `Policy::grants()` を使う([DR-0008](DR-0008-evaluation-semantics.md))。
- 1 件ずつなので `uses` の更新の書き込みは軽い(実測は実装時のベンチで確かめる)。
- 世代は事象固有の値なので、起動時に読み直した grant も再起動を跨いで判定できる([DR-0009](DR-0009-strength-class-as-specificity.md))。
- 永続化先のディレクトリは、評価するデーモン以外(同じ uid の他プロセス)から書けない場所に置く。書けると、使い切る前の grant ファイルを差し戻して `uses` を戻せる。置き場はアプリが決める。
- 静的な一覧(subject、tag、rule)の署名付き保存はそのまま。保存形は「一覧 1 本」と「grant 1 件ずつ」の 2 系統。

### builder と強さの制約

- `SubjectBuilder` は収集結果を持たず、placeholder(`true`)入りの subject を組む([DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md))。
- `RuleBuilder` は `Policy::rule_builder(id, subject)` から作る。`RuleBuilder::build()` は静的な `Rule` を返す。検査するのは値の妥当性と、強さ(クラス)と scope の制約([DR-0003](DR-0003-rule-strength-from-own-match.md))。制約の表(`AllowConstraints`)とどの scope が制約を満たすかはアプリが与える([DR-0009](DR-0009-strength-class-as-specificity.md))。
- `Policy::grant(&self, rule: &Rule, tagged: &TaggedChain, ctx: &EvalContext) -> Result<Grant, GrantError>` が subject の placeholder を `tagged` の実値で埋め、各 condition を pin し、id を付けた grant を返す。メモリ上の Policy には入れない。アプリが署名して永続化し、書けてから `Policy::add_grant` で入れる([DR-0008](DR-0008-evaluation-semantics.md))。`GrantError` は placeholder を埋める値が無い(`ValueUnavailable`、[DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md))、`pin` の失敗(`PinError`: 観測値が無い、引数が不正)、値の妥当性の違反。rule の再適用もこの入口で行う。

## Alternatives Considered

- 案 A: 一覧の中の rule に残り回数を書き戻し、評価のたびに一覧を再署名する
  - 不採用理由: 静的な定義と変動値が同じ場所に混ざり、`uses` の 1 回の消費ごとに一覧全体の書き直しと再署名が要る。grant 単位で永続化すれば、変わるのはその 1 件だけで済む。
- 案 B: 残り回数を署名の外の別ファイルに持つ
  - 不採用理由: 署名の外にある値は同じ uid のプロセスが書き換えられるので、残り回数を戻して許可を使い直せる。`uses` が守ろうとしている回数の上限が保証されない。
- 案 C: condition が grant 全体を受け取って新しい grant を返す(`(procinfo, grant) => grant`)
  - 不採用理由: condition が他の condition の pin 値や subject まで書き換えられる形になる。また評価の途中で進める形になり、採用されなかった grant も進んでしまう。condition が触るのを自分の pin 値だけに絞り、進めるのは採用が決まった後の `advance` に分ける。
- 案 D: condition に `() => void` の後処理コールバックを持たせ、採用されたら呼ぶ
  - 不採用理由: 変動値がコールバックのクロージャの中に隠れ、grant の中身として外から見えない。永続化するアプリが新しい中身を取り出せず、デーモンの再起動で消費が失われる。`advance` が pin 値の新版を値として返せば、それを差し替えた grant をそのまま署名して書ける。

## Consequences

- 評価の入口が `evaluate`(advance あり、新版を返す)と `explain`(advance なし、trace の表示用)の 2 つになる。表示のために評価して `uses` を減らしてしまう誤りを、入口の違いで防ぐ。
- 保存形が「一覧 1 本」と「grant 1 件ずつ」の 2 系統になる。アプリは両方の署名と保存を受け持つ。
- grant の永続化先は、評価するデーモン以外から書けない場所に置く必要がある。書けると、古い grant ファイルを差し戻して `uses` を戻せる(ロールバック)。
- `uses` が 0 になった grant や、寿命型の `check` が偽になった grant は、評価で失効が確定して `Decision.expired` に載る。メモリと保存先からの削除はアプリの責務になる。
- grant は自己完結なので、rule を直しても既存の grant には反映されない。直した rule を効かせるには、改めて grant を作る。一方、subject が名前で指すタグの定義を直すと、既存の grant の当たり方も変わる。
- 複数の allow が当たったときは advance で変わらない grant が先に採用されるので、限りある `uses` は他の grant で通らないときだけ減る。
- アプリが足す寿命型・状態型の語彙は、`kind` / `observe` / `pin` / `check` / `advance` を実装すればよい。どれも自分の pin 値しか触らないので、組み込みの語彙と組み合わせても互いに干渉しない。

## 関連

- [DESIGN-ja の「rule」「grant」「評価」「条件の実装」「保存」](../DESIGN-ja.md)
- [DR-0001](DR-0001-crate-naming.md): crate の分け方(rule と grant を置く procline-acl)
- [DR-0006](DR-0006-structured-values-instead-of-depends.md): 構造を持つ値の座(grant の `os.session` の pin 値の形)と、値の妥当性の検査
- [DR-0003](DR-0003-rule-strength-from-own-match.md): rule の強さと、`allow` に許す scope の制約
- [DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md): subject の placeholder と、grant を作るときの解決
- [DR-0008](DR-0008-evaluation-semantics.md): 評価の意味論(順序、ask、失効の確定、途切れた列、永続化と有効化の順)
- [DR-0009](DR-0009-strength-class-as-specificity.md): 強さのクラスの定義、制約の表、世代の値
