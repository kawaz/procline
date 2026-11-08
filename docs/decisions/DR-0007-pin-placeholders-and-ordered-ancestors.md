# DR-0007: rule の subject に pin の placeholder (`true`) を置き、`ancestors` は順序付きの部分列にする

- Status: Active
- Date: 2026-11-08

## Context

- 「いつもの許可」を rule として一覧に保存し、承認画面で選んで passkey 1 回で grant にしたい([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md))。subject が常に具体値だと、rule は特定のアプリの値に固定され、同じ形の許可をアプリごとに別の rule として保存することになる。1 つの rule で済ませるには、rule にはどの項目・field を pin するかだけを書き、実値は承認のときに埋める必要がある。
- 祖先への条件で「祖先のどれか」を表す書き方は、placeholder をどの祖先の値で埋めるかが曖昧になる(当たる祖先が複数あり得る)。「n 個上」や「間に何も挟まらない並び」を指定する書き方は、tmux、direnv、ラッパの有無で深さが安定しないので、実際のプロセスの列には使えない。

## Decision

### subject の値: 具体値か placeholder

| rule に書く値 | 意味 | 例 |
| --- | --- | --- |
| 具体値(文字列か数値。glob / 正規表現 / 数値範囲は `{"glob": …}` / `{"regex": …}` / `{"min": …, "max": …}`) | 手書きの具体値。そのまま照合する | `{"binary": {"team_id": "MYTEAM", "signing_id": "myapp"}}` = 自作アプリからは常に allow |
| `true` | placeholder。grant を作るときに、その subject が当たったプロセスの実値を pin する | `{"binary": {"team_id": true, "signing_id": true}}` = 承認したそのアプリに固定 |

- 構造を持つ値では field 単位で混ぜられる(`{"binary": {"signing_id": "com.googlecode.iterm2", "team_id": true}}` = signing identifier で見つけ、その Team ID を pin)。`process` は `true`(個体を pin)か具体値の複合。単純項目(`cwd`、`uid`、`path` …)も `true` で実値を完全一致で pin する。
- placeholder を書けるのは rule の inline の subject だけ。タグの定義と名前付きの subject に `true` があれば、loader はエラーにする(`LoadError::InvalidValue`)。placeholder を含む rule は読み込み時に自動で永続の grant にはならず、承認を経てだけ grant になる([DR-0008](DR-0008-evaluation-semantics.md))。
- grant の subject は inline の `Subject` で、placeholder を全部具体値に解決済み(名前付きの subject は展開する)。grant に `true` が残っていれば、loader はエラーにする(`LoadError::InvalidValue`)。
- 解決は `Policy::grant(&self, rule: &Rule, tagged: &TaggedChain, ctx: &EvalContext) -> Result<Grant, GrantError>` が行う(grant を返すだけで、メモリ上の Policy には入れない。[DR-0008](DR-0008-evaluation-semantics.md))。各 placeholder は項目の `Matcher::resolve` が実値に置き換える。`match` の placeholder は対象プロセス(列の先頭)の値、`ancestors` の要素の placeholder はその要素が当たった祖先の値で埋める。値が無ければ(署名が無いのに `team_id: true` 等)`GrantError::ValueUnavailable { key, field: Option<String> }`(項目の `ResolveError::ValueUnavailable { field }` に key を付けたもの)。
- 承認画面が passkey の前に「何が pin されるか」を見せられるよう、`Policy::resolve_subject(&self, subject: &SubjectRef, tagged: &TaggedChain) -> Result<Subject, GrantError>` を公開する。名前参照は一覧の subject に解決してから埋める (無ければ `GrantError::UnknownSubject`)。`grant` も内部でこれを使う。
- 強さのクラスは placeholder でも判定できる(どの field かは分かるため)。`Matcher::class(value, process)` は placeholder 入りの値も受ける。
- 「いつもの許可」は 1 つの rule で済む。`RuleBuilder`(`Policy::rule_builder(id, subject)` から作る)/ `SubjectBuilder` は収集結果を受け取らず、`PinSpec` から `true` 入りの subject を組む。

型の形:

- procline-core: `Pinnable<T> { Pin, Value(T) }`(JSON では `true` が `Pin`、それ以外は `T` の値)。`BinaryPin` の field は `Option<Pinnable<String>>`、`cdhash` は `Option<Pinnable<CdHash>>`。
- procline-acl: `MatchValue::Pin`(単純項目の placeholder)、`MatchValue::Process(Pinnable<ProcessIdentity>)`。
- `SubjectBuilder::new()` の `pin(key, PinSpec)` / `exact(key, MatchValue)` / `tag(name)` / `ancestor(AncestorMatch)` / `include_self()` / `build() -> Result<Subject, BuildError>`。祖先の要素は `AncestorBuilder` の `pin` / `exact` / `tag` / `build() -> Result<AncestorMatch, BuildError>` で組む。
- 同じ key への `pin` と `exact` は、`binary` では field 単位で 1 つの値に合成する(同じ field が両方にあれば `BuildError::Conflict`)。単純項目と `process` は 2 回目で `BuildError::Conflict`。
- `SubjectBuilder::build` / `AncestorBuilder::build` が検査するのは値の妥当性(`binary` の規則、空)だけ。語彙との照合(未登録の項目、`Matcher::validate`)は `RuleBuilder::build` の責務。
- 真偽値の完全一致は持たない。JSON の `true` は placeholder 専用で、真偽値の項目は今は無く、要るときは文字列で表す。

### `ancestors`: subject の順序付きの列(部分列の一致)

```json
{
  "match": { "binary": { "team_id": true, "signing_id": true } },
  "ancestors": [
    { "match": { "binary": { "signing_id": "com.anthropic.claude-code", "team_id": true } } },
    { "tags": ["terminal-app"] }
  ]
}
```

- `ancestors` の各要素は `match` と `tags` だけを持つ(`AncestorMatch`)。要素の中に `ancestors` を入れ子にせず、名前で参照もしない。
- 意味: 列の各要素が、この順で祖先のどこかに当たる。間に別の祖先が挟まってよい(部分列の一致)。
- 順序は対象に近い方から(収集結果の列 `[対象, 親, 祖父, …]` と同じ向き)。上の例は「上に claude-code がいて、さらにその上に `terminal-app` のタグが付いたプロセスがいる」。
- 照合は近い側から貪欲に決める。要素 1 を最も近い当たる祖先に、要素 2 をそのさらに上で最も近い当たる祖先に、と決める。placeholder の解決は「その要素が当たった祖先の値」で一意に決まる。具体値もタグも無い要素(`{"match": {"binary": {"team_id": true}}}` だけ)は「その値を持つ最も近い祖先」に当たる。
- `include_self: true` は subject に 1 つ(要素ごとではない)。列の照合を祖先ではなく対象自身から始めてよい、の意味(「自身か子孫」のタグの定義に使う)。対象自身に当たった要素の placeholder は対象自身の値で埋める。
- 「間に何も挟まらない」を区別する書き方は持たない(tmux / direnv / ラッパで深さは安定しないので、区別しても使えない)。
- ルールの強さは [DR-0003](DR-0003-rule-strength-from-own-match.md) のまま(`ancestors` は数えない。`ancestors` だけの subject は Weak)。

## Alternatives Considered

- 案 A: subject は常に具体値にし、アプリごとに rule を保存する
  - 不採用理由: 「いつもの許可」が承認したアプリの数だけ増える。同じ形の許可を 1 つの rule として選べない。
- 案 B: 祖先への条件に `any`(祖先のどれか)、`at`(n 個上)、`chain`(並び順まで指定)の 3 つの書き方を残す
  - 不採用理由: `any` は placeholder をどの祖先から取るかが曖昧になる。`at` と `chain` は、tmux / direnv / ラッパで深さが安定しないので、区別しても使えない。
- 案 C: 列の順序を遠い方(launchd 側)から書く
  - 不採用理由: 収集結果の列 `[対象, 親, 祖父, …]` と向きが逆になり、要素と祖先の index の対応が崩れる。
- 案 D: 貪欲に決めず、要素と祖先の当て方の全組み合わせを探索する
  - 不採用理由: 当て方が複数あり得るので、placeholder をどの祖先の値で埋めるかが一意に決まらない。

## Consequences

- builder は収集結果を持たない。承認画面は利用者が選んだ field を `true` で置いた rule を組み、実値は `Policy::grant` が `tagged` から埋める。
- 承認画面は `Policy::resolve_subject` で、passkey の前に pin される値をプレビューできる。
- grant の loader は placeholder の残りをエラーにする。grant は常に具体値だけで照合される。
- 署名が無いプロセスに `team_id: true` のような rule を適用すると、grant は作れない(`ValueUnavailable`)。
- `include_self` は subject に 1 つで、列の照合の始点だけを変える。
- 「直接の親だけ」のような深さを区別する条件は書けない。

## 関連

- [DESIGN-ja の「subject」「tag」「rule」「grant」「評価」「項目の登録」「ルールの作成と強さの制約」](../DESIGN-ja.md)
- [DR-0003](DR-0003-rule-strength-from-own-match.md): ルールの強さ(`ancestors` は数えない)
- [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md): rule と grant の分離、`Policy::grant`
- [DR-0005](DR-0005-process-identity-as-one-item.md): `process` の値の形
- [DR-0006](DR-0006-structured-values-instead-of-depends.md): 構造を持つ値の座(`binary` の field)と `Matcher::class`
- [DR-0008](DR-0008-evaluation-semantics.md): placeholder を書ける場所と、grant をメモリに入れる順
