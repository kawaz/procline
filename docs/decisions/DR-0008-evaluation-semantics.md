# DR-0008: 評価の意味論(順序、ask、既定の effect、失効の確定、途切れた列、観測の失敗、永続化と有効化の順、placeholder の場所、自動 grant 化の基準)を定める

- Status: Active
- Date: 2026-11-09

## Context

評価は grant だけを見て、採用した grant だけを advance する([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md))。その上で、次の点が文書の各所に分かれて書かれ、読み方が 1 つに決まっていなかった。

- 条件単位の真偽と grant 単位の採否がどの順で決まり、`advance` の結果がいつメモリ上の grant に効くか。`Policy::grant` や `evaluate` がメモリ上の grant を変えると、アプリが永続化する前に新しい grant や消費が効く。
- `ask` の grant が当たったときに、既定の effect と同じ扱いなのか、`ask` を返すのか。
- 寿命型は「一度偽になれば戻らない」としているが、評価から除くだけでは、時計の巻き戻しや観測の回復で `check` が真に戻れば grant が生き返る。
- 祖先の列が途中で途切れた(`ProcessChain.truncated`)とき、祖先への条件を持つ grant をどう扱うか。当たらない扱いにすると、祖先への条件を持つ deny が効かず allow が通る(fail-open)。
- condition の観測が失敗した(sysctl や IOKit の呼び出しの失敗)ときと、観測するものが無い・期間の外のときを区別するか。同じに扱うと、観測の失敗で寿命型の grant の失効が確定する。
- placeholder(`true`)をどこに書けるか。タグの定義や名前付きの subject は grant を作るときの対象プロセスと結び付かない。
- 読み込み時に自動で永続の grant になる rule には、placeholder を埋める機会も、chain や観測値から pin 値を作る機会も無い。
- 既定の effect を誰が与えるか。
- `uses` の上限が、並行する評価でどう守られるか。
- `explain` の `expired` を削除に使ってよいか。

## Decision

### 順序

1. 各 grant の条件を判定する(条件単位の真偽)。観測の失敗、寿命型の `check`、targets、subject の照合、状態型の `check`。
2. deny / allow / ask を決める(grant 単位の採否)。順序は deny > allow > ask。allow は ask を省くためにある。
3. 採用した grant にだけ `advance` をかけ、変わった grant の新版を `Decision.updated_grant` で返す。
4. アプリが変わった grant を署名して永続化し、**書けてから**結果(allow)を使う。

### 永続化と有効化の順

- `Policy::grant(&self, rule, tagged, ctx) -> Result<Grant, GrantError>` は grant を返すだけで、メモリ上の Policy には入れない。アプリが署名して永続化し、`Policy::add_grant` を呼んだときに効き始める。
- `evaluate` も `updated_grant` を返すだけで、メモリ上の grant を差し替えない。差し替えは `Policy::add_grant`(同じ id なら置換)で行う。
- 掃除のために `Policy::remove_grant(&mut self, id)` と `Policy::grants(&self) -> impl Iterator<Item = &Grant>` を持つ。
- アプリは `evaluate` → 永続化 → `add_grant` を直列化する。同時に走らせると、どちらの評価も同じ残り回数の grant を見るので、上限を超えて `uses` を消費できる。

### ask と既定の effect

- `ask` の grant が当たれば `Effect::Ask` を返し、`Decision.grant_id` は採用した ask の grant の id。既定の effect になるのは、どの grant も当たらないときだけ。
- 既定の effect はアプリが与える: `Policy::load_verified(bytes, sig, verifier, vocab, constraints, default_effect: Effect)`。`Decision.grant_id` が None のときの effect はこれ。

### 失効の確定

- 寿命型の condition の `check` が偽になった grant は、その評価でその場で失効を確定する。
- `Decision.expired: Vec<String>` に失効した grant の id を載せ、アプリが削除する(メモリ上は `remove_grant`、保存先からも)。
- 失効は一度確定したら戻らない。時計の巻き戻しや観測の回復で `check` が真に戻っても、確定した grant は削除されているので復活しない。
- `explain` も `expired` を載せるが、失効を確定しない。アプリは `explain` の `expired` を削除に使わない。

### 列が途切れた chain

- `ProcessChain.truncated: Option<Truncated>`。`enum Truncated { MaxAncestors, AncestorExited, Unavailable }` が途切れた理由を表す。
- subject の条件(`match` ∧ `tags` ∧ `ancestors` の部分列)はすべて肯定条件で、列を延ばしても「当たった」が「当たらない」に変わらない(単調)。よって途切れた列で当たった grant は全列でも当たるので、効果の決定に使う。
- `Decision.undecidable: Vec<String>` は、祖先への条件(`ancestors`、またはその定義が `ancestors` を持つタグ。タグが別のタグを参照するときは推移的に辿る)を持ち、途切れた列で当たらなかった grant の id。効果の決定にはそれらを使わない。
- `TaggedChain.undecidable_tags: BTreeSet<String>` は、途切れた列で有無を判定できなかったタグ。承認画面は「付いていない」と区別して見せる。
- 判定できない deny があるのに allow を通してよいかはアプリが決める。crate は事実を返す。

### 観測の失敗

- `Condition::observe(&self) -> Result<Option<Value>, ObserveError>`。`Ok(None)` は観測するものが無い、または期間の外(寿命型なら `check` が偽になり、失効が確定する)。`Err` は観測に失敗した(sysctl や IOKit の呼び出しの失敗)。`ObserveError { reason: String }`。
- `EvalContext` は key ごとに `Result<Option<Value>, ObserveError>` を持つ。
- `Err` のとき、その condition を使う grant はその評価で判定できない。`Decision.undecidable` に載せ、許可にも失効にもしない。

### `os.not_remote`

- 判定は asid(接続相手のセッションがコンソールのもの)だけで行う。祖先に sshd がいないことは使わない。祖先の有無は double-fork で変えられるため。

### `os.login_session` は状態型

- 寿命型の「偽になれば失効を確定する」は、観測値(世界の状態)と pin 値を比べる condition にだけ当てはまる。
- `os.login_session` は接続相手に依存する値を比べるので、偽になっても世界の状態が変わったのではなく、別の相手が来ただけ。よって状態型で、作成時の `{boot_uuid, asid}` を pin 値に持つ(状態型も pin 値を持てる。boot UUID と組にするのは [DR-0009](DR-0009-strength-class-as-specificity.md))。

### placeholder の場所

- placeholder(`true`)を書けるのは rule の inline の subject だけ。タグの定義と名前付きの subject に `true` があれば `LoadError::InvalidValue`。
- grant の subject は inline の `Subject`(`Grant.subject: Subject`)。名前付きの subject は grant を作るときに展開する。タグ名の参照だけは名前のまま残す([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md))。

### 自動 grant 化の基準

- 一覧の rule のうち、寿命型・消費型の condition を持たず、placeholder を含まず、pin に chain や観測値を要する condition(`os.login_session` 等)も含まないものは、読み込み時に自動で永続の grant になる。
- それ以外の rule は承認を経てだけ grant になる。

## Alternatives Considered

- 案 A: 失効した grant を「評価から除く」だけにする
  - 不採用理由: grant が残るので、観測の回復(観測できなかった世代がまた観測できる)や時計の巻き戻し(`until` の `check` が真に戻る)で、失効したはずの grant が復活する。失効をその場で確定して `expired` で返し、アプリが削除すれば戻らない。
- 案 B: `truncated` を無視して、取れた列だけで評価する
  - 不採用理由: 祖先への条件を持つ deny は、途切れた先に当たる祖先がいても当たらない扱いになり、allow が通る(fail-open)。判定できない grant を `undecidable` として返し、効果の決定から外せば、どう扱うかをアプリが事実を見て決められる。
- 案 C: `Policy::grant` が grant をメモリにも入れて返す(`evaluate` もメモリ上の grant を差し替える)
  - 不採用理由: 永続化の前に効く。書き込みに失敗すると、保存先に無い grant や消費がメモリ上だけで効き、デーモンの再起動で食い違う。メモリに入れるのを `add_grant` に分ければ、効くのは書けた grant だけになる。
- 案 D: `os.login_session` を寿命型にする
  - 不採用理由: 別のセッションの相手が評価されただけで `check` が偽になり、失効が確定して、元のセッションからも使えなくなる。
- 案 E: 列が途切れたら、祖先への条件を持つ grant を当たったかどうかによらず判定不能にする
  - 不採用理由: subject の条件は単調なので、途切れた列で当たった grant は全列でも当たり、判定できている。判定不能にすると、確かに当たっている deny や allow まで効果の決定から外れる。
- 案 F: 観測の失敗を `Ok(None)`(期間の外)と同じに扱う
  - 不採用理由: 寿命型では `check` が偽になって失効が確定し、戻らない。観測の呼び出しが一度失敗しただけで、期間の中にある grant が失われる。

## Consequences

- アプリは評価の後に、`updated_grant` の永続化と `add_grant`、`expired` の削除と `remove_grant` を受け持つ。
- メモリ上の grant が変わるのは `add_grant` / `remove_grant` だけになる。
- `truncated` のときや観測に失敗したときの扱い(判定できない deny が残る中で allow を通すか)はアプリの判断になり、crate は既定を持たない。
- `ask` の grant に当たったときは、既定の effect が何であっても `Effect::Ask` になる。
- 一覧を手で書くとき、タグの定義と名前付きの subject には具体値だけを書く。
- placeholder や `os.login_session` を含む rule は、寿命型・消費型を持たない deny でも、承認を経るまで効かない。
- `uses` は二重に消費されない。値を渡すのは永続化に成功した後なので、永続化に失敗したときは値も渡していない。上限を守るには、アプリが評価と永続化を直列化する必要がある。
- アプリは削除に `evaluate` の `expired` だけを使う。
- `os.login_session` の grant は、別のセッションの相手が評価されても失効しない(当たらないだけ)。

## 関連

- [DESIGN-ja の「評価」「rule」「grant」「保存」「条件」](../DESIGN-ja.md)
- [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md): rule と grant の分離、condition の observe / pin / check / advance、grant の保存
- [DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md): subject の placeholder と、`ancestors` の順序付きの部分列
- [DR-0009](DR-0009-strength-class-as-specificity.md): 強さのクラスの定義と、世代の値、`os.login_session` の pin 値の boot UUID
