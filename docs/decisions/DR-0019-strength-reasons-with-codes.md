# DR-0019: 条件の強さは、理由のコードと組で返す (判定の関数・結果の強さ・理由・コードの 4 つ 1 組の表で持つ)

- Status: Proposed
- Date: 2026-11-17

## Context

条件の強さ (クラス、強 / 中 / 弱) は、項目の実装 `Matcher::class` が `Strength` だけを返して決まり、ルールの強さは `Policy` の非公開の `own_class` が自身への条件から決める ([DR-0003](DR-0003-rule-strength-from-own-match.md)、[DR-0009](DR-0009-strength-class-as-specificity.md)、[DR-0012](DR-0012-strength-class-from-protection.md))。なぜその強さになったかは、どの口からも返らない。

DESIGN-ja の設計の柱 5 は「crate は条件の強さと、その理由になる事実を返す。弱い条件を拒むか、説明を添えて通すかは、アプリが決める」で、画面は項目を選ぶ所の横に強さと理由 (注意点) を出す ([issue](../issue/2026-11-17-strength-reason-codes.md))。今は理由が返らないので、画面に理由を出すには、アプリが crate の判定の規則を写して持つしかない。保護の状態の判定 (`Protection`) は procline-acl の非公開の型にあり、写す元も見えない ([issue](../issue/2026-11-15-handoff-review-followups.md) の 2)。

コードを読んで確かめた、今の判定の事実 (`crates/procline-acl/src/matchers.rs`、`vocabulary.rs`、`policy.rs`、`builder.rs`、`crates/procline-core/src/strength.rs`、`signature.rs`):

- 強さを決める関数は 6 種類ある。保護の状態 `Protection::of` (非公開)、項目ごとの `Matcher::class` (組み込みの 10 項目)、`Item::matcher_fn` の一定のクラス (`ConstClassMatcher`)、値の列の `value_class`、subject の `own_class` / `own_class_of`、タグの `tag_class` (この 2 つは非公開)。判定の分岐の全部は Decision の表
- `Protection::of` は、最初に当てはまった事実で返す。debugged か、`get-task-allow` 以外の 3 つの entitlement のどれかがあれば、残りを見ない。理由を複数持つ形になっていない
- 同じ事実が、項目によって違う強さに下げる。hardened runtime (`CS_RUNTIME`) が無いと、`binary` と `path` は開いている (弱) で、`process` は保護を緩める entitlement が無ければ認可で開く (中) (`Pins::Code` と `Pins::Individual`)
- 組み合わせで初めて下がる事実がある。`process` では、hardened runtime が無いことと `get-task-allow` があることは、片方だけなら中で、両方そろうと弱 (DR-0012 の観測の表の 4 行目。entitlement を持たないプロセスから task port が取れる)
- `path` は、所有者と書き込み可否 (`ProcessInfo.path_meta`) が取れなかった時も中に抑える。DR-0012 と DESIGN-ja「強さ: クラスと深さ」の表は、この場合を書いていない
- 項目が受けない形の値には、どの項目も弱を返す (`BinaryMatcher` は `BinaryPin::validate` の違反も)。build と読み込みが拒む値の、安全側の受け皿
- `BinaryMatcher::class` の「署名由来の field も `digest` も無ければ弱」の分岐は、その前の `BinaryPin::validate` が空の値を拒むので通らない
- 制約の違反のエラー (`BuildError::ScopeTooWeak`、`GrantError::ScopeTooWeak`、`LoadError::ScopeTooWeak`) は `class: Strength` を持ち、`Decision.too_weak` は grant の id だけを持つ。`Policy::load_verified` と `Policy::load_grant` は `todo!()` で、制約の検査は `RuleBuilder::build`、`Policy::grant`、評価 (`strong_enough`) の 3 か所にある
- `Vocabulary::class` は公開で、`own_class` は非公開。アプリは項目 1 つの強さは聞けるが、タグと `ancestors` を含めた subject の強さは聞けない
- `Strength` は procline-core にあり、`Matcher` と `Vocabulary` は procline-acl にある ([DR-0013](DR-0013-acl-layer-in-separate-crates.md))。収集だけを使うアプリ (DESIGN-ja「使い方の型」) は procline-acl に依存しない

この DR は [DR-0012](DR-0012-strength-class-from-protection.md) の保護の状態を前提にする。DR-0012 は [QUESTIONS](../QUESTIONS.md) の HO-C1 で裁定を待っていて、採られなければ、保護の状態から来る理由 (Decision の表の `protection.` で始まるコード) は無くなる。

- 目的:
  - 強さを返す口が、その強さになった事実を、文書に繋げられる識別子 (コード) と一緒に返す。アプリは crate の判定の規則を写さずに、項目の横に強さと理由を出せる
  - 判定と、その結果の強さ、理由、コードが 1 か所に並んでいて、判定を変えると理由とコードも同じ変更で直る
  - コードを変えても、古いコードから今のコードか「消えた」の説明に辿れる
- 増やしたくないもの:
  - 判定の規則を持つ場所 (crate の判定と、アプリが画面のために写す規則)
  - 強さと理由が別々に決まって、食い違いうる経路
  - 1 つの事実に 2 つのコードがあること、1 つのコードが 2 つの意味を持つこと
  - `Matcher` の method と、アプリの項目が実装する義務
  - 「何を許すか」を crate が決める箇所 (理由は事実で、通すか拒むかの判断を含まない。柱 3、[DR-0009](DR-0009-strength-class-as-specificity.md))

扱わないもの:

- 理由の文の多言語のリソースは、この DR では決めない (別に扱う)
- 画面の組み方と理由の文言の見せ方は procline の責務外
- 弱い条件を拒むか通すかの判断は procline の責務外
- オンライン文書の置き場と URL の形は procline の責務外
- アプリが足すコードの意味と文書は procline の責務外

## Decision

「どの選択肢でも変わらない部分」は既存の決定と DESIGN-ja の柱から導いたもので、項目ごとに出典を書く。既存の決定から決まらない点は「裁定待ちの分岐」(S1〜S7) に置く。下の例と表のコードの名前・返す形は、S1・S2・S4 の推奨の案で書いたもの。

### 例: API が返すもの

Team ID で `binary` を条件にした。照合したプロセスは hardened runtime の署名を持つが、保護を緩める entitlement `com.apple.security.cs.disable-library-validation` を持つ。

```text
// 承認画面で「このプロセスの Team ID で」を選んだ時 (照合するプロセスを渡す)
vocab.class("binary", {"team_id": true}, Some(&target))
  強さ: 弱
  理由: protection.disable_library_validation   上限 弱

// プロセスを渡さずに聞いた時 (RuleBuilder::build と読み込みが制約の検査に使う強さ。上限で決める)
vocab.class("binary", {"team_id": true}, None)
  強さ: 強
  理由: protection.without_process              上限 強 (注意点)

// Policy::grant で、制約の表が弱に課す scope が rule に無かった時
GrantError::ScopeTooWeak
  強さ: 弱
  理由: protection.disable_library_validation   上限 弱
```

cwd を条件にした。

```text
vocab.class("cwd", "/srv/proj", Some(&target))
  強さ: 弱
  理由: cwd                                     上限 弱
        cwd.snapshot                            上限 強 (注意点)
```

- `cwd` は「項目そのものが弱」(同じ uid のプロセスが値を決められる。柱 3) の理由、`cwd.snapshot` は強さを下げない注意点 (収集した時点の値で、後で変わりうる)
- 強さは理由の上限のうち最も低いもの。注意点は上限が強なので、強さを下げない (S2・S4 の推奨)
- アプリは、強さとコードから画面の文言と文書への繋ぎを作る。弱だから拒むか、説明を添えて通すかはアプリが決める

### 判定の表 (判定の関数・結果の強さ・理由・コードの 4 つ 1 組)

今のコードで強さを決めている判定の分岐を全部並べる。「結果の強さ」は、その事実が抑える強さの上限 (その事実だけがあった時の強さ)。保護の状態の行は、DR-0012 の 2 段 (保護の状態 → 項目ごとのクラス) をそのまま写し、コードの対象 (`binary`、`path`) と個体 (`process`) で分けて書く。

| 判定の関数 | 理由 (読む事実) | 結果の強さ | コード (案) |
|---|---|---|---|
| `Protection::of` | 検証に成功した署名が無い (`code_signing` が `Verified` でない、または収集していない) | コード 弱 / 個体 弱 | `protection.unverified` |
| `Protection::of` | debugged (`RuntimeState.debugged`) | 弱 / 弱 | `protection.debugged` |
| `Protection::of` | `com.apple.security.cs.allow-dyld-environment-variables` がある | 弱 / 弱 | `protection.allow_dyld_environment_variables` |
| `Protection::of` | `com.apple.security.cs.disable-library-validation` がある | 弱 / 弱 | `protection.disable_library_validation` |
| `Protection::of` | `com.apple.security.cs.disable-executable-page-protection` がある | 弱 / 弱 | `protection.disable_executable_page_protection` |
| `Protection::of` | status に hardened runtime (`CS_RUNTIME`) が無い | 弱 / 中 | `protection.no_hardened_runtime` |
| `Protection::of` | `com.apple.security.get-task-allow` がある | 中 / 中 | `protection.get_task_allow` |
| `Protection::of` | hardened runtime が無く、`get-task-allow` がある (entitlement の無いプロセスから接続できる) | 弱 / 弱 | `protection.get_task_allow_without_hardened_runtime` |
| `ProcessMatcher` / `BinaryMatcher` / `PathMatcher` の `class` | 照合するプロセスが無い (build、読み込み)。保護の状態と `PathMeta` を見ずに上限で決めた | 強 (注意点) | `protection.without_process` |
| 組み込みの全項目の `class`、`value_class` | 項目が受けない形の値 (妥当性の違反、空の列) | 弱 | `value.invalid` |
| `BinaryMatcher::class` | 署名由来の field が無く、`digest` だけ | 中 | `binary.digest_only` |
| `PathMatcher::class` | 実行パスの所有者が root でない (`PathMeta.owner_uid`) | 中 | `path.not_root_owned` |
| `PathMatcher::class` | 実行パスを利用者が書ける (`PathMeta.writable_by_user`) | 中 | `path.writable_by_user` |
| `PathMatcher::class` | 所有者と書き込み可否が取れなかった (`path_meta` が `None`) | 中 | `path.meta_unavailable` |
| `ResponsibleMatcher::class` | 項目そのものが中 (責任プロセス) | 中 | `responsible` |
| `NameMatcher` / `CwdMatcher` / `ArgvMatcher` / `UidMatcher` / `GidMatcher` / `TtyMatcher` の `class` | 項目そのものが弱 (同じ uid のプロセスが満たせる) | 弱 | 項目の key (`name`、`cwd`、`argv`、`uid`、`gid`、`tty`) |
| `CwdMatcher::class` | cwd は収集した時点の値 | 強 (注意点) | `cwd.snapshot` |
| `ConstClassMatcher::class` (`Item::matcher_fn`) | 登録した時に与えた一定のクラス (強でない時) | 与えたクラス | 項目の key (`app.…`) |
| `value_class` | 値の列は要素の最弱 | 要素の最弱 | 無し (要素の理由を全部集める) |
| `own_class` | 自身への条件が無い (`ancestors` だけ、または数えるものが無い) | 弱 | `subject.no_own_condition` |
| `own_class_of` | 自身への条件 (`match` とタグ) の最強 | 最強 | 無し (最強の条件の理由を集める) |
| `own_class_of` | `ancestors` と `include_self` は数えない | 強 (注意点) | `subject.ancestors_not_counted` |
| `tag_class` | タグの複数の定義は最弱 | 定義の最弱 | 無し (定義の理由を全部集める) |
| `tag_class` | 自身への条件が無い定義を持つタグは、強さに何も足さない | 強 (注意点) | `tag.definition_without_own_condition` |

- 各項目の強さは、項目の行と、その項目が使う保護の状態の行の上限のうち最も低いもの。`binary` の署名由来の field と `path` はコードの列、`process` は個体の列を使う。`binary` の `digest` だけの値も保護の状態の行を使う (今のコードで、開いていれば弱)。`responsible` と弱の 6 項目は保護の状態を使わない
- 保護の状態の行は、当てはまるものを全部返す (今の `Protection::of` のように最初の 1 つで止めない)。たとえば `process` で hardened runtime が無く `get-task-allow` がある時は、`protection.no_hardened_runtime` (中)、`protection.get_task_allow` (中)、`protection.get_task_allow_without_hardened_runtime` (弱) の 3 つで、強さは弱
- `BinaryMatcher::class` の「署名由来の field も `digest` も無ければ弱」の分岐は、`BinaryPin::validate` が先に空の値を拒むので、表では `value.invalid` に含める
- 登録されていない key と条件の項目は、今どおり強さに数えない (`Vocabulary::class` が `None`)。build と読み込みが拒むので、コードを持たない

### どの選択肢でも変わらない部分

#### 1. 強さを返す口は、理由と組で返す

- 強さを返す公開の口は、強さと、その強さの理由のコードを組で返す。対象は `Matcher::class` (返し方は S3)、`Vocabulary::class`、subject の強さ (下の 6)、制約の違反のエラー (下の 7)。出典: DESIGN-ja の設計の柱 5、[issue](../issue/2026-11-17-strength-reason-codes.md)
- 理由は判定が読んだ事実で、「通す / 拒む」「安全 / 危険」の判断を含まない。弱い条件も今どおり書けて、制約の検査は今どおりクラスだけで判定する (理由は検査の結果を変えない)。出典: 柱 3・柱 5、[DR-0009](DR-0009-strength-class-as-specificity.md)「制約の表はアプリが与える」
- 判定の分岐 1 つにつき、判定の関数・結果の強さ・理由・コードの 4 つを 1 組で書く (上の表)。判定を足す・変える時は、同じ変更で表の行を足す・変える。出典: [issue](../issue/2026-11-17-strength-reason-codes.md)

#### 2. コードは事実ごとに 1 つ

- コードは理由の事実を識別する。同じ事実を読む分岐は同じコードを返す (保護の状態のコードは `binary`、`path`、`process` が共有し、`value.invalid` は全項目が共有する)。1 つのコードは 1 つの意味しか持たない。出典: Context の「増やしたくないもの」
- 項目によって抑える強さが違う事実 (`protection.no_hardened_runtime`) も、コードは 1 つで、上限を項目の側 (コードの対象か個体か) で決める。DR-0012 が保護の状態を項目から独立に決め、項目ごとのクラスを別の表で決めている 2 段の形のまま。出典: [DR-0012](DR-0012-strength-class-from-protection.md)「保護の状態」「クラス」
- 組み合わせで初めて下がる事実は、その組を 1 つの事実として持つ (`protection.get_task_allow_without_hardened_runtime`)。DR-0012 の観測で、この組は他の 2 つのどちらとも違う経路 (entitlement の無いプロセスから task port と ptrace) を開いている。出典: [DR-0012](DR-0012-strength-class-from-protection.md) の観測の表の 4 行目
- 署名の検証ができなかったことは 1 つのコード (`protection.unverified`) にする。どう失敗したか (差し替え、未署名、時間切れ、収集しなかった) は `CodeSigning` と信頼の印 (`CodeSigning::mark`) が持っていて、理由のコードで同じ区別を重ねない。出典: [DR-0011](DR-0011-verified-signature-and-trust-mark.md)「信頼の印は core の 1 か所で決める」
- 当てはまる事実は全部返す。1 つの事実を直しても強さが上がらないこと (たとえば `path` を root 所有にしても、保護が開いていれば弱のまま) を、画面が伝えられる。出典: 柱 5 (理由になる事実を返す)

#### 3. 項目そのもののクラスの理由は、項目の key をコードにする

- 値によらずクラスが決まる項目 (`responsible`、弱の 6 項目、`Item::matcher_fn` で登録したアプリの項目) は、その強さの理由を項目の key そのもののコードで返す。key は語彙の中で重複しない (`Vocabulary::register` が重複を拒む) ので、コードも重複しない。出典: [DR-0006](DR-0006-structured-values-instead-of-depends.md)「名前空間」、`Vocabulary::register`
- `Item::matcher_fn(key, class, f)` で登録した項目は、与えたクラスが強でない時、crate が key のコードと与えたクラスの組を理由にする。アプリはコードを渡さなくてよい

#### 4. 組み込みのコードとアプリのコードを名前空間で分ける

- 組み込みのコードは `app.` で始めない。アプリの項目が返すコードは、その項目の key (`app.` で始まる) で始める。アプリの項目同士は key が重ならないので、コードも項目をまたいで重ならない。出典: DESIGN-ja「アプリが足す語彙」(アプリ固有のものは `app.` に置く)
- 1 つのアプリの項目の中でのコードの重複と意味は、アプリが持つ (「扱わないもの」)

#### 5. 列とタグの理由の集め方

- 値の列 (`MatchValue::AnyOf`) とタグの複数の定義は、強さが最弱になる ([DR-0010](DR-0010-or-in-values-and-tag-definitions.md))。どれか 1 つで通るので、どの要素・定義の弱さも条件の弱さになる。理由は全部の要素・定義から集める (同じコードは 1 つにまとめる)
- 自身への条件を持たない定義があるタグは、強さに何も足さない ([DR-0003](DR-0003-rule-strength-from-own-match.md)、DESIGN-ja「ルールの作成と強さの制約」)。そのことを `tag.definition_without_own_condition` で伝える (伝え方は S4)

#### 6. subject の強さと理由を返す公開の口を `Policy` に置く

- ルールの強さは subject の自身への条件 (`match` とタグ) の最強で、`ancestors` と `include_self` は数えない ([DR-0003](DR-0003-rule-strength-from-own-match.md))。この強さは項目 1 つの強さ (`Vocabulary::class`) からは分からないので、`own_class` を、subject (名前の参照を含む) と照合するプロセス (`Option`) を受けて強さと理由を返す公開の口にする。名前は実装で決める。出典: 柱 5、DR-0003
- 理由は、最強のクラスの条件 (同じクラスが複数なら全部) から集める。それより弱い条件の理由は subject の強さを決めていないので、subject の理由に入れない (項目ごとの理由は `Vocabulary::class` が返す)
- 自身への条件が無い時は `subject.no_own_condition` (弱)。`ancestors` か `include_self` がある時は `subject.ancestors_not_counted` を伝える (伝え方は S4)

#### 7. 制約の違反のエラーは、決めた強さを理由と組で持つ

- `BuildError::ScopeTooWeak`、`GrantError::ScopeTooWeak`、`LoadError::ScopeTooWeak` は、今 `class: Strength` で返している強さを、1 の組 (強さと理由) で返す。強さを返している口なので 1 がそのまま当たる。出典: 1。[DR-0009](DR-0009-strength-class-as-specificity.md) は variant の名前を決めていて、field の形は決めていない
- `Decision.too_weak` は今は強さを返していないので、1 は当たらない (理由を載せるかは S5)

#### 8. コードの変更と跡地

- コードは変えてよい。変える時は跡地を残す。出典: [issue](../issue/2026-11-17-strength-reason-codes.md)
- コードの状態は 3 つ
  - 現役: 判定が返す。廃止予定 (deprecated) の印と、後継のコードを持てる
  - 改名: 跡地が新しいコードを指す
  - 消えた: 跡地が、消えた版と、代わりに何を見ればよいかの説明を持つ
- 古いコードから、改名を辿って今のコードか「消えた」の説明に着ける。crate は現役の表と跡地の表を読むだけの形で公開し、古いコードを引く口を持つ。文書の側はこれで古い URL を今の文書に繋ぐ
- テストで保つ性質
  - 現役の表に同じコードが 2 度出ない
  - 跡地の表のコードは現役の表に無く、跡地同士でも重ならない
  - 改名の跡地を辿ると、輪にならずに現役のコードに着く
  - 判定の表の行をテストの入力 (照合するプロセスと値) にして、その行の強さとコードが返ることを確かめる。判定が返すコードは全部現役の表にあり、現役の表のコードはどれもいずれかの行で返る
  - 組み込みのコードは `app.` で始まらない
- 表をどこに持つかは S7

### 裁定待ちの分岐

推奨は 1 つずつ示すが、決定ではない。S3 と S5 は既存の DR が書いた型の形に触れるので、採る案によってその DR を改める。

#### S1: コードの形と名前

| 案 | 中身 | 良い面 | 悪い面 |
|---|---|---|---|
| a (推奨) | 文字列の newtype (`ReasonCode`)。組み込みのコードは定数 (`ReasonCode::NO_HARDENED_RUNTIME` のような関連定数) で、アプリの項目は自分のコードを同じ型で作る | コードの同一性が文字列そのもので、文書の URL の鍵・跡地の表・アプリのコードが同じ形で扱える。アプリのコードも同じ列に入る | アプリが `match` でコードを分けても、組み込みのコードが増えたことをコンパイラは教えない。綴りの誤りは定数を使えば防げるが、文字列を直に書くと防げない |
| b | 組み込みは `#[non_exhaustive]` の enum、アプリのコードは enum の variant `App(String)` | 組み込みのコードを型で列挙でき、綴りの誤りが起きない | crate はコードを足し続けるので `#[non_exhaustive]` が要り、網羅の検査は効かない。URL と跡地には結局文字列の名前が要り、variant と文字列の 2 つを対応させ続ける。改名すると variant の名前も変わり、アプリのコードが壊れる |
| c | `&'static str` をそのまま使う | 型が増えない | アプリが実行時に作るコードを持てない (`'static` に縛られる)。コードと他の文字列が型で区別されない |

名前の付け方 (a と b に共通の推奨):

- `.` で区切り、各段は snake_case (`Strength` と `Mark` の JSON の書き方と同じ)。先頭の段は判定の持ち主の名前にする。保護の状態は `protection.`、項目の判定は項目の key、値の形は `value.`、subject とタグの集め方は `subject.` と `tag.`
- 項目そのもののクラスの理由は key だけ (`cwd`)、項目が読む事実は key に続ける (`path.writable_by_user`)
- アプリの項目は key (`app.…`) に続ける (4)

推奨の理由: コードの役目は、crate の外の文書と画面がその事実を指す鍵で、同一性は文字列にある。b でも跡地と URL のために文字列の名前を持つので、enum は同じ識別子の 2 つ目の表現になる。持ち主の名前を先頭に置くと、判定の表の「判定の関数」の列とコードが対応し、アプリのコードは key で自然に分かれる。

#### S2: 判定の結果の型と、理由が複数ある時の持ち方

| 案 | 中身 | 良い面 | 悪い面 |
|---|---|---|---|
| a (推奨) | 理由の列だけを持つ型。理由は 1 つずつ「コードと、その事実が抑える強さの上限」の組。強さは列の上限の最小 (無ければ強) として型の method で出し、値としては持たない | 強さと理由が食い違えない (強さは理由から出る)。上限が項目で違う事実 (`protection.no_hardened_runtime`) も表せる。注意点を同じ列に載せられる (S4 の a) | 型が 2 つ増える (理由の組と、その列)。強さだけが欲しい呼び出し元も列を受け取る |
| b | 強さと、コードの列の組。上限は持たず、コードから表を引いて分かる | 型が 1 つで済む | 強さとコードを別々に作るので食い違いうる。上限が項目で違う事実は、コードから上限を引けない (コードを項目ごとに分けると、同じ事実に 3 つのコードができる) |
| c | 強さと、決め手になった理由 1 つ | 型が小さい | 1 つを直しても強さが上がらないことを伝えられない (2 の「全部返す」と衝突する)。組で下がる事実 (`process` の 3 つ) の内訳を出せない |

推奨の理由: 理由の事実と、その事実が抑える上限は、判定の表の 1 行 (4 つ 1 組) そのもの。強さを理由とは別の値として持つと、2 つの値を同時に正しく作る責務が全部の項目の実装に乗る。強さを理由から出せば、アプリの項目でも食い違いが起きない。型を置く crate は `Strength` と同じ procline-core (S6 の a で保護の状態の判定も core が返すため)。

#### S3: `Matcher::class` の戻り値を変えるか、別の method にするか

| 案 | 中身 | 良い面 | 悪い面 |
|---|---|---|---|
| a (推奨) | `Matcher::class` の戻り値を S2 の型にする (引数は今のまま)。`Vocabulary::class` も同じ型を返す | 強さと理由が 1 つの method で決まり、判定の表の行が実装の 1 か所に対応する。`Item::matcher_fn` で登録した項目はそのまま (3) | `Matcher` を実装したアプリの項目は戻り値を書き換える。**[DR-0006](DR-0006-structured-values-instead-of-depends.md)「登録の形」と [DR-0009](DR-0009-strength-class-as-specificity.md)「クラスの定義」の `class(...) -> Strength` と衝突する** ([DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md) の `Matcher::class` の記述も改める) |
| b | `class` はそのまま。`Matcher` に理由を返す method を足し、既定の実装は空の列 | アプリの項目はそのまま動く。既存の DR と衝突しない | 強さと理由を 2 つの method が別々に決めるので食い違いうる。既定の実装のままのアプリの項目は、弱でも理由が返らない (柱 5 が届かない)。`Matcher` の method が 1 つ増える |
| c | trait はそのまま。組み込みの項目の理由は、`Vocabulary` が項目の名前から決める | trait が変わらない | crate が組み込みの項目を名前で特別に扱う。判定 (項目の中) と理由 (`Vocabulary` の中) が別の場所に分かれ、4 つ 1 組が崩れる。値で強さが変わるアプリの項目は理由を返せない |

推奨の理由: 4 つ 1 組は「判定とその理由が同じ所で決まる」ことで、b と c はそれを 2 か所に分ける。アプリの項目にも柱 5 を届けるには、理由を返すことが項目の実装の一部になっている必要がある。

#### S4: 注意点 (強さを下げない事実) を同じ仕組みに載せるか

注意点の例: `cwd.snapshot` (収集した時点の値)、`protection.without_process` (上限で決めた)、`subject.ancestors_not_counted`、`tag.definition_without_own_condition`。env を項目に足す時 ([issue](../issue/2026-11-17-env-matcher-item.md)) の「伏せ字の値とは比べられない」も同じ種類。

| 案 | 中身 | 良い面 | 悪い面 |
|---|---|---|---|
| a (推奨) | 注意点も判定の表の行にし、S2 の a の理由の列に、上限が強の組で載せる | コードの表、跡地、テスト、返す口が 1 つで済む。上限が強なので強さの計算に効かない | 理由と注意点の区別が「上限が強か」の読み方に隠れる。強さを下げた理由だけを出したい画面は、上限で選り分ける |
| b | S2 の型に、注意点の列を別に持つ | 区別が型に出る | field が増える。どちらの列に置くかを項目の実装ごとに判断し、同じ事実が状況で入れ替わりうる (`protection.without_process` は強さを下げないが、強さが上限であることの説明でもある) |
| c | 載せない。注意点はアプリが項目ごとに知って出す | crate の型と表が小さい | 注意点の多くは crate の判定と収集の性質で、アプリが写して持つ (増やしたくないもの)。収集の側だけが知る事実 (伏せ字にしたか) を画面が知れない |

推奨の理由: 理由と注意点は、どちらも「この条件について知っておくべき事実」で、違いはそれが抑える強さの上限だけ。S2 の a の組はその違いを既に値で持っている。

#### S5: `Decision.too_weak` に理由を載せるか

| 案 | 中身 | 良い面 | 悪い面 |
|---|---|---|---|
| a (推奨) | 要素を、grant の id と、評価で決めた強さと理由の組にする | 採らなかった理由 (例: 保護のあるビルドで作った grant に、`disable-library-validation` を持つビルドが当たった) を、その評価の値として返す | Decision の型が変わる。**[DR-0008](DR-0008-evaluation-semantics.md) と [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md) の `Decision.too_weak: Vec<String>` と衝突する** ([DR-0012](DR-0012-strength-class-from-protection.md) の「id を載せる」は id が残るので変わらない) |
| b | id のまま。アプリは 6 の口に、その grant の subject と同じ chain を渡して聞き直す | 既存の DR と衝突しない。Decision は小さいまま | 同じ判定を 2 度行う。聞き直すまでに一覧の読み直しや grant の削除があると、評価の時と違う答えになる。照合するプロセスを渡し損ねると (`None`) 上限の答えが出る |
| c | trace の `strength` の項目 (`TraceEntry`) に理由を足す | 説明が trace にまとまる | `TraceEntry` は全項目に共通の形で、足す field は `strength` 以外の項目で常に空になる |

推奨の理由: `too_weak` は「その評価で、照合したプロセスで決め直した強さが足りなかった」という評価の結果で、理由はその結果の一部。評価の後で聞き直すと、同じ入力が揃っている保証が無い。

#### S6: 保護の状態の判定 (`Protection`) をどこで公開するか

| 案 | 中身 | 良い面 | 悪い面 |
|---|---|---|---|
| a (推奨) | procline-core に、収集した署名 (`Option<&CodeSigning>`) から保護の状態の理由の列 (S2 の型) を返す関数を置く。コードの対象と個体の 2 通りを返す。`protection.` のコードは core の表に入り、procline-acl の項目はこの関数を呼ぶ | 収集だけを使うアプリ (承認画面に表示する) も、ACL を持ち込まずに保護の状態と理由を出せる ([DR-0013](DR-0013-acl-layer-in-separate-crates.md) の層のまま)。判定は 1 か所 | OS に依らない core に、macOS の entitlement の名前と保護の規則が入る ([issue](../issue/2026-11-16-os-specific-identifiers-in-core-types.md) と同じ種類の問題。ただし `VerifiedSignature` の entitlements と `RuntimeState` は既に core にある)。コードの表が core と acl の 2 か所になり、重複のテストは両方を見られる procline-acl に置く。「コードの対象か個体か」(今の `Pins`) が core の言葉になる |
| b | procline-acl の `Protection` を公開する | 型を動かさない | 収集だけを使うアプリが保護の状態を出すには procline-acl に依存する (DR-0013 で分けた層を越える) |
| c | 公開しない。保護の状態は `binary` / `path` / `process` の条件の理由としてだけ返す | 公開の口が増えない | 条件を作らない画面 (収集だけの表示) は規則を写すことになる。[issue](../issue/2026-11-15-handoff-review-followups.md) の 2 が採る方向 (画面が保護なしを出す) に、収集だけのアプリは届かない |

推奨の理由: 保護の状態は、収集した署名だけから決まる事実で、条件の項目に依らない。信頼の印 (`CodeSigning::mark`) と同じく、収集した事実の上の判定として core に置くと、表示と照合が同じ判定を使う (柱 2)。

#### S7: コードの表と跡地の表をどこに持つか

| 案 | 中身 | 良い面 | 悪い面 |
|---|---|---|---|
| a (推奨) | Rust のソースの定数の表。判定はその定数を返し、跡地の表も同じ crate のソースに置く。公開の関数で両方を読める | 判定とコードがコンパイルで繋がる (表に無い定数を返せない)。生成の段が要らない | 表を文書から読む人は、ソースか、公開の関数で出した一覧を見る |
| b | データのファイル (TOML など) を正本にし、build で定数を作る | 文書の側がファイルをそのまま読める | build の段と依存が増える。判定の関数と表が別のファイルに分かれる |
| c | DESIGN の markdown の表を正本にし、テストで Rust の定数と突き合わせる | 文書を読む人が正本を見る | 正本が markdown と定数の 2 つになり、テストで同期を保つ |

推奨の理由: 4 つ 1 組のうち「判定の関数」と「コード」を同じソースに置けば、片方だけを変える変更がコンパイルかテストで止まる。表を置く crate は判定の持ち主に従い、S6 の a なら `protection.` が procline-core、他は procline-acl。

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 理由のコードの代わりに、理由の文 (`String`) を返す | 文書に繋げる鍵にならず、画面が文で分岐することになる。文の言語は別に扱う (「扱わないもの」) |
| 弱い条件を crate が拒む、または既定で拒む | 柱 5 (伝え、禁止しない) と柱 3 (制約の値はアプリが与える) に反する。拒むかはアプリの制約の表と画面が決める |
| 保護の状態のコードを項目ごとに分ける (`binary.no_hardened_runtime`、`process.no_hardened_runtime`) | 同じ事実に 3 つのコードができ、文書も 3 つに分かれる (2)。上限が項目で違うことは S2 の a の組が持つ |
| 理由に、列の何番目の要素か・どのタグの定義から来たかの位置を持たせる | 型が増える。要素ごとの強さと理由は、要素を 1 つずつ `Vocabulary::class` に渡せば得られる |
| 理由に深さ (pin した field の数、値の段階) を含める | 深さは UI の概念で、crate は算出も型も持たない ([DR-0006](DR-0006-structured-values-instead-of-depends.md)) |
| 理由のコードを rule や grant に書いて保存する | 強さは grant を作る時と評価の時に照合したプロセスで決め直す ([DR-0012](DR-0012-strength-class-from-protection.md))。保存した理由は、次の評価で古くなる |
| コードを一度決めたら変えない (跡地を持たない) | 判定は観測で変わる ([DR-0012](DR-0012-strength-class-from-protection.md) の未観測の点)。変えられないと、意味のずれた名前が残る。跡地があれば古い URL も今の文書に辿れる |
| 署名の検証の失敗の仕方ごとにコードを分ける (`protection.replaced`、`protection.unsigned` など) | 同じ区別を `CodeSigning` と信頼の印が既に持つ (2)。強さは、どの失敗でも同じ (開いている) |

## Consequences

- 画面は、`Vocabulary::class` (項目 1 つ) と 6 の口 (subject) から強さと理由のコードを得て、項目の横に出す。文言と、コードから文書への繋ぎはアプリと文書の側
- 強さの値と制約の検査の結果は変わらない。今のテストが確かめている強さはそのままで、戻り値の形が変わるので、強さを比べる assert は新しい型から強さを取り出して比べる (期待する強さは変えない)
- 保護の状態の判定は、当てはまる事実を全部見る (短絡しない)。結果の強さは今と同じ
- コードは公開の契約になる。変える時は跡地を残し、跡地の性質はテストで保つ
- S3 の a なら、`Matcher` を実装したアプリの項目は戻り値を書き換える。`Item::matcher_fn` で登録した項目は変わらない
- 採られた時に直す所:
  - コード: procline-core の `strength.rs` (理由の型とコード)。S6 の a なら保護の状態の判定 (`signature.rs` の隣)。procline-acl の `vocabulary.rs` (`Matcher::class`、`Vocabulary::class`、`value_class`、`ConstClassMatcher`)、`matchers.rs` (各項目の `class`、`Protection` の短絡と通らない分岐)、`policy.rs` (`own_class` の公開の口、`GrantError` と `LoadError` の `ScopeTooWeak`、S5 の a なら `Decision.too_weak`)、`builder.rs` (`BuildError::ScopeTooWeak`)。テスト: procline-acl の `tests/`、procline-acl-macos の `tests/protection_class.rs`、判定の表を入力にするテストと、表と跡地の性質のテスト
  - DESIGN-ja / DESIGN: 柱 5 から判定の表への参照。「強さ: クラスと深さ」(理由とコード、`path` の所有者と書き込み可否が取れない時の中)、「項目の登録」(`Matcher::class` の戻り値)、「ルールの作成と強さの制約」(subject の口、`ScopeTooWeak` の理由)、「評価」(S5)、「API の骨格」
  - DR: S3 の a なら [DR-0006](DR-0006-structured-values-instead-of-depends.md)・[DR-0009](DR-0009-strength-class-as-specificity.md)・[DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md) の `Matcher::class` の記述。S5 の a なら [DR-0008](DR-0008-evaluation-semantics.md)・[DR-0004](DR-0004-rule-grant-split-and-condition-advance.md) の `Decision.too_weak`
  - issue: [handoff-review-followups](../issue/2026-11-15-handoff-review-followups.md) の 2 は S6 で決まる。[strength-reason-codes](../issue/2026-11-17-strength-reason-codes.md) の受け入れ条件。[env-matcher-item](../issue/2026-11-17-env-matcher-item.md) は、env の項目を足す時に、伏せ字の注意点を判定の表の行として足す
- 未決:
  - 型・関数・定数の名前は実装の時に決める
  - 理由の文と、その多言語のリソース

## 関連

- [DESIGN-ja の「設計の柱」「強さ: クラスと深さ」「項目の登録」「ルールの作成と強さの制約」「評価」「アプリが足す語彙」](../DESIGN-ja.md)
- [DR-0003](DR-0003-rule-strength-from-own-match.md): ルールの強さは自身への条件の最強で、`ancestors` を数えない
- [DR-0006](DR-0006-structured-values-instead-of-depends.md): 項目の登録、`Matcher::class`、名前空間、深さ
- [DR-0009](DR-0009-strength-class-as-specificity.md): クラスの定義と、制約の表はアプリが与えること
- [DR-0010](DR-0010-or-in-values-and-tag-definitions.md): 値の列とタグの複数の定義は最弱
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md): 検証した署名と信頼の印
- [DR-0012](DR-0012-strength-class-from-protection.md): 保護の状態とクラス、評価での確かめ直し
- [DR-0013](DR-0013-acl-layer-in-separate-crates.md): crate の層
- [DR-0008](DR-0008-evaluation-semantics.md)・[DR-0004](DR-0004-rule-grant-split-and-condition-advance.md): `Decision.too_weak`
- issue: [strength-reason-codes](../issue/2026-11-17-strength-reason-codes.md)、[handoff-review-followups](../issue/2026-11-15-handoff-review-followups.md)、[env-matcher-item](../issue/2026-11-17-env-matcher-item.md)、[os-specific-identifiers-in-core-types](../issue/2026-11-16-os-specific-identifiers-in-core-types.md)
