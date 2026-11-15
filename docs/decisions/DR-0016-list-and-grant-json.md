# DR-0016: 一覧と grant の JSON の読み書き (形、値の読み方、検査、書き出し、エラー) を定める

- Status: Proposed
- Date: 2026-11-15

## Context

一覧 (subject、tag、rule) と grant は JSON で保存し、アプリが署名する (DESIGN-ja「保存」)。読み込みの入口 `Policy::load_verified` と `Policy::load_grant` は `todo!()` で、書き出す手段は無い。実装の前に文書とコードを仕分けた結果が [findings](../findings/2026-11-15-load-entry-recon.md) にあり、この DR はその (ii) の 1〜4・6・7 と (iii) の 1〜4 を扱う。findings が「決まっている」とした形 (subject / tag / rule / grant の field、値の書き方、署名の検証の順) はそのまま前提にし、ここには写さない。

決めないと書けない点の要約 (詳細は findings の 1・2・4・5・6・8):

- 一覧全体の入れ物と、名前付きの subject の JSON の形が文書に無い
- JSON の値をどの `MatchValue` に読むかが key で変わる (`process` と `responsible` の `true` は `Process(Pin)`、他は `Pin`) のに、振り分けを持つ所が決まっていない。builder は `PROCESS_ITEMS` に組み込みの名前を固定で持つ (`crates/procline-acl/src/builder.rs`)
- 未知の field を検出できるのは JSON を型に変える段だけ (`Matcher::validate` が受け取る `MatchValue` は未知の field を持てない)
- `Grant` と一覧を JSON に書き出す手段、読み込んだ rule を取り出す口が無い
- grant の condition は rule と同じ検査 (`validate_args`) では検査できない (`age` から直した `until` は引数を持たない)
- 自動で grant にする基準 ([DR-0008](DR-0008-evaluation-semantics.md)) の「pin に chain や観測値を要する condition」を、`Condition` trait から見分けられない
- 読み込みと builder で検査を共有する形、エラーが場所を持つかが決まっていない

コードを開いて、または実行して確かめたこと (findings が推論とした点を含む):

- `StartTime` は `deny_unknown_fields` を持たず、`ProcessIdentity` は持つ (`crates/procline-core/src/process.rs`)。`StartTime` が未知の field を読み飛ばすことは、JSON を読ませて確認した
- `serde_json::Value` や通常の map に読むと、重複したキーは後のものが残り、読んだ後では重複があったことが分からない (`{"x":1,"x":2}` が `x=2` になることを実行して確認した)
- `Option<serde_json::Value>` を derive の既定で読み書きすると、`Some(Null)` は `null` と書かれ、読むと `None` になる (serde_json 1.0.154 で実行して確認した)。`ConditionUse.args`、`PinnedCondition.args`、`PinnedCondition.pinned` がこの型
- procline-acl の依存に `serde` は無いが、procline-core が `serde` に依存するので、procline-acl に足してもビルドに入る crate は増えない
- `Pinnable` と `BinaryPin` に serde の実装は無い。doc は JSON の形 (`true` が `Pin`、未知の field は拒む) を書いている
- `Policy` には rule・subject・tag を変える入口も読む入口も無い。一覧を変えるには、新しい一覧を `load_verified` で読み直す

- 目的:
  - アプリが保存した一覧と grant が、読み直した時に、書いた時と同じ意味で評価に戻る
  - 一覧に書かれたものが、黙って捨てられたり別の意味に読まれたりせず、不正ならどこが不正かの分かるエラーになる
  - JSON から読んだ rule と grant が、builder と `Policy::grant` で作ったものと同じ検査を通っている
- 増やしたくないもの:
  - JSON の形の知識を持つ場所 (読む側と書く側、crate とアプリに分かれて持つこと)
  - `Matcher` / `Condition` の method と、アプリの項目が実装する義務
  - crate のコードが組み込みの項目を名前で特別に扱う箇所 (`PROCESS_ITEMS`、`age` / `until` / `uses` の名指し)
  - 同じ検査の実装の重複と、公開のエラーの型
  - 入口の引数と、crate が持つ方針 (何を許すか、新しさ、保存の仕方)

扱わないもの (誰の責務か):

| 扱わないもの | 責務 |
|---|---|
| 署名の形式、鍵、保存先、書き込みの原子性 | アプリ (DESIGN-ja「脅威モデルの前提」「保存」) |
| 保存したものの新しさ (差し戻しの検出) | アプリ。`PolicyVerifier` の実装で行う (Decision の「差し戻し」) |
| 一覧から消えた rule を指す grant、終わったプロセスを指す grant の削除 | アプリの掃除 ([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md)) |
| 項目の引数と pin 値 (`serde_json::Value`) の中身の形 | 項目の実装 ([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md)、[DR-0006](DR-0006-structured-values-instead-of-depends.md))。重複したキーだけは JSON の層の話で、crate が拒む (Decision の 5) |
| subject 1 つだけを署名なしで読む入口 (CLI の `match`) | CLI の設計 ([issue](../issue/2026-11-15-procline-cli.md))。一覧に包めば今の入口で読める |
| 収集の結果の JSON | [DR-0014](DR-0014-chain-trust-boundary-and-caller-supplied-values.md) (書き出しだけで、読み戻さない) |

## Decision

「どの選択肢でも変わらない部分」は既存の決定から導いたもので、項目ごとに出典を書く。既存の決定から決まらない点は「裁定待ちの分岐」(J1〜J7) に置く。

### どの選択肢でも変わらない部分

#### 1. JSON の形を持つ場所と、読み書きの入口

- JSON の形は crate が持ち、読む側と書く側の両方を crate が出す。アプリは形を知らずに、バイト列を署名して保存する
  - 出典: DESIGN-ja「保存」(「crate は `Grant` の JSON の形と、次の入口を持ちます」「保存と署名はアプリの責務」)。アプリが署名するのは書き出したバイト列で、形を知るのが crate だけなら、書き出しも crate に要る
- 読む入口は今の 2 つ (`Policy::load_verified`、`Policy::load_grant`) で、引数は変えない
- 書き出しは 2 つ: grant 1 件をバイト列にするものと、一覧 (subject の列、tag の列、rule の列) をバイト列にするもの。一覧を表す型は足さず、3 つの列を受け取る
- 書き出したバイト列を、同じ語彙・一覧・制約で読むと、書き出す前と同じ値になる (rule、tag、subject、grant のどれも)。テストで保つ
  - 「同じ値」は列の順序を含む。subject の列、tag の列、rule の列、`conditions`、`targets`、`ancestors` は、書き出した順で読む
  - 引数と pin 値の「無い」と「JSON の null」の区別も含む (下の 2 と 3)
- 読み込んだ一覧を取り出す口を `Policy` に置く (rule、名前付きの subject、tag の定義を読むアクセサ)
  - 出典: DESIGN-ja「grant」(承認画面に rule の一覧を出し、選んで grant にする) と [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md) (保存した rule も `Policy::grant` に渡す)。今は `Policy` から `&Rule` を得られない
- 一覧を変える流れ: アプリが、取り出した列に rule (`RuleBuilder::build` の結果) などを足して書き出し、署名して保存し、`load_verified` で読み直す。その後に保存した grant を `load_grant` で検査し直す (DESIGN-ja「保存」)。`Policy` に rule を足す入口は持たない

#### 2. 一覧の JSON

一覧全体の入れ物の形と、名前付きの subject の形は、既存の文書からは決まらない (J1)。J1 のどの案でも変わらないのは次のこと。

- tag の定義は `{"tag": 名前, "subject": …}`、rule は `id` を中に持つオブジェクト (DESIGN-ja「tag」「rule」)。同じ名前の tag の定義は複数置ける ([DR-0010](DR-0010-or-in-values-and-tag-definitions.md))
- 形式の版の field は持たない。未知のキーをエラーにする (下の 6) ので、形の違う一覧を黙って読むことは無い
- 省いた field は、builder で指定しなかった時と同じ値になる

  | 場所 | 必須 | 省ける (省いた時の値) |
  |---|---|---|
  | subject | なし (ただし全部が空の subject は不正。下の 6) | `match` (空)、`tags` (空)、`ancestors` (空)、`include_self` (`false`) |
  | `ancestors` の要素 | なし (同上) | `match`、`tags` |
  | tag | `tag`、`subject` | なし |
  | rule | `id`、`effect`、`subject` | `targets` (空 = 全対象。DESIGN-ja「rule」)、`conditions` (空) |

- `conditions` の要素は、文字列 (引数なし) か、キーが 1 つだけのオブジェクト (キーが項目の名前、値が引数)。キーが 0 個か 2 個以上のオブジェクトは不正 (DESIGN-ja「名前と参照」の形。1 要素が 1 つの条件)
  - 引数が無い (`ConditionUse.args` が `None`) なら文字列で書き、引数があるならオブジェクトで書く。引数が JSON の null (`Some(Null)`) の時は `{"名前": null}` と書き、読む時も引数ありとして読む。アプリの項目は null を引数に使えるので、文字列の形 (引数なし) と読み分ける

#### 3. grant の JSON と時刻

- 形は [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md)「grant の形」のとおり。`id`、`rule_id`、`effect`、`subject`、`targets`、`conditions`、`created_at` は必須で、`created_from` は省ける。`conditions` の要素は `key` が必須、`args` と `pinned` は省ける
- `args` と `pinned` は、キーが無いこと (`None`) と、キーがあって値が null であること (`Some(Null)`) を読み分ける。書き出しは、`None` ならキーを書かず、`Some(Null)` なら `null` を書く。アプリの項目は JSON の null を引数や pin 値として使えるので、読み書きで「無い」に変えない。型に制限は足さない
- `created_at` は RFC 3339 の文字列。書き出しは UTC で、秒未満は値が持つ分だけ付け、丸めない。読む時は時刻帯の付いた RFC 3339 を受ける。`until` の pin 値と同じ書き方 (`crates/procline-acl/src/conditions.rs`) で、時刻の書き方を 1 つにする
  - 精度を落とさない理由: 読み直した grant の `UntilWithin` は `created_at` を基準に判定する (DESIGN-ja「ルールの作成と強さの制約」)。`created_at` を丸めると、作った時に制約ちょうどだった `until` が、読み直しで制約を超える。採用の順 (作成の古い順、[DR-0008](DR-0008-evaluation-semantics.md)) も変わりうる
- `created_from` は、grant が作られた経路を表すアプリの語彙の文字列。crate は意味を解釈せず、`Policy::grant` は付けない (空で返す)。読み込みと書き出しは、文字列としてそのまま運ぶ。アプリが、返った grant に書いてから署名する
  - 出典: [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md) の形 (例の値は `approval-ui`) と、経路の語彙はアプリのものであること
- `rule_id` の rule が一覧に無い grant も受け付ける。grant は自己完結で、`rule_id` は表示と掃除のためのもの ([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md))

#### 4. 値の読み方

- JSON の値の形と `MatchValue` の対応は、項目によらず 1 つ (DESIGN-ja「matcher」の表は、形と JSON の対応を 1 つの表で持ち、項目は使える形を選ぶ)。どの形を受けるかと、その値の規則は項目が持つ (`Matcher::validate`、[DR-0006](DR-0006-structured-values-instead-of-depends.md))。配列を要素に分けるのは語彙 ([DR-0010](DR-0010-or-in-values-and-tag-definitions.md))
- オブジェクトは、キーの集合で形が決まる。形ごとのキーは重ならない

  | JSON | 形 |
  |---|---|
  | 文字列 | 完全一致 (文字列) |
  | 整数 (`i64` に収まるもの) | 完全一致 (数値) |
  | `{"glob"}` | glob |
  | `{"regex"}` | 正規表現 |
  | `{"min", "max"}` (両方必須) | 数値の範囲 |
  | `{boot_uuid, unique_id?, pid, start_time?}` | プロセスの個体 (`process`、`responsible`) |
  | `{digest?, team_id?, signing_id?, bundle_id?, cdhash?}` | コードの同一性 (`binary`) |
  | 配列 | 値の列 |
  | `true` | placeholder (どの `MatchValue` にするかは J2) |

- 上のどれにも当たらない値は、読み取りの段でエラー: 小数、`i64` に収まらない数、`false`、`null`、キーがどの形にも入らないか 2 つの形にまたがるオブジェクト、空のオブジェクト
  - 出典: `Literal` は整数と文字列だけで、真偽値の完全一致は無い (DESIGN-ja「matcher」、[DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md))。小数を丸めると、書かれた値と別の値に一致する
- `responsible` の値の形は `process` と同じ (実装は同じ検査を使う。DESIGN に書き足す)
- アプリの項目が書ける値は、上の表の形に限る。独自の構造を持つ値は書けない (`MatchValue` は閉じた集合)。形を足す時は、キーが既存の形と重ならないものにする
- `subject` の位置 (rule と tag) は、文字列なら名前、オブジェクトならその場の定義 (DESIGN-ja「名前と参照」、`SubjectRef`)

#### 5. serde の置き場

- procline-core の `Pinnable<T>` と `BinaryPin` に `Serialize` と `Deserialize` を置く。`BinaryPin` は未知の field を拒む
  - 出典: [DR-0014](DR-0014-chain-trust-boundary-and-caller-supplied-values.md)「rule と grant の値や設定として外から書く型は `Deserialize` を持つ」。同じ分類の `ProcessIdentity`、`StartTime`、`CdHash`、`SessionLevel` は core にあり、core は JSON の形を持つ crate (DESIGN-ja「構成」)。2 つの型の doc も JSON の形を書いている
- `StartTime` は未知の field を拒む ([DR-0006](DR-0006-structured-values-instead-of-depends.md)「未知の field がある値は不正。`process` の値も同じ」。`start_time` は `process` の値の一部)
- 重複したキーは、バイト列を JSON として読む最初の段で、全部の階層について拒む。`serde_json::Value` や通常の map に読んだ後では後のキーだけが残って検出できないので、重複を拒む読み方を crate が持ち、`serde_json::Value` にする前に通す
  - 項目に `serde_json::Value` のまま渡す引数と pin 値の中も、同じ段を通るので同じく拒む。重複は JSON の層の話で、項目の値の形の知識は要らない
- 未知の field、型の違い、必須の field の欠けを検出するのは、JSON を型に変える読み取りの段 (crate)。項目の実装は、型になった値の規則を検査する
  - 出典: [DR-0006](DR-0006-structured-values-instead-of-depends.md) の「誰が何をする」の表は、未知の field をエラーにする主体を読み込みとしている
- procline-acl の型の JSON との行き来は procline-acl が持つ。依存に `serde` を足してよい。derive で書くか手で書くかは実装に任せる (公開の `Deserialize` を持つかは J3)

#### 6. 一覧の読み込みの検査

順序は、署名の検証 (`SignedKind::List`) → 読み取り → 検査。1 つでも不正ならエラーを返し、`Policy` を作らない (不正な要素を飛ばして残りを読むことはしない)。

| 検査 | 出典 |
|---|---|
| 一覧・subject・tag・rule・値の中の未知のキーはエラー。重複したキーは、項目の引数の中を含むどの階層でもエラー (上の 5) | DESIGN-ja「アプリが足す語彙」(「黙って無視すると、そこから作る grant が意図より長く効く」) と同じ理由。`targets` や `conditions` の誤記を読み飛ばすと、条件が落ちて rule が広がる |
| subject の名前の重複、rule の `id` の重複はエラー。tag の名前の重複は正常 | 名前が指すものが 1 つに決まること (DESIGN-ja「名前と参照」)、grant が `rule_id` で rule を指すこと ([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md))、タグの複数定義 ([DR-0010](DR-0010-or-in-values-and-tag-definitions.md)) |
| 条件が 1 つも無い subject と `ancestors` の要素はエラー | DESIGN-ja「ルールの作成と強さの制約」は、空を builder が検査する値の妥当性に数える。読み込みは同じ値の妥当性を検査する |
| `targets` の glob が不正ならエラー | builder と同じ検査。評価では不正な glob は何にも当たらないので、`deny` が黙って効かなくなる |
| 未登録の項目、値の妥当性、placeholder の場所、参照先の無い名前、タグの循環、`allow` の制約 (上限のクラス) | findings の 5 の「決まっている」のとおり |

- 同じ項目の condition を 1 つの rule に 2 回書くことは検査しない (どちらも AND で効く)

#### 7. grant の読み込みの検査

順序は、署名の検証 (`SignedKind::Grant`) → 読み取り → 検査。

- subject: inline だけ (文字列の名前は不正)。placeholder が残っていれば不正。項目の登録、値の妥当性、タグ名が一覧にあることは一覧と同じ ([DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md)、[DR-0008](DR-0008-evaluation-semantics.md))
- `targets` の glob、未知のキー、重複したキー (引数と pin 値の中を含む) は一覧と同じ
- conditions: `key` が語彙にあること。`age` の key を持つ grant は不正 (`age` は grant を作る時に `until` に直る。[DR-0004](DR-0004-rule-grant-split-and-condition-advance.md))。引数と pin 値の検査は J4
- `allow` の制約: クラスは上限で、`UntilWithin` の基準時刻は `created_at` (DESIGN-ja「ルールの作成と強さの制約」)
- 読み込んだ grant の `id` が `Policy` の中の grant と重なっても、`load_grant` はエラーにしない。`add_grant` は同じ `id` を置き換える ([DR-0008](DR-0008-evaluation-semantics.md))。同じ `id` の保存物のどれが新しいかは保存先の話で、アプリの責務

#### 8. 自動で作る grant

基準は [DR-0008](DR-0008-evaluation-semantics.md)「自動 grant 化の基準」のまま。

- `load_verified` が作り、返す `Policy` に入れる。永続化しない。一覧を読み直すたびに、その一覧から作り直す
  - 出典: grant を 1 件ずつ永続化する目的は、意図しない終了で grant と変わる値 (`uses` の残り) を失わないこと ([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md))。自動の grant は一覧だけから決まり、基準により変わる値を持たないので、失うものが無い。元になる一覧は署名して保存したもので、効き始める前に保存されている ([DR-0008](DR-0008-evaluation-semantics.md)「永続化と有効化の順」の趣旨)
  - 別に永続化すると、一覧から消した `deny` が保存した grant として残り、手書きの `deny` が保存を待たないと効かない (自動にする理由「『許可する』操作なしに効かせる」に反する)
- 中身は rule の写し: `effect`、`targets`、名前を展開した subject、`rule_id`。conditions は `key` と `args` を写す。`created_from` は空。読み込みの時には chain も観測値も無いので、`Condition::pin` を今の形のまま呼ぶことはできない (pin 値の扱いは J5)
- `Policy::grants()` に並び、`Decision.grant_id` と trace に `id` が出る。アプリが `remove_grant` で除いたものは、一覧を読み直すまで戻らない
- 一覧から rule を消して読み直せば、その grant も無くなる
- 基準の「pin に chain や観測値を要する condition」を語彙からどう知るかは J5、`id` と `created_at` は J6

#### 9. 差し戻し

- 入口は版を受け取らず、一覧と grant の JSON は版や世代の field を持たない
- 保存したものの新しさは、アプリが `PolicyVerifier::verify` の中 (または入口を呼ぶ前) で確かめる。`verify` は用途・バイト列・署名を受け取り、署名の形式はアプリが決めるので、アプリは世代を署名の対象や包みに入れて、自分が守る最新の値と比べられる
  - 出典: DESIGN-ja「脅威モデルの前提」(保存先と署名鍵の保護はアプリの責務) と「保存」(署名の形式・保存先はアプリが決める)。新しさの判定に要るのは「最新の値を、差し戻されない所に持つ」ことで、保存先の保護そのもの。crate が版を受け取っても、比べる相手の値を出すのはアプリで、crate が足せるのは数の比較だけ
- 差し戻した一覧に対して grant の検査し直しが行われる点 ([issue](../issue/2026-11-15-grant-and-list-rollback.md)) は、一覧の新しさをアプリが確かめることで扱う

#### 10. エラー

- 公開のエラーの型は分けたまま (`BuildError`、`LoadError`、`GrantError`)。検査の実装は 1 つを共有し、結果をそれぞれの型に写す
  - 出典: [DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md)・[DR-0008](DR-0008-evaluation-semantics.md)・[DR-0009](DR-0009-strength-class-as-specificity.md) が variant を型ごとに名指しする (`LoadError::InvalidValue`、`BuildError::ScopeTooWeak` / `LoadError::ScopeTooWeak` / `GrantError::ScopeTooWeak` など)。「同じ検査をする」は DESIGN-ja「ルールの作成と強さの制約」
- 読み取りの段の失敗は `LoadError::Parse`。バイト列を JSON として読む段 (JSON の構文、どの階層でも重複したキー) と、JSON を型に変える段 (未知のキー、型の違い、必須の field の欠け、4 の「どれにも当たらない値」) の両方。`serde_json::Error` が行と桁を持つ
- 検査の段 (語彙・一覧・制約との照合) の失敗は今の variant。足すのは 2 つ: 名前の重複 (rule の `id`。J1 の b と c では subject の名前も) と、空 (`BuildError::Empty` と同じ名前)
- `LoadError::InvalidValue` は、項目の規則に反する値と、placeholder を書けない場所の `true`。placeholder を含む rule は自動で grant にならないだけで、エラーではない ([DR-0008](DR-0008-evaluation-semantics.md))
- `load_grant` の `ScopeTooWeak` の `rule_id` には、grant の `rule_id` を入れる。`load_grant` は 1 件ずつ読むので、どの grant かは呼び出し側が知っている
- 返すのは最初に見つけた 1 つ

### 裁定待ちの分岐

推奨は 1 つずつ示すが、決定ではない。J2・J4・J5 は既存の DR が書いた型や trait の形に触れるので、採る案によってその DR を改める。

#### J1: 一覧の入れ物と、名前付きの subject の形

一覧全体をどんな入れ物にするかと、名前付きの subject をどう書くかは、既存の文書に無い。DESIGN-ja「名前と参照」は、参照が現れる場所ごとに名前の種類が 1 つに決まるという規則で、保存の入れ物の形を決めるものではない。

| 案 | 形 | 意味と帰結 |
|---|---|---|
| a | 種類ごとのキー `subjects` / `tags` / `rules` を持つオブジェクト。`tags` と `rules` は配列で、`subjects` は名前をキーにしたオブジェクト (`{"名前": { subject }}`) | 要素の種類は置かれた場所で決まる。subject の名前が JSON のキーになり、同じ名前を 2 回書くと JSON の重複したキーとして読み取りの段のエラーになる。`Policy` が持つ subject の並び (名前と subject の組の列) の順序を保ちにくい (通常の map はキーの順になる) ので、書いて読むと同じ順になることを別に保証する必要がある |
| b (推奨) | 種類ごとのキーを持つオブジェクトで、3 つとも配列。subject は `{"name": "名前", "subject": { subject }}` | 要素の種類は置かれた場所で決まる。3 つの種類がどれも「オブジェクトの配列」で、tag の定義 (`{"tag": 名前, "subject": …}`) と同じ形に揃う。順序は配列の順。同じ名前の重複は、読んだ後の検査のエラーになる |
| c | 要素の配列 1 本で、各要素が `tag` / `rule` / `subject` のどのキーを持つかで種類を示す | tag の今の形と揃い、種類をまたいで書いた順に並べられる。種類の判定が要素ごとに要り、キーを 2 つ持つ要素やどれも持たない要素の扱いを決める必要がある |

b の例:

```json
{
  "subjects": [ { "name": "…", "subject": { … } } ],
  "tags": [ { "tag": "terminal-app", "subject": { … } } ],
  "rules": [ { "id": "…", "effect": "allow", "subject": { … }, "targets": [ … ], "conditions": [ … ] } ]
}
```

- 推奨の理由 (提案の理由で、既存の決定からの導出ではない): 要素が何であるかを置き場所だけで決められ、要素ごとの種類の判定が要らない。3 つの種類の読み方が 1 つで済み、列の順序と名前の重複を、JSON の構文の扱いに頼らずに値として扱える
- a と b では、種類ごとのキーは省ける (省いた時は空)

#### J2: placeholder (`true`) をどの `MatchValue` にするか

今の型は、`process` と `responsible` の placeholder だけが `MatchValue::Process(Pinnable::Pin)` で、他の項目は `MatchValue::Pin` ([DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md)「型の形」)。JSON はどちらも `true` なので、読む時に key を見ないと決まらない。builder も同じ理由で `PROCESS_ITEMS` を持つ。

| 案 | 中身 | 意味と帰結 |
|---|---|---|
| a (推奨) | 値全体の placeholder を `MatchValue::Pin` 1 つにし、`MatchValue::Process` は具体値だけを持つ (`Process(ProcessIdentity)`)。`process` / `responsible` の項目は `Pin` を自分の placeholder として受ける | JSON の値は、key を見ずに形だけで `MatchValue` に決まる。builder の `PROCESS_ITEMS` が要らなくなる。trait は変わらない。**[DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md)「型の形」の `MatchValue::Process(Pinnable<ProcessIdentity>)` と衝突する** (JSON の形と意味は変わらない) |
| b | 型はそのまま。読み取りの段が、key が `process` か `responsible` の時だけ `true` を `Process(Pin)` にする | 既存の DR と衝突しない。crate が組み込みの項目を名前で特別に扱う箇所が、builder に加えて読み取りにも要る (1 か所にまとめても名指しは残る)。アプリの項目は、個体の placeholder を持てない |
| c | 型はそのまま。`Matcher` に「この項目の placeholder の値」を返す method を足し、読み取りと builder がそれを使う | 名指しは無くなる。trait の method が 1 つ増え、アプリの項目にも実装が要る。builder は語彙を持たない作り (`RuleBuilder::build` まで語彙と照合しない) なので、placeholder の形を決める時機を builder の後ろに移す必要がある |

- 推奨の理由: 「値全体を承認の時の実値で埋める」という同じ意味に、型の上で 2 つの書き方があることが、key を見る振り分けと名指しの元になっている。意味が 1 つなら値も 1 つにすると、読み取り・builder・項目のどこにも特別な扱いが残らない。何を埋めるかは今も項目の `resolve` が決めている

#### J3: procline-acl の型が公開の `Deserialize` を持つか

| 案 | 中身 | 意味と帰結 |
|---|---|---|
| a | `Subject`、`Rule`、`Tag`、`Grant` などに公開の `Serialize` と `Deserialize` を置く | 型そのものが JSON の形を表す。アプリは、署名の検証も検査も通さずに、受け取ったバイト列を `Grant` や `Rule` として読める。検査を通すこと (`load_verified` / `load_grant` を使うこと) はアプリの責務になる |
| b (推奨) | 公開するのは `Serialize` だけ。JSON から読むのは `load_verified` と `load_grant` の中だけ | JSON のバイト列が rule や grant の値になる経路は、署名の検証と検査を通る入口に限られる。アプリのコードが field を書いて値を組むこと (`Policy::from_parts`、公開の field) は今のまま止めない。署名を使わないアプリは、常に真を返す `PolicyVerifier` を渡す |

- 推奨の理由: [DR-0014](DR-0014-chain-trust-boundary-and-caller-supplied-values.md) が収集の型で引いた線 (止めるのは、受け取ったバイト列を読み込むだけで評価に渡せる値になること。アプリのコードが組むことは止めない) を、`add_grant` にそのまま渡せる `Grant` にも同じに引く。`Serialize` は表示・ログ・他のプロセスへの受け渡しのために持つ (同じ DR の `ProcessChain` と同じ)
- [DR-0014](DR-0014-chain-trust-boundary-and-caller-supplied-values.md) が `Deserialize` を持つとした「rule と grant の値」(`ProcessIdentity` など) は、単独では評価に渡らない値で、どちらの案でも `Deserialize` を持つ

#### J4: grant の condition (引数と pin 値) の検査

rule の引数の検査 (`Condition::validate_args`) は grant には使えない。`age` から直した `until` は引数を持たず、`validate_args` はそれを不正とする。pin 値を検査する method は無い (findings の 5)。

| 案 | 中身 | 意味と帰結 |
|---|---|---|
| a | 検査しない。`load_grant` が condition について見るのは、`key` の登録と制約まで | trait は変わらない。pin 値を読めない grant は、評価で `check` が偽になる (寿命型は失効が確定し、状態型は当たらないまま残る)。項目の実装が変わって pin 値を読めなくなると、その condition を持つ `deny` の grant も評価で失効して消える。`age` の key の検査は crate が名前で行う |
| b (推奨) | `Condition` に、grant の中の引数と pin 値の組を検査する method を足し、`load_grant` が呼ぶ。不正なら `LoadError::InvalidValue` | 読めない pin 値の grant を、読み込みの時にエラーとしてアプリが知る。grant には `validate_args` を呼ばないので、`until` の引数の問題と `age` の名指しが無くなる (`age` の実装が「grant には現れない」と答える)。trait の method が 1 つ増え、アプリの項目にも実装が要る。[DR-0004](DR-0004-rule-grant-split-and-condition-advance.md) の trait の列挙に足す |

- 推奨の理由: `load_grant` は値の妥当性を検査し ([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md)、DESIGN-ja「保存」)、値の妥当性は項目が持つ ([DR-0006](DR-0006-structured-values-instead-of-depends.md))。pin 値は項目だけが読める値なので、両方を満たすには項目に聞く口が要る。subject の値は読み込みで項目が検査するのに、condition の値だけ検査しない形 (a) は、同じ grant の中で扱いが分かれる
- a を採る理由になるもの: 署名された grant の中身は、署名鍵を守るアプリが書いたもの。読めない pin 値は攻撃ではなく、版の食い違いか実装の誤りで、評価は安全側 (`allow` は通らない) に倒れる

#### J5: grant に pin 値を持つ condition を語彙から知る方法

自動 grant 化の基準 ([DR-0008](DR-0008-evaluation-semantics.md)) と、採用の順 (同 DR の「advance で変わらない grant を優先」) は、どちらも condition の pin 値の性質で決まる。`Condition` trait が返すのは `kind()` (寿命型 / 状態型) だけで、どちらも見分けられない。採用の順は今、`uses` の名前で近似している ([issue](../issue/2026-11-09-consumable-condition-marker.md))。

| 案 | 中身 | 意味と帰結 |
|---|---|---|
| a (推奨) | `Condition` に、grant での pin 値の性質を返す method を 1 つ足す。値は 3 つ: pin 値を持たない / 持つが採用で変わらない / 採用のたびに変わる | 自動の対象は「placeholder が無く、寿命型の condition が無く、どの condition も pin 値を持たない rule」になり、`Condition::pin` を呼ばずに写せる。採用の順も同じ値で決まり、`uses` の名指しが要らなくなる (issue の 1 つ目の受け入れ条件が同時に決まる)。trait の method と、3 値の型が 1 つずつ増える |
| b | 2 値 (pin 値を持つか) を返す method を足す | 自動の対象は a と同じ。採用の順は `uses` の名指しのままで、issue は残る |
| c | trait を変えず、自動の対象を「condition を 1 つも持たない rule」に狭める | trait は変わらない。**[DR-0008](DR-0008-evaluation-semantics.md) の基準と衝突する**: 状態型の condition だけを持つ手書きの `deny` (時間帯だけの拒否など) が、承認を経ないと効かなくなる |

- 推奨の理由: 見分けたい 2 つは「この condition が grant にどんな pin 値を持つか」という 1 つの性質から決まる。1 つの method で、読み込みと評価の両方から組み込みの名前の名指しが消える。b は同じ trait を 2 回に分けて変えることになる
- a の制約: 「採用のたびに変わる」は項目ごとに決まった分類で、pin 値を見ない。`Condition::advance` の結果が pin 値によって変わる項目 (ある値では変わり、ある値では変わらない) では、採用の順に対して近似になる。pin 値を受け取って答える形の method にすれば grant ごとに正確になるが、評価のたびに、採用しない grant についても項目を呼ぶことになり、自動の対象の判定 (読み込みの時で、pin 値がまだ無い) には使えない
- a と b に共通の帰結: 引数だけから pin 値を作る状態型の condition (組み込みには無い) は、自動の対象から外れる。[DR-0008](DR-0008-evaluation-semantics.md) の文言「pin に chain や観測値を要する condition」より対象がわずかに狭くなるので、文言を「pin 値を持つ condition」に改める
- この分岐は `Condition` trait の変更で、JSON の形 (J1〜J3) とは独立に裁定できる

#### J6: 自動で作る grant の `id` と `created_at`

満たすべき性質: `id` は rule の `id` から決まって読み直しても同じで、`Policy::grant` が付ける `id` (`g-…`) と重ならない。`created_at` は採用の順 (同じ effect の中で作成の古い順) に効く。

| 案 | `id` | `created_at` | 意味と帰結 |
|---|---|---|---|
| a (推奨) | `rule:<rule の id>` | UNIX epoch (`1970-01-01T00:00:00Z`) | 値が一覧だけから決まり、時計に依らない。同じ effect で当たった grant の中では、一覧の rule 由来が先に採用される。作成時刻としての意味は無いので、アプリは `id` の接頭辞で見分けて表示を分ける |
| b | 同じ | 読み込みの時刻 | `load_verified` が時計を読む (引数は増やせないので、テストで時刻を差し替えられない)。読み直すたびに値が変わり、承認で作った grant との採用の順が、読み直した時機で変わる |

- 推奨の理由: 一覧だけから決まる grant は、値も一覧だけから決まる形にする

#### J7: 検査の段のエラーが場所を持つか

読み取りの段のエラー (`Parse`) は行と桁を持つ。検査の段のエラー (`UnknownItem { key }` など) は、どの rule・tag・subject で起きたかを持たない。

| 案 | 中身 | 意味と帰結 |
|---|---|---|
| a (推奨) | 検査の段の `LoadError` の variant に、JSON の中の位置を JSON Pointer (RFC 6901) の文字列で持たせる (例 `/rules/3/subject/match/uid`) | どのエラーも場所が分かる (読み取りは行と桁、検査は位置)。型は増えない。`ScopeTooWeak` の `rule_id` は位置に替わる。既存の DR と DESIGN が書く variant (`UnknownTag { name }` など) に field が 1 つ足される |
| b | 持たない | 今の variant の形のまま。一覧のどこで起きたかは、アプリか書いた人が key や名前から探す |

- 推奨の理由: 目的の「どこが不正かの分かるエラー」。位置は JSON の構造だけで言えるので、`id` が欠けている・重複している要素も指せる

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 一覧に形式の版の field を置く | 未知のキーをエラーにするので、形の違う一覧を黙って読むことは無い。今の要件に、版で読み方を変える場面が無い |
| 項目が JSON の値を自分で読む (`Matcher` に JSON を受け取る method を足す) | `MatchValue` は閉じた集合なので、項目に読ませても書ける形は増えない。同じ JSON が key ごとに別の意味に読まれうる。trait の method とアプリの実装の義務が増える |
| `MatchValue` に、項目が自由に使える値 (`serde_json::Value`) を持つ variant を足す | アプリの項目が独自の構造を書けるようになるが、型が増え、その variant の列・placeholder・クラスの規則を決める必要がある。今それを要する項目は無い |
| 入口が版 (単調な番号) を受け取って検査する | Decision の 9。比べる相手の値を守るのはアプリで、crate が足せるのは数の比較だけ。入口の引数と一覧の field が増える |
| 自動で作る grant を、アプリが署名して永続化する | Decision の 8。失うものが無く、一覧から消した rule の grant が残る |
| 読み込みの時に、空の chain と観測値なしで `Condition::pin` を呼び、pin 値が要るかを確かめる | 収集していない chain を組むことになる ([DR-0014](DR-0014-chain-trust-boundary-and-caller-supplied-values.md) の `from_collected` は収集した値の表明)。偽の入力に項目の実装がどう答えるかに頼る |
| pin に chain が要る condition を、組み込みの名前 (`os.login_session`) で見分ける | procline-acl は OS に依存せず、`os.*` の項目を知らない ([DR-0013](DR-0013-acl-layer-in-separate-crates.md))。アプリの項目を見分けられない |
| `ConditionKind` に消費型の値を足す | [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md) は 2 値と決めている。偽で失効するか (kind) と、pin 値の性質は別の軸で、1 つの enum に混ぜると組み合わせを表せない |
| grant にも `validate_args` を呼び、`until` だけ引数なしを許す | 組み込みの名前の特別な扱いが増える。grant の中の引数と pin 値の組の妥当性は、rule の引数の妥当性とは別の問い |
| 公開のエラーの型を、共通の検査エラー 1 つと、それを包む 3 つにまとめる | [DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md)・[DR-0008](DR-0008-evaluation-semantics.md)・[DR-0009](DR-0009-strength-class-as-specificity.md) が名指しする variant の形が変わる。検査の共有は実装でできる。まとめるなら、それらの DR を改める別の決定にする |
| エラーの場所を、rule の `id` や名前を持つ専用の型で表す | 型が増える。`id` が欠けている・重複している要素を指せない |
| 不正な要素を飛ばして、残りの一覧を読む | 黙って無視すると、書いた人の意図と違う一覧が効く (DESIGN-ja「アプリが足す語彙」と同じ理由) |
| `created_from` を `Policy::grant` の引数で受け取る | 引数が増える。返った grant の公開の field に書けば足りる |
| 一覧を表す型 (subject・tag・rule の 3 つの列を持つ構造体) を足す | 書き出しの引数は 3 つの列で表せる。型を足すほどの振る舞いを持たない |

## Consequences

- アプリが一覧を変える手順は、取り出す → 足す → 書き出す → 署名して保存 → `load_verified` で読み直す → 保存した grant を `load_grant` で検査し直す、になる。自動の grant は保存しない
- 保存したものの新しさを確かめるかどうかと、その方法は、アプリの `PolicyVerifier` の実装で決まる。crate の入口と JSON は、それに関わる値を持たない
- 一覧を手で書く時、未知のキー、重複したキー、条件の無い subject、重複した名前はエラーになる。読み取りの段のエラーは行と桁を持つ
- 値の形を足す時は、オブジェクトのキーが既存の形と重ならないことが条件になる
- 重複したキーを拒む読み方を crate が持つ。項目の引数と pin 値 (`serde_json::Value`) の中の重複したキーも、項目に渡る前に拒まれる
- テストで保つ性質: 書き出して読むと同じ値になる (列の順序と、引数・pin 値の「無い」と null の区別を含む)。未知のキー・空を含む一覧と grant を拒む。重複したキーを、項目の引数と pin 値の中を含むどの階層でも拒む。自動の grant が、同じ一覧の読み直しで同じ値になる
- 採られた時に直す所:
  - コード: `crates/procline-acl/src/policy.rs` (2 つの入口、アクセサ、書き出し、`LoadError`、`rules` の未使用の印)、`crates/procline-core/src/pin.rs` と `binary.rs` (serde)、`process.rs` (`StartTime`)、`crates/procline-acl/Cargo.toml` (`serde`)。J2 の a なら `subject.rs`・`matchers.rs`・`builder.rs`。J4 の b と J5 の a・b なら `vocabulary.rs`・`conditions.rs`・`crates/procline-acl-macos/src/os_items.rs`、J5 の a なら `policy.rs` の採用の順
  - DESIGN-ja / DESIGN: 「保存」(一覧の形、書き出し、自動の grant、新しさの責務)、「項目の登録」(未知の field を検出する段を読み取りにし、エラーを `Parse` にする)、「matcher」(`responsible` の値の形、アプリの項目が書ける値)、「grant」(`created_at` の書き方、`created_from` の意味)、「API の骨格」
  - DR: [DR-0014](DR-0014-chain-trust-boundary-and-caller-supplied-values.md) の「外から書く型」の列挙に `Pinnable` と `BinaryPin` を足す。J2 の a なら [DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md) の「型の形」、J4 の b と J5 の a・b なら [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md) の trait、J5 の a・b なら [DR-0008](DR-0008-evaluation-semantics.md) の基準の文言、J7 の a なら variant を書いている各所
  - issue: [差し戻し](../issue/2026-11-15-grant-and-list-rollback.md) の crate の論点は Decision の 9 で決まる。[消費型の印](../issue/2026-11-09-consumable-condition-marker.md) の 1 つ目の受け入れ条件は J5 の a で決まる。[CLI](../issue/2026-11-15-procline-cli.md) の段 2 は、この読み込みが入った後に形を決める
- 未決:
  - 書き出しの関数とアクセサの名前・署名は、実装の時に決める
  - 一覧を読み直している間の評価を、古い `Policy` で続けるか止めるかは、アプリが決める

## 関連

- [DESIGN-ja の「ACL ルールの形と評価」「項目の登録」「ルールの作成と強さの制約」「保存」「API の骨格」「脅威モデルの前提」](../DESIGN-ja.md)
- [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md): rule と grant、condition の trait、grant の保存
- [DR-0006](DR-0006-structured-values-instead-of-depends.md): 値の形と妥当性は項目自身が持つ
- [DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md): placeholder と型の形
- [DR-0008](DR-0008-evaluation-semantics.md): 永続化と有効化の順、自動 grant 化の基準
- [DR-0009](DR-0009-strength-class-as-specificity.md): 制約の表と検査
- [DR-0010](DR-0010-or-in-values-and-tag-definitions.md): 値の列とタグの複数定義
- [DR-0013](DR-0013-acl-layer-in-separate-crates.md): crate の層
- [DR-0014](DR-0014-chain-trust-boundary-and-caller-supplied-values.md): 外から書く型と `Deserialize`
- [findings: 読み込みの入口の実装前の仕分け](../findings/2026-11-15-load-entry-recon.md)
- issue: [差し戻し](../issue/2026-11-15-grant-and-list-rollback.md)、[消費型の印](../issue/2026-11-09-consumable-condition-marker.md)、[CLI](../issue/2026-11-15-procline-cli.md)
