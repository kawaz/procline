# 読み込みの入口 (load_verified / load_grant / sanitize_for_display) の実装前の仕分け: 文書で決まっていることと、決めないと書けないこと

- Date: 2026-11-15

観測した commit: main = 2aac951。文書とコードを読んで仕分けた。コードは実行していない。「決まっている」には、実際に節を開いて確かめたものだけを挙げる。推論で補った所には「推論」と付ける。

## 対象

`todo!()` のまま残る次の 3 つ。

- `Policy::load_verified`: 一覧 (subject、tag、rule) のバイト列と署名を受け取り、検証してから読む (`crates/procline-acl/src/policy.rs`)
- `Policy::load_grant`: 保存した grant 1 件を同じく検証してから読む (`crates/procline-acl/src/policy.rs`)
- `sanitize_for_display`: 置き場は procline-core (`crates/procline-core/src/sanitize.rs`、`crates/procline-core/src/lib.rs` が再公開)。procline-acl ではない

署名を検証する trait の名前は `PolicyVerifier` で、`SignedKind` を受け取る (`crates/procline-acl/src/policy.rs` の 46〜56 行)。

## 判明した事実

### 1. 一覧の JSON の形

決まっている:

- subject の field は `match` / `tags` / `ancestors` / `include_self` (DESIGN-ja「subject」の表 180〜185 行、例 168〜176 行)
  - `ancestors` の要素は `match` と `tags` だけを持ち、入れ子にも名前の参照にもしない (DR-0007「ancestors」、DESIGN-ja 194 行)
- 値の書き方 (DESIGN-ja「matcher」の表 361〜366 行、DR-0007 の表)
  - 完全一致は文字列か数値。glob / 正規表現 / 数値の範囲は `{"glob"}` / `{"regex"}` / `{"min","max"}`
  - `true` は placeholder 専用で、真偽値の完全一致は無い (DESIGN-ja 377 行)
- 値の列は JSON の配列で `MatchValue::AnyOf` になる。1 段だけで、placeholder を入れられず、空は不正。要素ごとに形が違ってよい (DR-0010「値の列」、DESIGN-ja 368〜375 行)
- 構造を持つ値
  - `binary` は `{digest?, team_id?, signing_id?, bundle_id?, cdhash?}` で、field ごとに `true` か文字列を書ける。妥当性の規則は DESIGN-ja 387〜396 行と DR-0006
  - `process` は `true` か `{boot_uuid, unique_id?, pid, start_time?: {secs, micros}}` (DESIGN-ja 383 行、DR-0005)
- tag は `{"tag": 名前, "subject": …}` で、同じ名前の定義を複数置ける (DESIGN-ja「tag」の例 222〜256 行、DR-0010)
- rule は `{id, effect, subject, targets, conditions}` (DESIGN-ja「rule」265〜281 行)
  - `effect` は `allow` / `deny` / `ask`
  - `subject` は、文字列なら subject の名前、オブジェクトならその場の定義 (DESIGN-ja「名前と参照」351 行)
  - `conditions` の要素は文字列 (`"app.unlock"`) か、引数付きのオブジェクト (`{"age": "1h"}`) (DESIGN-ja 271 行、353 行)
- 型との対応: `Subject` / `AncestorMatch` / `Rule` / `ConditionUse` / `Tag` / `SubjectRef` / `MatchValue` の field は、上の JSON と 1 対 1 で対応する。名前が違うのは、Rust の `Tag.name` が JSON では `tag` になる所だけ

決まっていない / 食い違い:

- 一覧全体の入れ物の形が文書のどこにもない。subjects / tags / rules をどのキーの配列で持つか、版の field を持つかが未定
- 名前付きの subject の JSON の形が文書にない。`Policy` は `Vec<(String, Subject)>` で持つ
- 値の JSON をどの型に読むかが key によって変わるのに、この振り分けをどこが持つかが決まっていない
  - `ProcessMatcher::validate` / `ResponsibleMatcher::validate` は `MatchValue::Process(Pin)` しか受け付けず、`MatchValue::Pin` を拒む (`crates/procline-acl/src/matchers.rs` の `validate_identity`)。このため `{"process": true}` は key を見て `Process(Pin)` にするしかない
  - `binary` のオブジェクトと `{"glob": …}` / `{"min", "max"}` の区別も、key で振り分けることになる
  - `Matcher` trait には JSON から値を作る口がない。builder は `PROCESS_ITEMS = ["process", "responsible"]` を固定で持ち、Design rationale を書いている (`crates/procline-acl/src/builder.rs` 14〜17 行)
  - DR-0006 は「値の形は項目自身が持つ」とするが、`MatchValue` は閉じた enum なので、アプリの項目は構造を持つ独自の値を JSON に書けない。この帰結は文書に書かれていない
- 次の扱いが未定
  - subject / rule / tag の field を省いた時の既定値 (例の上では省略しているが、規定はない)
  - `conditions` の要素で、オブジェクトのキーが 2 つ以上ある時
  - JSON の小数、i64 に収まらない数、`false`、`null` (`Literal` は `Integer(i64)` と `Text` だけ)
- `responsible` の JSON の形は DESIGN に書かれていない。コードは `process` と同じ形として扱う

### 2. grant の JSON の形

決まっている:

- `{id, rule_id, effect, subject, targets, conditions:[{key, args?, pinned?}], created_at, created_from}` の形 (DR-0004「grant の形」、DESIGN-ja「grant」312〜331 行)。`Grant` / `PinnedCondition` の field と 1 対 1 で対応する
- `age` は `until` に直す (`args` は無くし、key も `until` にする)。`os.session` の pin 値は段階以下の世代の複合 (DR-0004、DESIGN-ja 331〜332 行)
- subject は inline だけで、名前付きの subject は展開済み。タグ名は名前のまま残す。placeholder が残っていれば `LoadError::InvalidValue` (DR-0007、DR-0008「placeholder の場所」、DESIGN-ja 334〜336 行)
- id は `Policy::grant` が一意に付ける (DESIGN-ja 333 行)。形はコードの doc で `g-<epoch からの nanos>-<sequence>` に決めている (`crates/procline-acl/src/policy.rs` 134 行)
- `until` の pin 値は RFC 3339 で、書き出しは UTC。小数の秒は、ある時だけ付ける (`crates/procline-acl/src/conditions.rs` の module doc)
- `process` の pin 値の例は DESIGN-ja 383 行にあり、`ProcessIdentity` の field と一致する

決まっていない / 食い違い:

- `created_at` を JSON にどう書くかの規定がない。例は `+09:00` の RFC 3339 で、精度と時刻帯は未定。精度を落とすと、採用の順 (`created_at` の古い順) と `UntilWithin` の基準時刻がずれる
- `created_from` の意味と、誰が付けるかが未定。`Policy::grant` は常に `None` を入れる
- crate に `Grant` を JSON に書き出す手段がない (`Serialize` も関数もない)
  - DESIGN-ja「保存」は「crate は `Grant` の JSON の形を持つ」とするが、今の API ではアプリが署名するバイト列を作れない
  - 一覧も同じで、RuleBuilder で作った rule を一覧に保存する流れ (DESIGN-ja 340 行) に要る `Rule` / `Subject` / `Tag` の書き出しもない
- `rule_id` の rule が一覧に無い grant を受け付けるかは書かれていない。「grant は自己完結」(DESIGN-ja 335 行) から見て、受け付けてよいと推論する (未確認)

### 3. 署名の検証

決まっている:

- `trait PolicyVerifier { fn verify(&self, kind: SignedKind, bytes: &[u8], sig: &[u8]) -> bool; }` と `enum SignedKind { List, Grant }` (DESIGN-ja「保存」630 行、「API の骨格」724〜725 行)。コード (`crates/procline-acl/src/policy.rs` 46〜56 行) と一致する
- 検証するのは渡されたバイト列そのもの。署名の形式・鍵の種類・保存先・鍵の保護はアプリが決める (DESIGN-ja 概要「脅威モデルの前提」、「保存」630〜632 行)。crate は用途を `kind` で渡すだけ
- 順序は「検証してから読む」(DESIGN-ja 632 行、`load_verified` の doc)。失敗は `LoadError::InvalidSignature`
- `load_verified` の引数 (bytes, sig, verifier, vocab, constraints, default_effect) は DR-0008「ask と既定の effect」と同じ

決まっていない / 食い違い:

- 一覧と grant を同じ鍵で署名する時、`kind` をどう使って用途を分けるかはアプリに任されている。crate に追加の要求はない (食い違いではなく、境界の記述)

### 4. 版・世代・差し戻し (rollback)

決まっている:

- 署名は版や新しさを見ない。置き場と鍵の保護はアプリの責務 (`docs/issue/2026-11-15-grant-and-list-rollback.md`「背景」、DESIGN-ja「保存」648 行)

決まっていない:

- 入口が版を受け取って検査する形を持つか、版の検査を境界の記述だけにするかが未定。issue は、これを読み込みの実装の時に一緒に決めるとしている
  - 版を受け取る形にすると、`load_verified` の引数が DR-0008 / DESIGN と変わり、一覧の JSON に版の field が要る (1 の入れ物の形と連動する)
- 一覧を読み直した後の grant の検査し直し (DESIGN-ja 646 行) は、差し戻した一覧に対して行われる。issue の指摘のとおりで、これも未決

### 5. 読み込みの時の検査と LoadError

決まっている:

- 未登録の項目はエラー (`LoadError::UnknownItem`)。DESIGN-ja「アプリが足す語彙」535 行と 430 行
- 値の妥当性は `Matcher::validate` と `Condition::validate_args` で検査し、不正なら `InvalidValue` (DESIGN-ja 430 行、DR-0006 の「誰が何をする」の表)
- placeholder を書けない場所 (grant、タグの定義、名前付きの subject) に placeholder があれば `InvalidValue` (DR-0007、DR-0008、DESIGN-ja 295 行・430 行)
- 参照先の無いタグ名・subject 名は `UnknownTag` / `UnknownSubject` (DESIGN-ja 430 行)
- タグの循環はエラー。名前単位で見て、同じ名前の定義のどれかが循環すれば不正 (DESIGN-ja 246 行、DR-0010)
- 制約 (`AllowConstraints`) で `allow` を検査し、違反は `ScopeTooWeak`。`deny` と `ask` は検査しない (DESIGN-ja 614 行・626 行、DR-0009)
- プロセスで決まるクラス (`binary` / `path` / `process`) は、読み込みの時は上限 (保護あり、root 所有) で判定する (DR-0012「いつ決めるか」、DESIGN-ja 618 行)
- `UntilWithin` の判定
  - rule では `age` の長さで判定し、`until` は通す (DESIGN-ja 618 行、`rule_meets`)
  - `load_grant` では基準時刻を grant の `created_at` にする (DESIGN-ja 618 行、`crates/procline-acl/src/constraints.rs` の doc)
- 自動で grant にする基準: 寿命型・消費型の condition を持たず、placeholder を含まず、pin に chain や観測値を要する condition も含まない rule は、読み込みの時に永続の grant になる (DR-0008「自動 grant 化の基準」、DR-0004)
- 今の `LoadError` の variant は次の 8 つ (`crates/procline-acl/src/policy.rs` 782〜811 行)
  - `InvalidSignature`
  - `Parse(serde_json::Error)`
  - `UnknownItem{key}`
  - `UnknownTag{name}`
  - `UnknownSubject{name}`
  - `TagCycle{tags}`
  - `InvalidValue{key, reason}`
  - `ScopeTooWeak{rule_id, class}`

決まっていない / 食い違い:

- 未知の field の検査は、文書の書き方のままでは実装できない
  - DESIGN-ja 430 行は「項目の実装 (`Matcher::validate`) が検査して、未知の field を含む不正な値をエラーにする」とする
  - しかし `Matcher::validate` が受け取るのは `MatchValue` で、未知の field を持てない。検出は JSON を値に変える段 (crate の側) でしかできない
  - その時のエラーが `Parse` か `InvalidValue` かも未定
- `StartTime` は `deny_unknown_fields` を持たない (`crates/procline-core/src/process.rs` 139 行)
  - `ProcessIdentity` は持っているので、`process.start_time` の中の未知の field だけは黙って捨てられる。serde の既定の挙動からの推論で、実行しては確かめていない
  - DESIGN-ja 393 行 (「`process` の値も同じ」) と食い違う
- pin に chain や観測値が要る condition を判定する手段がない
  - `Condition` trait には `kind()` (Lifetime / State) しかない
  - `os.login_session` は State で、chain から pin 値を作る (`crates/procline-acl-macos/src/os_items.rs`)。読み込みの時にこれを見分ける方法がない
  - `docs/issue/2026-11-09-consumable-condition-marker.md` と同じ種類の穴。`uses` は名前で見分けられるが、アプリが足した消費型は見分けられない
- 自動で作る grant の id・`created_at`・`created_from` が未定。あわせて次も未定
  - アプリが永続化するか (メモリにだけ置くか)
  - `grants()` に混ざって掃除の対象になるか
  - `created_at` を何にするか (採用の順に効く)
  - ctx も chain も無い所で、状態型の condition の `pin` をどう呼ぶか (今の `Policy::grant` は `tagged` と `ctx` を要する)
- grant の condition の検査は「一覧と同じ」では済まない
  - `age` から直した `until` は `args: None` を持つ。`Until::validate_args(None)` はエラーを返す (`crates/procline-acl/src/conditions.rs` の `until_args`)。grant にそのまま `validate_args` をかけると、正しい grant を拒む
  - pin 値の妥当性を検査する trait の method がない (`uses` の pin 値が数か、`until` の pin 値が時刻か、など)
  - grant に `age` の key が残っていた時の扱いも未定
- 次の扱いが文書にない
  - 空の subject (builder には `BuildError::Empty` があるが、`LoadError` に対応する variant がない)
  - subject 名・rule の id の重複、読み込んだ grant の id の重複
  - targets の glob の不正 (builder は `InvalidValue{key:"targets"}` を返すが、読み込みでの扱いは文書にない)
  - 一覧の構造の側の未知のキー (例: rule の `efect`)。DESIGN が触れているのは値の中の未知の field だけ
- `LoadError::InvalidValue` の doc の列挙に「a rule that becomes a permanent grant」がある。しかし placeholder を含む rule は定義により永続の grant にならないので、列挙が循環していて意味が曖昧
- `LoadError` は、どの rule / tag / subject で起きたかを持たない。`ScopeTooWeak` の `rule_id` を除くと、`UnknownItem{key}` だけでは場所が分からない。grant を読む時に `ScopeTooWeak.rule_id` に何を入れるか (grant の `rule_id` か id か) も未定
- `Parse` は `serde_json::Error` だけを持つ。procline-acl は `serde` の crate に依存していない (`crates/procline-acl/Cargo.toml` の依存は `serde_json` のみ) ので、`Value` から手で変換すると、その形のエラーを `Parse` で表しにくい

### 6. 型の serde

決まっている:

- 収集した事実の 18 型は `Serialize` だけを持つ。rule と grant の値や設定として外から書く型 (`ProcessIdentity`、`StartTime`、`CdHash`、`SessionLevel`、`Strength`、`EnvPolicy`) は `Deserialize` を持つ (DR-0014「収集した事実の型と JSON」107〜108 行)。コードの実態とも合う
- condition の引数と pin 値は `serde_json::Value` で、項目の実装が読む (DR-0004「世代を返す専用の trait は持たない…pin 値は JSON の値で表す」、`Condition` trait の形)。実例として、`os.session` は `serde_json::from_value` で `SessionLevel` を読む (`crates/procline-acl-macos/src/os_items.rs` 100 行)
- matcher の項目の値は `MatchValue` で受け取る。アプリの項目も `Item::matcher_fn` のクロージャが `&MatchValue` を受け取る。列は語彙が要素に分けて渡す (DR-0010)

決まっていない / 食い違い:

- procline-acl の型には serde の derive が 1 つもない。`serde` の crate に依存していないので derive を書けない。手で `Value` から読むか、依存を足すかが未定
- `Pinnable<T>` と `BinaryPin` (procline-core) にも serde の実装がない
  - doc と DESIGN は「JSON では `true` が `Pin`」「未知の field は拒む」と、JSON の形を書いている
  - これらは DR-0014 の「外から書く型」の列挙にも入っていない。DR-0014 の分類から見れば `Deserialize` を持つ側だが、明記がない
  - 読む処理を core に置くか acl に置くかで、層の責務が変わる
- アプリの matcher の項目が `MatchValue` に無い形の値を JSON で受け取る道は、今は無い。これを仕様として明記するかは未定 (1 の key ごとの振り分けと同じ論点)

### 7. `sanitize_for_display` の仕様

決まっている (DESIGN-ja「表示用の無害化」134〜140 行、doc comment、DR-0001 の core の責務):

- 相手が自由に決められる文字列 (argv、パス、env の値) を画面に出す時に通す
- 制御文字と bidi の制御文字はエスケープして見せる (表示を入れ替えて別のコマンドに見せる攻撃を防ぐ)
- 長すぎる値は、切り詰めたことが分かる形で切り詰める
- 照合には元の値を使う
- 形は `fn(value: &str, max_chars: usize) -> String`、置き場は procline-core

決まっていない:

- エスケープの書き方 (`\u{202E}` / `\x1b` / `^[` など)
- 対象の文字の範囲
  - C0 / DEL / C1 の扱い、タブと改行をエスケープするか
  - bidi の対象 (U+202A〜202E、U+2066〜2069、U+200E/200F、U+061C)
  - 他の書式文字 (ゼロ幅文字、U+2028/2029) を含めるか
- 元の文字列に、エスケープと同じ見た目の文字列があった時に区別するか (`\` 自体をエスケープして単射にするか)
- `max_chars` の単位 (char / 書記素 / 表示幅)。エスケープした後の長さで数えるか、`max_chars = 0` の時はどうするか
- 切り詰めた印の形
- 呼び出す箇所はまだない。procline-cli の出力もこの関数を通していない

### 8. 今ある実装との接続

コードで確かめたもの:

- `Policy::from_parts` は何も検査しない。doc に「`load_verified` が拒むものは呼び出し側の責任」とある。ACL のテストは全部これで Policy を組む (`crates/procline-acl/tests/` の too_weak.rs、grant.rs、tagging.rs、alternatives.rs、evaluate.rs、builder.rs)
- `RuleBuilder::build` が検査するもの (`crates/procline-acl/src/builder.rs`)
  - 名前の参照を展開すること (`UnknownSubject`)
  - `match` の key が matcher として登録されていること (`UnknownItem`)
  - `validate_value` (列の形と `Matcher::validate`)
  - タグ名が一覧にあること (`UnknownTag`)
  - condition の key の登録と `validate_args`
  - targets の glob
  - `allow` のクラスを上限 (`own_class(subject, None)`) で決め、`rule_meets` で制約を検査すること
- `RuleBuilder::build` が検査しないもの
  - placeholder の場所 (名前付きの subject に `true` があっても通る)
  - タグの循環
  - inline の subject が空であること
  - タグの定義そのものの key と値
- `Policy::grant` の側には、制約の判定 (`grant_meets`) と値の検査 (`resolve_entries` の中の `validate_value`) がある

共有できる形になっているか:

- 判定の部品 (`validate_value`、`rule_meets`、`grant_meets`、`own_class(…, None)`、`has_tag`、`expand`) は `pub(crate)` で、そのまま使える
- 検査の本体 (`check_entries` と `RuleBuilder::build` の中身) は `BuildError` を返す。`LoadError` とは型が違い、`ScopeTooWeak` が持つものも違う (`BuildError` は `rule_id` を持たない)。そのままでは共有できず、エラーの型の分け方を決め直す必要がある
- `RuleBuilder` は `&Policy` を要する。読み込みは、subjects / tags を入れた Policy を先に作ってから rule を検査する順序になる
- タグの循環を拒む関数は今ない。`tag_class` と `tag_chain` は、循環したら打ち切るだけ (`crates/procline-acl/src/matching.rs` 187 行の doc に「Loading rejects cycles」とある)
- 読み込んだ rule をアプリに渡す口がない
  - `Policy.rules` は `#[expect(dead_code, reason = "rules are read once loading is implemented")]` で、読む箇所も accessor もない
  - DESIGN は承認画面に rule の一覧を出すとする (DESIGN-ja 340 行、DR-0004)
  - `Rule` を JSON から読む型も無いので、アプリは `Policy::grant` に渡す `&Rule` を得られない

### 9. 読み込みを前提にしたテスト

- `#[ignore]` のテストはない
- `load_verified` / `load_grant` / `sanitize_for_display` を呼ぶテストはなく、`todo!()` に当たるテストもない (crates 全体を grep で確認)
- 読み込みを待っている印は、`Policy` の `#[expect(dead_code)]` (`rules` が読まれない) だけ

## 実装に入るための仕分け

### (i) 今の決定だけで実装に入れる範囲

- 署名を先に検証し、失敗したら `InvalidSignature` を返す骨組み (`kind` は `List` / `Grant`)
- subject / ancestors / rule / tag の各要素の JSON の読み取り (1 で「決まっている」とした形だけ)
- 検査の本体
  - 未登録の項目
  - `validate_value` / `validate_args` (rule の condition に限る。grant は (ii) の 2)
  - placeholder の場所
  - タグ名・subject 名の参照先
  - 名前単位のタグの循環
  - `allow` の制約を上限のクラスで検査すること
- `load_grant` の、subject の検査と制約の検査 (`grant_meets`、基準時刻は `created_at`)
- 上の部品に対するテスト
- ただし、どれも (ii) の 1 (一覧の入れ物の形) と (iii) の 1 (JSON を値に変える場所) が決まらないと、入口として結線できない

### (ii) 裁定が要る点

1. 一覧の入れ物の形と、名前付きの subject の形
   - a: `{"subjects": {名前: subject}, "tags": [...], "rules": [...]}` のように種類ごとのキーで分ける。種類が構造で決まり、名前の重複は object のキーで 1 つになる (serde_json は重複したキーを黙って後勝ちにするので、別に検査が要る)
   - b: 要素の配列 1 本にして、各要素が `tag` / `rule` / `subject` のどれかのキーを持つ。tag の今の形 (`{"tag": …}`) と揃うが、種類の判定が要素ごとに要る
2. grant の condition の妥当性の検査
   - a: `validate_args` は rule にだけかけ、grant は key の登録と制約だけを見る。pin 値は `check` が読めなければ偽 (= 失効) で安全側に倒れる、と割り切る
   - b: `Condition` に pin 値を検査する method を足す。trait が変わり、アプリの項目にも実装が要る
   - c: `age` から直した `until` は args を持たない、と特別扱いして `validate_args` を使い回す。組み込みの名前に依存する
3. 自動で作る grant の扱い
   - a: メモリにだけ置き、永続化しない。一覧を読み直せば作り直す。id は rule の id から決まるものにし、`created_at` は読み込みの時刻にする
   - b: アプリが永続化する。差し戻しの検査の対象にもなる
   - 3-2: 「pin に chain や観測値が要る」をどう知るか。trait に印を足すか、組み込みの名前で判定するか。消費型の印の issue と一緒に決めるかどうかも含む
4. 差し戻しの扱い (`docs/issue/2026-11-15-grant-and-list-rollback.md`)
   - a: 入口が版 (単調な番号) を受け取って検査する。引数と一覧の形が変わり、DR-0008 と DESIGN を改める
   - b: 版の検査は、アプリが読み込みの前に行う。crate は境界の記述だけを持つ
5. `sanitize_for_display` の詳細
   - エスケープの書き方、対象の文字の集合、`\` を単射のためにエスケープするか、`max_chars` の単位、切り詰めた印の形
6. 重複と空の扱い
   - subject 名・rule の id・読み込んだ grant の id の重複と、空の subject を、それぞれエラーにするか。エラーにするなら `LoadError` に variant を足すか
7. 一覧の構造の側の未知のキー (例: rule の誤記 `efect`)
   - エラーにするか、無視するか

### (iii) 先に設計の文書化 (DR) が要る点

1. JSON を `MatchValue` に変える責務の置き場
   - key によって読む型が変わる (`process` / `responsible` の `true` は `Process(Pin)`、`binary` はオブジェクト) のに、`Matcher` trait に口がなく、builder は名前を固定で持つ
   - 次のどれにするかと、アプリの項目が `MatchValue` に無い形を書けないことを明記するかを決める
     - 語彙・項目が読む (trait に method を足す)
     - crate が key の表で振り分ける
     - 値の中身だけで振り分ける (この場合は `{"process": true}` を受け付けられない)
   - DR-0006「値の形は項目自身が持つ」との関係も整理が要る
2. serde の置き場と範囲
   - `Pinnable` / `BinaryPin` に `Deserialize` を足すか (core の責務か、acl の責務か)。DR-0014 の「外から書く型」の列挙に追記するかどうかも含む
   - procline-acl に `serde` を足して derive で読むか、`serde_json::Value` から手で読むか
   - `StartTime` の未知の field の扱いを `ProcessIdentity` と揃えること
   - 未知の field の検出を「項目の実装」でなく「読み取りの段」で行うように、DESIGN-ja 430 行の文言を直すこと
3. `Grant` / 一覧の書き出し (`Serialize` か関数) を crate が持つこと
   - DESIGN の「crate は `Grant` の JSON の形を持つ」が、読み込みの入口しか持っていない
   - あわせて決めること
     - `created_at` の時刻の形と精度
     - `created_from` の意味
     - 読み込んだ rule をアプリが取り出す口 (`Policy` の accessor)
4. 読み込みと builder で検査を共有するためのエラーの型の構成
   - `BuildError` と `LoadError` を分けたまま変換するか、共通の検査エラーを持つか
   - エラーに場所 (どの rule / tag / subject / grant か) を持たせるか

## serde の挙動の観測

リポの外に置いた小さな試験プログラムで実行して確かめた (serde_json 1.0.154、serde の derive)。

- `Option<serde_json::Value>` の field は、`Some(Null)` を書き出すと `null` になり、derive の既定で読み戻すと `None` になる (`None` はキーを書かない設定でも同じ)。キーの省略と null は、既定の読み方では区別できない
- 重複したキーを持つオブジェクト (`{"x":1,"x":2}`) を `serde_json::Value` や map に読むと、エラーにならず後のキーが残る (`x` は 2)。読んだ後の値からは、重複があったことは分からない
- `StartTime` は、未知の field を持つ JSON をエラーにせず読む (未知の field は捨てられる)

## 未観測

- `rule_id` の rule が一覧に無い grant を受け付けてよいかは、文書からの推論で、文書に明記はない
