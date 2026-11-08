# DR-0006: key をまたぐ依存を持たず、構造を持つ値の座にする。強さはクラスと深さの 2 軸で表す

- Status: Active
- Date: 2026-11-08

## Context

ACL の条件に使う項目には、単独では意味を持たないものがある。

- signing identifier は開発者が自由に決める値で、ad-hoc 署名でも名乗れる。Team ID と組になって初めて「誰のどのコードか」を指す。
- bundle ID は Info.plist から読むので誰でも書ける。署名者と signing identifier の組に乗せないと何も保証しない。
- cdhash や Team ID は、署名の検証が通っていなければ何を指すか保証がない。
- 起床の回数や画面のロック解除の回数は、起動セッションの中でだけ意味を持つ。

これらを別々の key の項目にして key の間に依存を宣言すると、依存先が同じ match に揃っているかの検査(欠け・矛盾・重複)が読み込みに要り、「署名の検証が通った」だけを表す人工の項目も要る。ところが組み込みで依存が要る組は、どれも「同じ座(key)に、構造を持つ値がある」だけだった。プロセスのコードの同一性を表す値、OS の世代の段階、プロセスの個体識別である。

matcher の項目、寿命型の scope、状態型の条件はどれもアプリが足せる語彙で、同じ規則で扱いたい。

## Decision

### 登録の形

条件に使える項目(`match` の key、寿命型の scope の名前、状態型の条件の名前)は、組み込みもアプリも同じ形で登録する。

```
register(key, impl)
```

- `key`: 項目の名前(名前空間は下記)。
- `impl`: 項目の種類ごとの実装。matcher の項目は `Matcher` trait(照合する `matches` と、値からクラスを決める `class(&self, value) -> Strength`)を実装して `Item::matcher(key, impl)` で登録する。クラスが値によらず一定の項目は、クラスを明示してクロージャで `Item::matcher_fn(key, class, f)` と登録できる。寿命型と状態型は condition の trait(observe / pin / check / advance、[DR-0004](DR-0004-rule-grant-split-and-condition-advance.md))で、`Item::condition(key, impl)`。
- 登録先は procline-acl の `Vocabulary`。matcher の項目、scope、条件が同じ器に入る。
- 登録時の検査は key の重複と名前空間だけ。

key をまたぐ依存は持たない。値の形と妥当性の規則は項目自身が持ち、項目の実装が検査して不正ならエラーにする。

| 誰 | 何をする |
| --- | --- |
| builder(`SubjectBuilder` / `RuleBuilder`) | `SubjectBuilder::pin(key, PinSpec)` で、利用者が選んだもの(`process` なら取れた識別子の全部、`binary` なら field の組み合わせ)から、妥当性の規則を満たすように収集結果の値で埋める。`PinSpec` は `{ All, Binary(Vec<BinaryField>) }`。`os.session` は条件の項目なので、段階は `RuleBuilder::condition(ConditionUse::with_args("os.session", json!("unlocked")))` のように rule の条件の引数で指定する |
| 読み込み(`Policy::load_verified`、`Policy::load_grant`) | 各項目の値の妥当性を項目の実装で検査し、不正ならエラー。`binary` / `process` の値に未知の field があれば、黙って捨てずにエラー |
| UI(アプリ側) | key ごとに 1 つの選択肢を出し、その中で値の段階や field の組み合わせを選ばせる |

### 構造を持つ組み込みの座

| 座 | 値の形 | 照合 | クラス |
| --- | --- | --- | --- |
| `process` | 取れた識別子を全部 pin する複合(`{unique_id?, pid, start_time?}`、[DR-0005](DR-0005-process-identity-as-one-item.md)) | 両側に揃う最強の識別子 1 つで比べる | Strong |
| `binary` | 任意個の field の複合 `{digest?, team_id?, signing_id?, bundle_id?, cdhash?}` | 値にある field を全部それぞれ検証する(AND)。署名由来の field(`team_id` / `signing_id` / `bundle_id` / `cdhash`)は署名の検証が通ったときだけ一致。どの field も完全一致 | 値にある field の最強(署名由来の field があれば Strong、`digest` だけなら Medium) |
| `os.session` | 段階の enum `boot` < `awake` < `unlocked`。pin 値は選んだ段階以下の世代の複合(`{"boot": "7B1E…", "awake": 12, "unlocked": 3}`) | 段階以下の世代が全部一致 | Strong(世代は偽れない) |

`binary` の field の値はどれも文字列(`digest` は `sha256:<hex>`、`cdhash` は hex、`team_id` / `signing_id` / `bundle_id` は署名や Info.plist の値そのまま)。真偽値の field は無い。

`binary` の妥当性の規則(項目の中に閉じる):

- `signing_id` があるなら `team_id` もある(signing identifier は開発者が自由に決め、ad-hoc 署名でも名乗れるため)。
- `bundle_id` があるなら `team_id` と `signing_id` もある(Info.plist は誰でも書けるため)。
- `cdhash` と `digest` は単独でよい。
- 空(field が 1 つも無い)は不正。
- 未知の field がある値は不正(黙って捨てない)。`process` の値も同じ。
- builder はこの規則を満たすように収集結果から埋める(利用者が `signing_id` を選べば `team_id` も入る)。読み込みは満たさない値をエラーにする。
- `cdhash` は、CodeDirectory が identifier・Team ID・Info.plist のハッシュを含むので、下の field の値を全部決める最も強い field(SDK の `cs_blobs.h`: `CS_SUPPORTSTEAMID`、`teamOffset`、`CSSLOT_INFOSLOT`)。
- `digest` は実行パス上のファイルの内容のハッシュで、床として置く。macOS では `proc_pidpath` のパスを読むので、exec の後にファイルを置き換えられると稼働中の像と食い違う(クラスは実行パスと同じ Medium)。Linux は `/proc/<pid>/exe` が稼働中の inode を指すので実質強い。署名由来の field が取れる環境・アプリでは `digest` を使わず、UI は署名由来の field を優先して出す。
- 署名が有効なことは署名由来の field の matcher の性質なので、それだけを表す項目は持たない。

`os.session` の世代の定義:

- 段階の名前は期間の名前。`boot` は起動してから再起動まで、`awake` は起床してからスリープ・ハイバネーションまで、`unlocked` は解錠してから画面ロック(手動、離席の自動ロック、スクリーンセーバー)まで。
- `awake` と `unlocked` は厳密には入れ子でない(スリープせずにロックできる)が、段階 N はそれ以下の世代を全部 pin するので、`unlocked` を選ぶとスリープでも失効する。これは仕様。
- observe は 3 つの段階の世代を 1 つの複合値 `{"boot": uuid, "awake": 回数, "unlocked": 回数}` で返し、その期間の中にいる段階だけを含める(期間の外、つまりロック中やスリープ中の段階は欠く。`boot` は `kern.bootsessionuuid`、他は開始の回数)。pin は引数の段階以下の field を写し、`check` は pinned にある field が全部 observed にあって一致するときだけ真。期間の外では field が欠けるので偽になり、次に期間が始まれば回数が変わるので永久に失効する。「解錠の回数」だけを世代にすると、ロック中も回数が変わらず通ってしまうため。
- ユーザーの切り替え(`os.console_user`)とログインセッション(`os.login_session`、asid)は `os.session` の段階に入れず、独立の座のまま。省電力でモニタが消えるまでの期間は持たない(ロックもスリープも伴わずに起き、マルチモニタの扱いも要るので、欲しいアプリが `app.` で足す)。
- 通知で数える世代(`awake`、`unlocked`、`os.console_user`)はデーモンの起動中しか数えられない。再起動後は観測値が無いか一致しないので `check` が偽([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md))。

### 名前空間

- 接頭辞なし: 対象プロセス自身の属性(`process`、`binary`、`uid`、`gid`、`path`、`cwd`、`argv`、`env`、`name`、`tty`、`responsible` …)。subject は「そのプロセスへの条件」なので無印。
- `os.` はホストの状態と世代、`time.` は時刻、`app.` はアプリ固有。
- `until` / `age` / `uses` は接頭辞なし。grant 自体の寿命であってプロセスの属性でもホストの状態でもないが、組み込みの基本語として無印にする。

### 強さの 2 軸

| 軸 | 何を表すか | 値 |
| --- | --- | --- |
| クラス | 同じ uid のプロセスがその値を偽れるか | `Strength { Strong, Medium, Weak }` |
| 深さ | 値がどれだけ絞るか | `Depth`(値の段階、または pin した field の数) |

- クラスは項目が値から決める(`Matcher::class`)。多くの項目は値によらず一定で、`process`、uid、`os.session` が Strong、実行パスと責任プロセスが Medium、名前、argv、cwd、tty、env が Weak。`binary` は値にある field の最強(上の表)。
- `Strength` は procline-core に置く共有型。どの項目がどのクラスかは Vocabulary(登録された項目の実装)が持つので、`ProcessInfo` の各項目は Strength を持たない。
- ルールの強さの制約はクラスで判定する(算出の規則は [DR-0003](DR-0003-rule-strength-from-own-match.md))。深さは制約に使わず、UI の並び順と、アプリが追加で課す制約の材料にする。

## Alternatives Considered

- 案 A: 項目を key ごとに分け、key をまたぐ依存(depends)を登録時に宣言する。依存先は同じ match に値ごと pin されていなければならない
  - 不採用理由: 組み込みで依存が要った組は、どれも同じ座に構造を持つ値があるだけだった(Context)。key をまたぐ依存は、読み込みに欠け・矛盾・重複の検査を要し、「署名の検証が通った」だけを表す人工の項目を要した。値の構造を 1 つの key に閉じれば、検査はその key の中で済む。
- 案 B: `binary` を段階の enum にする(`team_id` < `signing_id` < `bundle_id` < `cdhash`)
  - 不採用理由: `digest` / `cdhash` と `team_id` 系は、並列に検証したい別の観点で、1 本の順序に乗らない。`cdhash` だけ、`digest` だけ、`team_id` + `signing_id`、のような組み合わせが要る。
- 案 C: コードの同一性の座を `signer` と名付ける
  - 不採用理由: 署名が無いバイナリに使えない。見たいのは署名者ではなくコードの同一性なので `binary` にする。

## Consequences

- 読み込みの検査が key の中に閉じる。項目の実装が自分の値の妥当性を検査すればよく、他の key を見に行かない。
- UI は key ごとに 1 つの選択肢を出せばよい。
- アプリの項目が組み込みの座に依存する形は書けない。組で使いたいときは同じ match に並べる(AND)。
- Linux では `binary` の `digest` がコードの同一性の主手段になる。
- 承認画面は値の段階や field を選ぶだけでよく、妥当性の規則を満たす値は builder が埋めるので、利用者が組を作り損ねることがない。一覧を手で書く場合は、妥当性の規則を満たす値を書く必要がある(満たさなければ読み込み時にエラー)。
- `ProcessInfo` は強さを持たないので、収集の crate は強さの規則を知らずに済む。

## 関連

- [DESIGN-ja の「matcher」「項目の登録」「強さ: クラスと深さ」「scope: grant の寿命」](../DESIGN-ja.md)
- [DR-0001](DR-0001-crate-naming.md): crate の分け方(`Strength`、`BinaryPin`、`SessionLevel` を置く procline-core、`Vocabulary` を置く procline-acl)
- [DR-0003](DR-0003-rule-strength-from-own-match.md): ルールの強さを対象プロセス自身の条件から算出する
- [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md): condition の observe / pin / check / advance と、grant の pin 値
- [DR-0005](DR-0005-process-identity-as-one-item.md): `process` の値の形と照合
