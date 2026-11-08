# 接続元プロセスの情報収集と ACL 設計

## 概要

プロセスとその祖先の情報を集め、その情報に対するアクセス制御(ACL)を定義・評価するための crate 群です。pam-passkey の承認画面と、cw の ACL 照合・後付けの許可ルールが同じものを必要とするので、両者から切り出して共通の部品にします。収集の入口は UNIX ドメインソケットの接続相手(audit token)が主ですが、中心はあくまでプロセスで、接続相手であることには依存しません。

**利用者と使い方**

- **pam-passkey**: 呼び出し元のプロセスとその祖先を集め、承認画面に表示する。照合は使わない。
- **cw**: 接続相手を集め、キーごとの ACL で許可・拒否・再認証を決める。承認画面から後付けでルールを作る。

**設計の柱**

1. **識別は pid より強いもので**: 接続相手は audit token、祖先はプロセスごとに一意な ID で特定し、pid の再利用で取り違えない。
2. **表示と照合を同じ型の上に置く**: 画面で見ている情報から、そのままルールを作れるようにする。
3. **項目ごとに強さを持つ**: 同じ uid のプロセスが偽れる項目(名前、cwd、argv)と、偽れない項目(コード署名)を、項目を登録するときに強さで区別し、弱い条件だけの許可を制限する。
4. **語彙をアプリが足せる**: matcher の項目、scope(grant の寿命)、条件は、組み込みの語彙に加えて、アプリ固有のものを同じ形で登録できるようにする。

**範囲**

macOS を先に実装し、Linux は後から足せる形にします。Linux の収集(`SO_PEERCRED`、pidfd、`/proc`)も同じ型の上に同じやり方で足します。

## 構成

収集は OS ごとの crate に実装し、型と照合は OS に依存しない core に置きます。アプリが使うのは入口の procline だけで、これがビルドターゲットに応じて OS ごとの crate を読み込みます(`[target.'cfg(target_os = "macos")'.dependencies]`)。core 自体を入口にしないのは、OS ごとの crate が core の型に依存するので、core から読むと循環するためです。ACL は型だけに依存するので、Linux の収集を足してもそのまま使えます。名前は process lineage(プロセスとその祖先の列)から取っています(決定の記録: [DR-0001](decisions/DR-0001-crate-naming.md))。

| crate | 中身 | 依存 |
| --- | --- | --- |
| procline | 入口。core の型と、ビルドターゲットの OS の collect を再公開する | core、OS ごとの crate(target ごとに片方だけ) |
| procline-core | 収集結果の型、強さのクラスの型(`Strength`)、署名の信頼度の判定、表示用の無害化、env の方針と伏せ字、JSON の形 | なし(OS 非依存) |
| procline-macos | 接続相手と祖先の収集、コード署名の検証、アイコン、OS の世代(起動、スリープ、画面ロックなど)の提供 | core、Security framework、AppKit |
| procline-acl | rule と grant の型、評価、語彙(matcher の項目、scope、条件)とその登録、rule の作成と grant の発行 | core |

アプリ(cw、pam-passkey)は、必要なものだけを使います。pam-passkey は収集だけ、cw はすべてです。cw 固有の語彙(`app.unlock` など)は cw 側で定義して、`app.` の名前で procline-acl に登録します。

## 収集する情報

収集結果は、対象のプロセス(多くは接続相手)を先頭に launchd までの祖先を並べた列です。各プロセスが下の項目を持ち、取れなかった項目は空にします。表の「強さ」は項目のクラスで、「同じ uid のプロセスがその値を偽れるか」で決めます。depends を持つ項目は根のクラスを引き継ぎます(後述の「強さ: クラスと深さ」)。

### 識別子

| 項目 | 取り方(macOS) | 強さ | 備考 |
| --- | --- | --- | --- |
| audit token(接続相手) | `getsockopt(LOCAL_PEERTOKEN)` | 強 | 公開 API。pid、pidversion、uid、asid を含む |
| unique\_id / parent\_unique\_id | `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` の `p_uniqueid`、`p_puniqueid` | 強 | 起動ごとに一意な 64bit ID。祖先を確実に辿れる。`#ifdef PRIVATE` の SPI なので、取れなければ pid と起動時刻の組に落とす |
| pid、起動時刻 | `proc_pidinfo(PROC_PIDTBSDINFO)` | 強(組で) | 組で識別子になる(unique\_id が無いときの識別) |
| asid(audit session ID) | audit token | 強 | ログインや ssh のセッションごとに別。`os.login_session` の pin 値に使う |

これらの識別子は収集の内部の分類で、ルールの語彙では audit token、unique\_id、pid と起動時刻が個体識別の `process` 1 項目に畳まれ(「matcher」)、asid は `os.login_session` の pin 値として内部で使われるだけで語彙には出ません。

### プロセスの属性

| 項目 | 取り方(macOS) | 強さ |
| --- | --- | --- |
| uid、gid、所属グループ(照合は数値。表示用に名前も持つ。1つの ID に名前が複数あり得るので列で持つ) | `LOCAL_PEERCRED`、audit token | 強 |
| コード署名(識別子、Team ID、cdhash、署名者の証明書チェーン、ad-hoc・hardened runtime・platform binary の別、entitlements、公証) | `SecCodeCopyGuestWithAttributes`(接続相手は audit token、祖先は pid)、`SecCodeCheckValidity`、`SecCodeCopySigningInformation` | 強(検証が通ったときだけ) |
| 実行パス | `proc_pidpath` | 中(ユーザーが書き換えられない場所なら) |
| app bundle(bundle ID、版) | 実行パスから `.app` を遡り Info.plist を読む | 強の連鎖の葉(`team_id`、`signing_id` に依存) |
| 責任プロセス | `responsibility_get_pid_responsible_for_pid`(私的 API) | 中 |
| プロセス名、argv、cwd、tty | `KERN_PROCARGS2`、`PROC_PIDVNODEPATHINFO`、`kinfo_proc` | 弱 |
| env | `KERN_PROCARGS2`(同じ uid か root のみ) | 弱(方針は後述) |
| アイコン | `NSWorkspace.icon(forFile:)` を 64px PNG に縮小 | 表示専用(照合に使わない) |

SPI や私的 API に依存する項目は、取れなければ空にするだけで、収集全体は止めません。実機では自分が使う最新の macOS だけで確かめます。古い版で取れなくても空になるだけで、安全側に倒れるためです。

## 署名の信頼度と警告

アイコンや名前は「何に見えるか」、署名は「実際は誰か」です。core は各プロセスに署名の信頼度を付け、両者が食い違うときに目立たせるための判定を提供します。pam-passkey の承認画面も cw のルール作成画面も、この判定をそのまま表示します。

| 信頼度 | 状態 | 表示 |
| --- | --- | --- |
| platform | Apple のプラットフォームバイナリ | 警告なし |
| notarized | Developer ID 署名で公証済み | 警告なし(署名者名と Team ID を併記) |
| developer\_id | Developer ID 署名だが公証なし | ⚠️ 未公証 |
| adhoc | ad-hoc 署名(Team ID なし) | ⚠️ ad-hoc |
| unsigned / invalid | 署名なし、または検証に失敗 | ⛔ 署名なし / 署名が無効 |

アイコンや名前は誰でも真似できるので、画面では署名者名と Team ID を常に並べて出します。過去の承認と比べて「署名者が変わった」と警告する仕組みは持ちません。ルールやタグは署名者で照合するので、署名者が変われば自然に当たらなくなるためです。

公証の有無は、requirement `notarized` を渡した `SecCodeCheckValidity` で真偽として取れます。署名の検証は大きなアプリでは重く、ticket が staple されていないと問い合わせが走ることもあるので、結果は cdhash をキーに期限付きでキャッシュします(公証は後から取り消され得るため、無期限にはしない)。

**アイコン**: 手元の .app から取ります。App Store の API は、Developer ID 配布のアプリが取れず、利用中のアプリを外部に問い合わせることになるので使いません。キャッシュのキーは cdhash(なければ bundle ID と版)です。アイコンは誰でも真似できるので、画面では必ず署名の信頼度と並べて出します。

## env、無害化、収集の整合性

### env

env にはトークンなどの秘密が混ざるので、収集するかどうかを呼び出し側が選びます。

| 方針 | 収集するもの |
| --- | --- |
| `none`(既定) | 収集しない |
| `allowlist` | 列挙した変数だけ(例: `PWD`、`SSH_CONNECTION`、`SUDO_COMMAND`) |
| `all` | すべて。ただし伏せ字の規則を必ず通す |

伏せ字は core に置き、2つの関数として差し替えられるようにします。対象の判定 `Fn(&str) -> bool`(変数名を受け取る)と、伏せ方 `Fn(&str, &str) -> String`(名前と値を受け取る)です。既定は、名前に `TOKEN`、`SECRET`、`PASS`、`KEY`、`CRED`、`AUTH`、`COOKIE`、`SESSION`、`PRIVATE`、`CERT`、`SALT`、`PWD`、`OTP` を含む変数(大文字小文字を区別しない)の値を伏せ、名前だけ残します。語の選び方は Rails の `filter_parameters` や Sentry の既定の伏せ字など、既存のリストに合わせます。`PWD` は作業ディレクトリの変数も巻き込みますが、作業ディレクトリは cwd の項目で取れるので困りません。外したいときは、既定の判定関数を包んで PWD を除く関数に差し替えます。env は弱い項目なので、照合の条件には既定で使えません。

### 表示用の無害化

argv、パス、env の値など、相手が自由に決められる文字列を画面に出すときは、core の関数を通します。

- 制御文字と bidi 制御文字はエスケープして見せる(表示を入れ替えて別のコマンドに見せる攻撃を防ぐ)。
- 長すぎる値は切り詰め、切り詰めたことが分かる形にする。
- 照合には無害化する前の元の値を使う。

### 収集の整合性

収集は時間がかかるので、その間にプロセスが入れ替わることがあります。

1. 接続相手は audit token、祖先は unique\_id(なければ pid と起動時刻)を、収集の最初に記録する。
2. 署名は、接続相手を audit token で参照して検証する(pid で参照すると、その間に別のプロセスになり得る)。
3. 収集の最後に、記録した識別子が変わっていないことを確かめる。変わっていれば結果を捨て、エラーを返す。
4. 祖先は途中で終了していることがある。その場合は「ここで途切れた」と分かる形で列を終える。

## ACL ルールの形と評価

ACL は4つの部品でできています。subject、tag、rule は名前を付けて使い回せる静的な定義で、署名付きの一覧に入り、設定ファイルにも承認画面にも同じ形で現れます。grant は rule を実際のプロセスに適用して条件を具体値に pin したもので、評価が見るのはこれだけです。

| 部品 | 中身 | 使い道 |
| --- | --- | --- |
| subject | 1つのプロセスへの条件。祖先への条件を入れ子で持てる | ルールの対象、タグの定義 |
| tag | 名前の付いた subject。当たるプロセスにタグが付く | 承認画面での表示、ほかの subject の条件 |
| rule | 誰が(subject)、何に(targets)、いつまで・どんなときに(conditions)、どうなるか(effect)。conditions は記号のまま | grant の元。「いつもの許可」を承認画面で選んで passkey 1回で適用 |
| grant | rule を承認の瞬間の接続相手に適用し、各 condition を具体値に pin したもの | 評価 |

どの grant にも当たらなければ既定の effect(普通は `ask`)になり、拒否は許可より優先します。

### subject

subject は1つのプロセスへの条件で、接続相手か祖先かを区別しません。祖先への条件は `ancestors` の中に subject を入れ子で書きます。入れ子の subject もまた `ancestors` を持てるので、「A の下の B の下の C」のような何層の形でも組み立てられます。

```json
{
  "match": {
    "signature_valid": true,
    "team_id": "VWXYZ67890",
    "signing_id": "com.anthropic.claude-code",
    "cwd": "/Users/alice/src/pj1/**"
  },
  "ancestors": [
    { "any": { "match": { "signature_valid": true, "team_id": "ABCDE12345", "signing_id": "com.googlecode.iterm2" } } }
  ]
}
```

| 要素 | 中身 |
| --- | --- |
| match | そのプロセス自身の項目への条件(形は後述の matcher) |
| tags | そのプロセスに付いているタグ |
| ancestors | 祖先への条件の列。`any`(祖先のどれか)、`at`(n 個上)、`chain`(並び順まで指定)。中身はどれも subject。`"include_self": true` でそのプロセス自身も候補に含める(「自身か祖先のどれか」) |

`match` と `tags` はそのプロセス自身への条件で、`ancestors` は祖先だけへの条件です(`include_self` がなければ自身は含まない)。`ancestors` しか書かなければ、そのプロセス自身には条件を付けないことになります。subject の中の条件はすべて AND です。OR はルールを分けて書きます。ルールを読む人が入れ子の論理式を追わずに済むようにするためです。

### tag

tag は名前の付いた subject です。収集のたびに、列の各プロセスを tag の subject と照合し、当たったプロセスにタグを付けます。深い条件は tag(や名前付きの subject)の定義に閉じ込め、ルール側はその名前を参照するだけにします。次の例は、pj1 の claude セッション自身と、そこから起動されたプロセスのすべてにタグが付きます。

```json
{
  "tag": "claude-pj1",
  "subject": {
    "ancestors": [{
      "any": {
        "match": {
          "signature_valid": true,
          "team_id": "VWXYZ67890",
          "signing_id": "com.anthropic.claude-code",
          "cwd": "/Users/alice/src/pj1/**"
        },
        "ancestors": [{ "any": { "match": { "signature_valid": true, "team_id": "ABCDE12345" } } }]
      },
      "include_self": true
    }]
  }
}
```

これでルールの subject は `{"tags": ["claude-pj1"]}` だけで済みます。画面では、タグが付いたプロセスのすべてにタグを出します。そのタグを認可したときに通るプロセスと、画面でタグが付いているプロセスがそのまま一致します。

- タグを条件にした場合の強さは、タグの定義の subject の強さと同じです(算出の規則は「ルールの作成と強さの制約」)。
- 上の `claude-pj1` は `ancestors` だけで対象自身への条件を持たないので弱で、これを subject にした `allow` ルールには世代の scope が要ります(下の rule の例は `os.boot` と `app.unlock` を持つので満たします)。
- タグの定義もルールと同じ署名付きの一覧に入れます。同じ uid のプロセスが定義を書き換えられると、そのタグを条件にしたルールが全部広がるためです。
- タグの定義が別のタグを参照してもよく、循環は読み込み時にエラーにします。

### rule

rule は静的な定義です。conditions は記号のまま書き、世代や時刻はまだ持ちません。subject、tag と同じ署名付きの一覧に入ります。

```json
{
  "id": "pj1-claude-usual",
  "effect": "allow",
  "subject": { "tags": ["claude-pj1"] },
  "targets": ["key:k1"],
  "conditions": ["os.boot", "app.unlock", { "age": "1h" }, { "uses": 3 }, "os.not_remote"]
}
```

| 要素 | 中身 |
| --- | --- |
| id | rule の名前。grant が `rule_id` で指す |
| effect | `allow`(無認証で通す)、`deny`(拒否)、`ask`(アプリの再認証を求める) |
| subject | 上の subject。名前で参照してもよい |
| targets | ルールが効く対象(キーの glob、タグ)。対象の語彙はアプリが決める。不要なアプリは省略する |
| conditions | 条件の名前の列(すべて AND)。寿命型と状態型があり、どちらかは語彙が決める(下記) |

条件には2つの種類があり、どちらかは語彙に登録するときに決まります。ルールには `conditions` に名前を並べるだけで、種類ごとに置き場を分けません(すべて AND)。

| 種類 | 偽になったとき | 例 |
| --- | --- | --- |
| 寿命型(scope) | 戻らない。その grant は永久に失効する | `os.boot`、`app.unlock`、`age`、`until`、`uses` |
| 状態型 | 偽の間だけ当たらない | `os.not_remote`、`os.console_active`、`time.window` |

`uses`(消費型)も寿命型です。一度 0 になれば戻りません。種類はルールを書く人ではなく語彙が知っているので、承認画面や trace では各条件の横に種類を出し、読む人にどちらの意味かを見せます。

静的な rule を評価に直接使うことはしません。評価が見るのは grant だけです。一覧の rule のうち寿命型・消費型の condition を持たないものは、読み込み時に自動で永続の grant になります。手書きの deny を「許可する」操作なしに効かせるためです。寿命型・消費型を含む rule は、承認を経てだけ grant になります。

### grant

grant は、rule を実際のプロセス(承認の瞬間の接続相手)に適用し、各 condition を具体値に pin したものです。grant を作るときに、寿命型の条件にはその時点の世代を記録し、`age` は時刻に直します。

```json
{
  "id": "g-2026-11-08-0001",
  "rule_id": "pj1-claude-usual",
  "effect": "allow",
  "subject": { "tags": ["claude-pj1"] },
  "targets": ["key:k1"],
  "conditions": [
    { "key": "os.boot", "pinned": "7B1E…" },
    { "key": "app.unlock", "pinned": 12 },
    { "key": "until", "pinned": "2026-11-08T13:00:00+09:00" },
    { "key": "uses", "pinned": 3 },
    { "key": "os.not_remote" }
  ],
  "created_at": "2026-11-08T12:00:00+09:00",
  "created_from": "approval-ui"
}
```

- `conditions` の各要素は `key`、元の引数 `args`(必要なら)、`pinned`(pin 値。状態型には無い)です。`age` は grant を作るときに `until` の pin 値に直します(`key` も `until` にする)。
- depends の規則は grant にも当てはまります(`os.wake` の pin があるなら `os.boot` の pin もある)。
- `id` は `Policy::grant` が一意に付けます(上の `g-…` は例示)。
- grant は自己完結です。effect、targets、pin 済みの conditions、subject の中身を自分で持ち、元の rule の id を `rule_id` として持ちます(表示と掃除に使う)。rule が後で変わっても、既存の grant は変わりません。
- subject の中のタグ名・subject 名の参照は、名前のまま残します。タグの定義は署名付きの一覧にあり、その更新は意図した変更なので、既存の grant にも及んでよいためです。
- 寿命型・消費型の condition を持たない rule から作った grant は pin 値が無く、失効しません(永続の grant)。deny は普通こちらです。

保存した rule がそのまま再適用の対象になります。承認画面に rule の一覧を出し、選んで passkey を1回通せば grant ができます。承認画面でその場で条件を選んで許可する流れは「rule を組み立て、すぐ grant にする」の 2 段です。rule を一覧に保存するかは利用者が選び、保存しなければ使い捨ての rule になります。

### 名前と参照

subject、tag、rule、条件の組は、どれも名前を付けて一覧に置き、ほかから名前で参照できます。承認画面で作った subject を名前付きで保存すれば、次からはタグの定義にも別のルールにも使い回せます。

参照は文字列で書きます(`{"ref": "…"}` のような包みは使いません)。

**決定の理由**: 参照が現れる場所ごとに、何を指すかが1つに決まっていて、種類が混ざる場所がないためです。

- `tags` の中はタグ名だけ。
- subject の位置(ルールの `subject`、`ancestors` の `any` などの中身)は、文字列なら subject 名、オブジェクトならその場の定義。型で区別できる。
- rule は適用するときに名前で指すだけで、一覧の中からは参照されない。
- `conditions` の要素は、文字列も `{"age": "1h"}` のような引数付きも、どちらも語彙の名前。

包みを入れても、書く量と読む手間が増えるだけで、曖昧さは減りません。この前提が崩れる(同じ場所に種類の違う名前が入り得る形を足す)ときにだけ、見直します。

### matcher

`match` の key は語彙(`Vocabulary`)に登録された項目の名前で、値はその項目への条件です。照合の形は項目ごとに決まります。

| 形 | 使える項目 |
| --- | --- |
| 完全一致 | すべて |
| glob | パス、識別子、bundle ID、プロセス名、cwd。パスと cwd は絶対パスで書き、`~` は解釈しない |
| 正規表現 | パス、argv |
| 数値の範囲 | uid |

`cdhash`、`process`、`team_id` は完全一致だけにします。署名の条件は、署名の検証が通ったときだけ一致とみなします(署名系の項目はすべて `signature_valid` に依存します。下記)。ad-hoc 署名は Team ID が空なので、Team ID の条件には決して一致しません。

**`process`** は「この個体のプロセス」を表す項目です(決定の記録: [DR-0005](decisions/DR-0005-process-identity-as-one-item.md))。pin 値は、builder がその時点で取れた識別子を全部持つ複合値です(例 `{"process": {"unique_id": 12345, "pid": 501, "start_time": {"secs": 1762570683, "micros": 123456}}}`)。照合は両側に揃っている最も強い識別子で比べ、最悪でも pid と起動時刻の組の一致を見ます。ルールを書く人は、どの識別子で比べたかを気にしません。クラスは強で、depends を持たない独立項目です。`match` にも `ancestors` の中にも書けるので、「このターミナルのタブのシェルの子孫」が書けます。pin したプロセスが終わればそのプロセスは列に居なくなり、grant は当たらなくなります。列に居るプロセスの寿命はこれで表せます。終わったプロセスを指す grant の削除は掃除(アプリ)の責務です。UI では「このプロセスだけ」の 1 選択肢として出します。

### 項目の登録と depends

条件に使える項目(`match` の key、寿命型の scope の名前、状態型の条件の名前)は、組み込みもアプリも同じ形で語彙に登録します(決定の記録: [DR-0002](decisions/DR-0002-matcher-depends-and-two-axis-strength.md))。

```
register(key, impl, depends: [key...])
```

| 引数 | 中身 |
| --- | --- |
| key | 項目の名前。組み込みは接頭辞なし(`signing_id`、`cwd`)か `os.` / `time.`、アプリは `app.`(名前空間の規則は「アプリが足す語彙」のとおり) |
| impl | 項目の種類ごとの実装。matcher の項目は照合する関数、寿命型と状態型は condition の trait(observe / pin / check / advance、「条件の実装」) |
| depends | この項目の値が意味を持つために、同じ `match`(寿命型なら同じ `conditions`)に値ごと pin されていなければならない項目の列 |

登録先は procline-acl の `Vocabulary` で、matcher の項目、scope、条件が同じ器に入ります。`depends` に挙げた key が登録されていなければ、登録の時点でエラーにします。depends の循環もエラーです。

組み込みの項目の depends は次のとおりです。

| 項目 | depends | 理由 |
| --- | --- | --- |
| `signature_valid` | (なし、根) | 署名の検証が通ったこと。値は真偽。署名系の項目はすべてここに依存する |
| `cdhash` | `signature_valid` | 検証が通っていない cdhash は、何を指すか保証がない |
| `team_id` | `signature_valid` | 同上 |
| `signing_id` | `team_id` | signing identifier は開発者が自由に決める値で、ad-hoc 署名でも名乗れる。単独では弱く、Team ID と組でだけ意味を持つ |
| `bundle_id` | `team_id`、`signing_id` | Info.plist は誰でも書ける。署名者と signing identifier の組に乗せてだけ使う |
| `os.wake` | `os.boot` | 起床の回数は起動セッションの中でだけ意味を持つ |
| `os.screen_unlock` | `os.boot` | 同上 |

寿命型にも同じ規則を当てはめます。ルールの `conditions` に `os.wake` を置くなら、`os.boot` も置かなければなりません。表に無い組み込みの項目(`process`、`uid`、`path`、`cwd`、`argv`、`os.login_session` など)は、depends を持たない独立項目です。

規則は 1 つだけです: **depends に挙がった項目は、同じ match に値ごと pin されている**。例えば `"signing_id": "com.anthropic.claude-code"` を条件にするなら、同じ match に `team_id` と `"signature_valid": true` も入ります(上の subject の例がこの形です)。各部品の責務は次のとおりです。

| 誰 | 何をする |
| --- | --- |
| builder(承認画面からルールを作る `SubjectBuilder` / `RuleBuilder`) | 利用者には項目を 1 つ選ばせる(多くは葉)。選んだ項目から根までの祖先は、builder が収集結果の値で埋める。利用者に祖先を手で選ばせない |
| 読み込み(`Policy::load_verified`) | 欠け(ある項目の depends の項目が同じ match に無い)はエラー。矛盾(同じ項目が重複 key で複数回書かれている)はエラー。重複(複数の葉が同じ祖先を共有する)は、祖先が map に 1 つあればよいので正常 |
| 評価 | 連鎖全体を見る。match の項目をすべて AND で照合し、葉だけを見て祖先を省くことはしない |
| UI(アプリ側。procline-acl は連鎖の列挙と並び順を提供する) | depends のある項目は、連鎖(depends で繋がった項目の集まり)ごとに 1 つの選択肢として見せ、候補を強度順に並べる(例: 署名の連鎖なら `signature_valid` < `team_id` < `signing_id` < `bundle_id`、別の枝に `cdhash`)。選ぶと、その項目から根までが pin される。依存の無い独立項目はそのまま並べる |

### 強さ: クラスと深さ

項目の強さは 2 つの軸で表します。

| 軸 | 何を表すか | 値 |
| --- | --- | --- |
| クラス(連鎖の間) | 同じ uid のプロセスがその値を偽れるか(「収集する情報」の表の強さ) | 強 / 中 / 弱 |
| 深さ(連鎖の中) | どれだけ絞るか。葉ほど祖先の値をすべて pin するので厳しい | 根からの距離 |

- クラスは連鎖に 1 つです。登録するときに根(depends が空の項目)に与え、depends を持つ項目は根のクラスを引き継ぎます。複数の根に至る項目は、最も強い根のクラスになります(AND は条件を狭めるだけなので)。
- 独立項目は 1 項目だけの連鎖で、自分が根です。クラスは「収集する情報」の表のとおりです(`process`、uid、署名系は強、実行パスと責任プロセスは中、名前、argv、cwd、tty、env は弱)。
- bundle\_id は強の連鎖の葉(`team_id`、`signing_id` に依存)で、実行パスは中の独立項目です。
- どの項目がどのクラスかは語彙が持ちます。収集結果の各項目は強さを持ちません。
- 深さは UI の並び順と、アプリが追加で課す制約の材料です。ルールの強さの制約には使いません(「ルールの作成と強さの制約」)。

### 評価

評価の対象は grant です。

1. 失効した grant を除く(寿命型の `check` が偽のもの。掃除の対象にする)。
2. targets が対象に当たらない grant を除く。
3. 各 grant の subject を照合し(match の項目は depends の祖先も含めてすべて照合する)、状態型の `check` を取る。`deny` が1つでも当たれば拒否。
4. `allow` が当たれば許可。当たった allow のうち採用するのは 1 件。advance で変わらない grant(永続、または `uses` を持たない)を優先し、同順なら作成の古い順。他の grant で通るのに、限りある `uses` を減らさないため。
5. `ask` が当たれば、または何も当たらなければ、既定の effect。
6. 採用された grant にだけ、各 condition の `advance` をかける。1 つでも新しい pin 値を返せば、pin 値を差し替えた新しい grant を作る(grant は immutable)。

評価の結果(`Decision`)は effect だけでなく、採用された grant の id と、各条件がどの項目に一致したか(trace)を返します。画面の「なぜ通ったか、なぜ聞かれたか」に使います。手順 6 で grant が変わったときは、その新版も返します(`updated_grant`)。

評価の入口は 2 つです。`evaluate` は手順 6 まで行い、メモリ上の grant も新版に差し替えます。`explain` は trace の表示用で、`advance` をかけず、`updated_grant` は常に空です。

- アプリは `updated_grant` を署名して永続化し、書けてから値を渡します。書き込みに失敗してもメモリ上は減った側なので、安全側に倒れます。
- `uses` が 0 になった grant は、次の評価で手順 1 により失効扱いになります。削除は掃除(アプリ)の責務です。

## scope: grant の寿命

寿命型の条件(以下 scope)は、grant を作るときにその時点の世代(epoch)を pin し、評価のたびに今の世代と pin 値を比べて、違えばその grant は永久に失効します。「解錠している間」ではなく「この解錠の回の間」になるので、一度ロックして解錠し直しても grant が生き返りません。

この形にすると、どの scope も「一度終われば戻らない」ことが自動的に保証され、アプリが足すのも condition の trait の実装 1 つで済みます(「条件の実装」)。grant を作るときに今の世代を観測できなければ grant を作れず(`PinError::Unobservable`)、評価のときに観測できなければ `check` が偽になって失効します。どちらも安全側に倒れるためです。

scope は複数並べられ、すべてが生きている間だけ grant が効きます(AND)。「24時間、ただし再起動まで」のように組み合わせます。

### 組み込みの語彙

| 名前 | 終わる時点 | 世代の取り方(macOS) |
| --- | --- | --- |
| `until` | 指定の時刻 | 時計(世代ではなく時刻で判定) |
| `age` | grant の作成からの経過時間 | grant を作るときに `until` の pin 値に直す |
| `uses` | N 回採用されたら | 残り回数を pin し、採用されるたびに 1 減る(世代ではなくカウンタ) |
| `os.boot` | 再起動 | `kern.bootsessionuuid` |
| `os.wake` | スリープ、ハイバネーション | IOKit の電源通知で数える起床の回数 |
| `os.screen_unlock` | 画面ロック、スクリーンセーバー | 画面のロック解除の通知で数える回数 |
| `os.login_session` | ログアウト、ssh の切断 | audit token の asid(grant を作るときの接続相手のもの) |
| `os.console_user` | ユーザーの切り替え | コンソールユーザーの変化で数える回数 |

通知で数える世代(`os.wake`、`os.screen_unlock`、`os.console_user`)は、デーモンの起動中しか数えられません。デーモンが再起動したら、それらを pin した grant はすべて失効します(間に何が起きたか分からないため)。起動時に読み直した grant では、これらの世代の観測値が無いか、pinned と observed が一致しないので `check` が偽になり、これも自動的に守られます(「保存」)。

`os.wake` と `os.screen_unlock` は `os.boot` に依存し、rule に置くときは `os.boot` も置きます(「項目の登録と depends」)。

### アプリが足す語彙

アプリ固有の語彙は `app.` の名前空間に置きます。名前空間は組み込み(`os.`、`time.` など)と `app.` だけで、アプリが自由に作ることはしません。評価するアプリは常に1つなので複数の名前空間は要らず、自由にすると今後 crate に足す名前空間とぶつかり得るためです。cw なら次のようなものです。

- `app.unlock`: vault を開いた回。手動ロックや vkey\_ttl 切れで終わる。
- `app.passphrase`: P を発行した回。Sealed になると終わる。

登録されていない名前を持つルールは、読み込み時にエラーにします(黙って無視すると、そこから作る grant が意図より長く効くため)。

## 条件、ルールの作成、保存

### 条件

状態型の条件は、評価のたびに真偽が変わり得るものです。scope と違い、偽になっても grant は失効せず、そのときだけ当たらなくなります。scope と同じく、組み込みに加えてアプリが `app.` の名前で足せます。

| 名前 | 真になるとき |
| --- | --- |
| `os.not_remote` | 接続相手のセッションが ssh 経由でない(祖先に sshd がいない、asid がコンソールのもの) |
| `os.console_active` | 画面がロックされていない |
| `os.tty` | 接続相手が指定の tty を持つ |
| `time.window` | 指定の曜日・時間帯 |

「自宅の Wi-Fi にいる間」のような場所の条件は、アプリが必要に応じて足します。

### 条件の実装: observe / pin / check / advance

寿命型(scope)、消費型(`uses`)、状態型は、同じ trait の関数で表します。外の状態(世代、画面ロックの状態など)を読むのは `observe` だけで、`pin` / `check` / `advance` は渡された値から結果を決めます。condition が触るのは自分の pin 値だけで、grant 全体は受け取りません。

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
    /// grant を作るときに 1 回。pin 値を返す。状態型は Ok(None)。寿命型で観測値が無ければ Err(PinError::Unobservable)。args が不正なら Err(PinError::InvalidArgs)
    fn pin(&self, args: Option<&Value>, obs: &Observed) -> Result<Option<Value>, PinError>;
    /// 判定。副作用なし
    fn check(&self, args: Option<&Value>, pinned: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> bool;
    /// 採用された grant にだけ呼ぶ。pin 値の新版。None なら変化なし
    fn advance(&self, pinned: Option<&Value>) -> Option<Value>;
}

enum PinError { Unobservable, InvalidArgs { reason: String } }
```

| 項目 | observe | pin | check | advance |
| --- | --- | --- | --- | --- |
| 世代(`os.boot`、`os.wake`、`app.unlock` …) | 今の世代 | observed の値(無ければ Err) | pinned == observed | None |
| `until` | None | args の時刻 | obs.now < pinned | None |
| `age` | None | obs.now + args の期間(`until` の pin 値になる) | obs.now < pinned | None |
| `uses` | None | args の N | pinned > 0 | pinned − 1 |
| 状態型(`os.console_active` 等) | 今の状態(観測するものがあれば) | None | observed / args / chain を見る | None |

- `ConditionKind` は Lifetime / State の 2 値です。世代、`until`、`age`、`uses` は Lifetime で、`uses` も一度 0 になれば戻りません。
- `EvalContext` は `now` と「key → `observe()` の結果」を持ちます。Policy が condition ごとに `Observed { now, value: ctx.observed(key) }` を組んで渡します(condition は自分の key を知らない)。
- 状態型の `check` には `args` が届くので、`time.window` の時間帯のような引数を判定に使えます。

### ルールの作成と強さの制約

ルールは、収集した情報から項目を選んで作ります(RuleBuilder)。承認画面で「このプロセスの署名で」「1つ上の祖先の Team ID で」と選ぶと、その値がそのまま条件になります。depends のある項目を選ぶと、根までの祖先も収集結果の値で埋まります(「項目の登録と depends」)。`SubjectBuilder` が subject を、`RuleBuilder` が静的な rule を作ります。

- `RuleBuilder::build()` は静的な `Rule` を返し、世代は記録しません。検査するのは depends の欠けと、強さ(クラス)と scope の制約(下記)です。制約は寿命型・消費型の condition の有無で判定します(pin 値はまだ無い)。
- pin は `Policy::grant(rule, ctx)` が行います。pin した grant をメモリ上の Policy にも入れて返します(署名と保存はアプリ)。`pin` が失敗した(`PinError`: 観測値が無い、引数が不正)とき、depends が欠けているときは `GrantError` です。

ルールの強さは、subject のうち対象プロセス自身への条件から決まります(決定の記録: [DR-0003](decisions/DR-0003-rule-strength-from-own-match.md))。

- 対象プロセス自身への条件は、`match` と、`tags` が指すタグの定義のうち自身への条件です。ルールの強さは、それらの項目のクラスのうち最も強いものです。
- `ancestors` の条件は数えません。祖先が強く特定されていても、対象は「その子孫なら何でも」で、対象自身は縛られないためです。`include_self` があっても同じです(「自身か祖先のどれか」であって、自身を pin していない)。
- 自身への条件が何も無い subject(`ancestors` だけ)は最も弱く、弱と同じ制約を受けます。
- タグを条件にしたときの強さは、タグの定義の subject を同じ規則で算出したものです。

build 時に次の制約を検査し、満たさなければエラーにします。制約はクラスで判定し、深さは使いません。制約の値はアプリが変えられます。

| ルールの強さ(クラス) | `allow` で許される scope(既定) |
| --- | --- |
| 強(署名、`process`) | 制限なし |
| 中(実行パス、責任プロセス) | `until` が 7 日以内、または世代の scope を含む |
| 弱(名前、cwd、argv、env) | 世代の scope(`os.login_session`、`app.unlock` など)を含む |

`uses` は制約の判定では世代の scope と同じ扱いです(寿命型で、一度切れれば戻らないため)。

`deny` には制約をかけません。弱い条件の拒否も、少なくとも安全側には働くからです。画面では、弱い条件を選んだ時点で「同じユーザーの他のプロセスも名乗れる条件です」と表示します。

### 保存

保存形は「一覧 1 本」と「grant 1 件ずつ」の 2 系統です。どちらも JSON で、保存と署名はアプリの責務です。

**一覧**(subject、tag、rule): crate は「一覧のバイト列と署名を受け取り、検証してから読む」ための入口(`Policy::load_verified`)を用意します。cw は一覧に D 側の鍵で署名し、同じ uid のプロセスが勝手に許可ルールを書き足せないようにします(PasskeyRegistry と同じ扱い)。

**grant**: grant はメモリ上に持ち、デーモンの意図しない終了に備えて、作成時と更新時に 1 件ずつ署名して永続化し、起動時に全部読み直します。crate は `Grant` の JSON の形と、2 つの入口を持ちます。

- `Policy::load_grant(bytes, sig, &verifier)`: 1 件のバイト列と署名を受け取り、検証してから `Grant` を返す。一覧と同じ検査(未登録の項目、depends の欠け・矛盾)をし、落ちればエラー。
- `Policy::add_grant(grant)`: 読み直した grant をメモリ上の Policy に入れる。


- 1 件ずつなので、`uses` の更新の書き込みは軽く済みます(実測は実装時のベンチで確かめる)。
- 起動時に読み直した grant のうち、デーモンの起動中しか数えられない世代(`os.wake` 等)を pin したものは、観測値が無いか、pinned と observed が一致しないので `check` が偽になり失効します。「デーモン再起動で失効」は自動的に守られます。
- 永続化先のディレクトリは、評価するデーモン以外(同じ uid の他プロセス)から書けない場所に置きます。書けると、使い切る前の grant ファイルを差し戻して `uses` を戻せるためです。置き場はアプリが決めます。

## API の骨格

収集、評価、rule の作成、grant の発行が入口です。語彙の拡張は、matcher の項目、scope、条件を同じ `register` で登録します。

```rust
// 収集(procline-macos)
let chain: ProcessChain = collect_peer(&stream, &CollectOptions {
    env: EnvPolicy::Allowlist(&["PWD", "SSH_CONNECTION"]),
    icon: true,
    max_ancestors: 32,
})?;
// chain.processes()[0] が対象、以降が祖先。chain.truncated
// p.signature_trust(): Platform / Notarized / DeveloperId / AdHoc / Unsigned / Invalid

// 強さ(procline-core の共有型)。どの項目がどのクラスかは Vocabulary が持ち、ProcessInfo の項目は持たない
enum Strength { Strong, Medium, Weak }               // クラス(連鎖ごとに 1 つ)
struct Depth(u8);                                    // 深さ(連鎖の根からの距離)
// Chain: depends で繋がった項目の集まり。Vocabulary が列挙し、項目を強度順に並べる(UI の選択肢)

// 語彙(procline-acl)
let mut vocab = Vocabulary::builtin();               // matcher の項目(signature_valid / team_id / signing_id / process / cwd など)、os.* の scope と条件、until / age / uses
// matcher の項目、寿命型、状態型を同じ register で足す。depends の key が未登録、または循環ならエラー
vocab.register(Item::matcher("app.workspace", depends: [...], |p, arg| ...))?;      // 照合する関数。根(depends なし)は Item::root_matcher(key, class, ...) でクラスを与える
vocab.register(Item::condition("app.unlock", depends: [], CwUnlock::new(&vault)))?;  // Condition を実装した値(寿命型)
// 状態型も同じ Item::condition(...) で register に渡す。寿命型か状態型かは Condition::kind が返す

trait Condition {
    fn kind(&self) -> ConditionKind;                 // Lifetime / State
    fn observe(&self) -> Option<Value>;              // 評価の最初に EvalContext::capture が 1 回呼ぶ
    fn pin(&self, args: Option<&Value>, obs: &Observed) -> Result<Option<Value>, PinError>;
    fn check(&self, args: Option<&Value>, pinned: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> bool;
    fn advance(&self, pinned: Option<&Value>) -> Option<Value>;
}

// 一覧(subject、tag、rule)の読み込みと、保存した grant の読み直し
let mut policy = Policy::load_verified(bytes, sig, &verifier, &vocab)?;  // 未登録の項目、タグの循環、depends の欠け・矛盾はエラー
let saved = policy.load_grant(grant_bytes, grant_sig, &verifier)?;  // grant 1 件を検証し、語彙と照合する(未登録の項目、depends の欠け・矛盾はエラー)
policy.add_grant(saved);                             // メモリ上の Policy に入れる

// 評価
let tagged = policy.tag(&chain);                     // 各プロセスに付いたタグ(画面の表示にも使う)
let decision = policy.evaluate(&tagged, &Target::key("github/token"), &ctx);  // 採用された grant に advance をかける
if let Some(grant) = &decision.updated_grant {
    // 署名して永続化し、書けてから値を渡す
}
let shown = policy.explain(&tagged, &Target::key("github/token"), &ctx);      // advance なし(trace の表示用)

pub struct Decision {
    pub effect: Effect,
    pub grant_id: Option<String>,        // 採用された grant。既定の effect なら None
    pub trace: Trace,
    pub updated_grant: Option<Grant>,    // advance で変わった grant の新版。explain では常に None
}

// 承認画面から rule を作る
let subject = SubjectBuilder::from(&tagged, 0)       // 対象プロセスの項目から選ぶ(tagged が語彙への参照を持つ)
    .pin("signing_id")                               // 祖先の team_id / signature_valid も収集結果の値で入る
    .tag("claude-pj1")
    .build()?;
let rule = RuleBuilder::new(subject, &vocab)
    .targets(["key:k1"])
    .condition(ConditionUse::with_args("age", json!("1h")))
    .condition(ConditionUse::named("os.boot"))      // 記号のまま。世代は grant を作るときに pin する
    .allow()
    .build()?;                                       // 静的な Rule。depends の欠けと、強さ(クラス)と scope の制約を検査

// rule を適用して grant を作る(各 condition の pin。保存した rule も同じ入口)
let grant = policy.grant(&rule, &ctx)?;              // pin して id を付け、メモリ上の Policy にも入れて返す。GrantError: pin の失敗(Unobservable / InvalidArgs)、depends の欠け
// アプリは grant を署名して永続化する
```

- `EvalContext::capture` は評価の開始時に現在時刻と各 condition の `observe()` の結果を一度だけ取り、評価の途中で値が変わらないようにします。Policy はそこから condition ごとに `Observed` を組んで `pin` と `check` に渡します。テストでは全部を差し替えられます。
- `uses` は `evaluate` の中で、採用された grant の `advance` で減ります。アプリは `decision.updated_grant` を署名して永続化し、書けてから値を渡します。

---

裁定待ちは [docs/QUESTIONS.md](QUESTIONS.md)、作業は `docs/issue/` にあります。
