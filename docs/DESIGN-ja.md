# 接続元プロセスの情報収集と ACL 設計



## 概要

プロセスとその祖先の情報を集め、その情報に対するアクセス制御(ACL)を定義・評価するための crate 群です。pam-passkey の承認画面と、cw の ACL 照合・後付けの許可ルールが同じものを必要とするので、両者から切り出して共通の部品にします。収集の入口は UNIX ドメインソケットの接続相手(audit token)が主ですが、中心はあくまでプロセスで、接続相手であることには依存しません。

**利用者と使い方**

- **pam-passkey**: 呼び出し元のプロセスとその祖先を集め、承認画面に表示する。照合は使わない。
- **cw**: 接続相手を集め、キーごとの ACL で許可・拒否・再認証を決める。承認画面から後付けでルールを作る。

**設計の柱**

1. **識別は pid より強いもので**: 接続相手は audit token、祖先はプロセスごとに一意な ID で特定し、pid の再利用で取り違えない。
2. **表示と照合を同じ型の上に置く**: 画面で見ている情報から、そのままルールを作れるようにする。
3. **項目ごとに強さを持つ**: 同じ uid のプロセスが偽れる項目(名前、cwd、argv)と、偽れない項目(コード署名)を型で区別し、弱い条件だけの許可を制限する。
4. **語彙をアプリが足せる**: scope(ルールの寿命)と条件は、組み込みの語彙に加えて、アプリ固有のものを登録できるようにする。

**範囲**

macOS を先に実装し、Linux は後から足せる形にします。crate の名前は未定で、本書では仮称を使います。

## 構成

収集は OS ごとの crate に実装し、型と照合は OS に依存しない core に置きます。アプリが使うのは入口の procinfo だけで、これがビルドターゲットに応じて OS ごとの crate を読み込みます(`[target.'cfg(target_os = "macos")'.dependencies]`)。core 自体を入口にしないのは、OS ごとの crate が core の型に依存するので、core から読むと循環するためです。ACL は型だけに依存するので、Linux の収集を足してもそのまま使えます。

| crate(仮称) | 中身 | 依存 |
| --- | --- | --- |
| procinfo | 入口。core の型と、ビルドターゲットの OS の collect を再公開する | core、OS ごとの crate(target ごとに片方だけ) |
| procinfo-core | 収集結果の型、署名の信頼度の判定、表示用の無害化、env の方針と伏せ字、JSON の形 | なし(OS 非依存) |
| procinfo-macos | 接続相手と祖先の収集、コード署名の検証、アイコン、OS の世代(起動、スリープ、画面ロックなど)の提供 | core、Security framework、AppKit |
| proc-acl | ルールの型、評価、scope と条件の語彙、拡張の登録、ルールの作成 | core |

アプリ(cw、pam-passkey)は、必要なものだけを使います。pam-passkey は収集だけ、cw はすべてです。cw 固有の語彙(`app.unlock` など)は cw 側で定義して、`app.` の名前で proc-acl に登録します。

## 収集する情報

収集結果は、対象のプロセス(多くは接続相手)を先頭に launchd までの祖先を並べた列です。各プロセスが下の項目を持ち、取れなかった項目は空にします。照合の強さは「同じ uid のプロセスがその値を偽れるか」で決めます。

### 識別子

| 項目 | 取り方(macOS) | 強さ | 備考 |
| --- | --- | --- | --- |
| audit token(接続相手) | `getsockopt(LOCAL_PEERTOKEN)` | 強 | 公開 API。pid、pidversion、uid、asid を含む |
| unique\_id / parent\_unique\_id | `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` の `p_uniqueid`、`p_puniqueid` | 強 | 起動ごとに一意な 64bit ID。祖先を確実に辿れる。`#ifdef PRIVATE` の SPI なので、取れなければ pid と起動時刻の組に落とす |
| pid、起動時刻 | `proc_pidinfo(PROC_PIDTBSDINFO)` | — | 表示用。照合には単独で使わない |
| asid(audit session ID) | audit token | 強 | ログインや ssh のセッションごとに別。`login_session` scope に使う |

### プロセスの属性

| 項目 | 取り方(macOS) | 強さ |
| --- | --- | --- |
| uid、gid、所属グループ(照合は数値。表示用に名前も持つ。1つの ID に名前が複数あり得るので列で持つ) | `LOCAL_PEERCRED`、audit token | 強 |
| コード署名(識別子、Team ID、cdhash、署名者の証明書チェーン、ad-hoc・hardened runtime・platform binary の別、entitlements、公証) | `SecCodeCopyGuestWithAttributes`(接続相手は audit token、祖先は pid)、`SecCodeCheckValidity`、`SecCodeCopySigningInformation` | 強(検証が通ったときだけ) |
| 実行パス | `proc_pidpath` | 中(ユーザーが書き換えられない場所なら) |
| app bundle(bundle ID、版) | 実行パスから `.app` を遡り Info.plist を読む | 弱(署名と組でなければ) |
| 責任プロセス | `responsibility_get_pid_responsible_for_pid`(私的 API) | 中 |
| プロセス名、argv、cwd、tty | `KERN_PROCARGS2`、`PROC_PIDVNODEPATHINFO`、`kinfo_proc` | 弱 |
| env | `KERN_PROCARGS2`(同じ uid か root のみ) | 弱(方針は後述) |
| アイコン | `NSWorkspace.icon(forFile:)` を 64px PNG に縮小 | 表示専用(照合に使わない) |

SPI や私的 API に依存する項目は、取れなければ空にするだけで、収集全体は止めません。

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
4. 祖先は途中で終了していることがある(親が先に終了し launchd に引き取られた場合など)。その場合は「ここで途切れた」と分かる形で列を終える。

## ACL ルールの形と評価

ACL は、名前を付けて使い回せる4つの部品でできています。どれも単体で意味を持ち、設定ファイルにも承認画面にも同じ形で現れます。

| 部品 | 中身 | 使い道 |
| --- | --- | --- |
| subject | 1つのプロセスへの条件。祖先への条件を入れ子で持てる | ルールの対象、タグの定義 |
| tag | 名前の付いた subject。当たるプロセスにタグが付く | 承認画面での表示、ほかの subject の条件 |
| rule | 誰が(subject)、何に(targets)、いつまで・どんなときに(conditions)、どうなるか(effect) | 評価 |
| preset | scope の世代を記録する前のルール | 「いつもの許可」を passkey 1回で適用 |

どのルールにも当たらなければ既定の effect(普通は `ask`)になり、拒否は許可より優先します。

### subject

subject は1つのプロセスへの条件で、接続相手か祖先かを区別しません。祖先への条件は `ancestors` の中に subject を入れ子で書きます。入れ子の subject もまた `ancestors` を持てるので、「A の下の B の下の C」のような何層の形でも組み立てられます。

```json
{
  "match": { "signing_id": "com.anthropic.claude-code", "cwd": "~/src/pj1/**" },
  "ancestors": [
    { "any": { "match": { "team_id": "ABCDE12345", "signing_id": "com.googlecode.iterm2" } } }
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
        "match": { "signing_id": "com.anthropic.claude-code", "cwd": "~/src/pj1/**" },
        "ancestors": [{ "any": { "match": { "team_id": "ABCDE12345" } } }]
      },
      "include_self": true
    }]
  }
}
```

これでルールの subject は `{"tags": ["claude-pj1"]}` だけで済みます。画面では、タグが付いたプロセスのすべてにタグを出します。そのタグを認可したときに通るプロセスと、画面でタグが付いているプロセスがそのまま一致します。

- タグを条件にした場合の強さは、タグの定義の subject の強さと同じです。
- タグの定義もルールと同じ署名付きの一覧に入れます。同じ uid のプロセスが定義を書き換えられると、そのタグを条件にしたルールが全部広がるためです。
- タグの定義が別のタグを参照してもよく、循環は読み込み時にエラーにします。

### rule

```json
{
  "id": "r-01",
  "effect": "allow",
  "subject": { "tags": ["claude-pj1"] },
  "targets": ["key:k1"],
  "conditions": ["os.boot", "app.unlock", { "age": "1h" }, "os.not_remote"],
  "created_from": "approval-ui"
}
```

| 要素 | 中身 |
| --- | --- |
| effect | `allow`(無認証で通す)、`deny`(拒否)、`ask`(アプリの再認証を求める) |
| subject | 上の subject。名前で参照してもよい |
| targets | ルールが効く対象(キーの glob、タグ)。対象の語彙はアプリが決める。不要なアプリは省略する |
| conditions | 条件の名前の列(すべて AND)。寿命型と状態型があり、どちらかは語彙が決める(下記) |

条件には2つの種類があり、どちらかは語彙に登録するときに決まります。ルールには `conditions` に名前を並べるだけで、種類ごとに置き場を分けません(すべて AND)。

| 種類 | 偽になったとき | 例 |
| --- | --- | --- |
| 寿命型(scope) | 戻らない。そのルールは永久に失効する | `os.boot`、`app.unlock`、`age`、`until` |
| 状態型 | 偽の間だけ当たらない | `os.not_remote`、`os.console_active`、`time.window` |

種類はルールを書く人ではなく語彙が知っているので、承認画面や trace では各条件の横に種類を出し、読む人にどちらの意味かを見せます。保存するときは、寿命型の条件にその時点の世代を記録した形に展開します(`age` は時刻に直す)。

### preset

preset は、scope の世代を記録する前のルールに名前を付けたものです。適用すると、その時点の世代を記録し、`age` を時刻に直して、普通のルールとして追加します。

```json
{
  "preset": "pj1-claude-usual",
  "rule": {
    "effect": "allow",
    "subject": { "tags": ["claude-pj1"] },
    "targets": ["key:k1"],
    "conditions": ["os.boot", "app.unlock", { "age": "1h" }]
  }
}
```

承認画面に preset の一覧を出し、選んで passkey を1回通せば、いつもの許可をその場で作れます。preset の追加と変更も、ルールと同じ署名付きの一覧に入れます。

### 名前と参照

subject、tag、preset、条件の組は、どれも名前を付けて一覧に置き、ほかから名前で参照できます。承認画面で作った subject を名前付きで保存すれば、次からはタグの定義にも別のルールにも使い回せます。

参照は文字列で書きます(`{"ref": "…"}` のような包みは使いません)。

**決定の理由**: 参照が現れる場所ごとに、何を指すかが1つに決まっていて、種類が混ざる場所がないためです。

- `tags` の中はタグ名だけ。
- subject の位置(ルールの `subject`、`ancestors` の `any` などの中身)は、文字列なら subject 名、オブジェクトならその場の定義。型で区別できる。
- preset は適用するときに名前で指すだけで、一覧の中からは参照されない。
- `conditions` の要素は、文字列も `{"age": "1h"}` のような引数付きも、どちらも語彙の名前。

包みを入れても、書く量と読む手間が増えるだけで、曖昧さは減りません。この前提が崩れる(同じ場所に種類の違う名前が入り得る形を足す)ときにだけ、見直します。

### matcher

| 形 | 使える項目 |
| --- | --- |
| 完全一致 | すべて |
| glob | パス、識別子、bundle ID、プロセス名、cwd |
| 正規表現 | パス、argv |
| 数値の範囲 | uid |

`cdhash`、`unique_id`、`team_id` は完全一致だけにします。署名の条件は、署名の検証が通ったときだけ一致とみなします。ad-hoc 署名は Team ID が空なので、Team ID の条件には決して一致しません。

### 評価

1. scope が切れたルールを除く(切れたルールは掃除の対象にする)。
2. targets が対象に当たらないルールを除く。
3. subject を照合する。`deny` が1つでも当たれば拒否。
4. `allow` が当たれば許可。
5. `ask` が当たれば、または何も当たらなければ、既定の effect。

評価の結果は effect だけでなく、どのルールが効いたかと、各条件がどの項目に一致したか(trace)を返します。画面の「なぜ通ったか、なぜ聞かれたか」に使います。

## scope: ルールの寿命

寿命型の条件(以下 scope)は「今の世代(epoch)を返す関数」で定義します。ルールを作るときにその時点の世代を記録し、評価のたびに今の世代と比べて、違えばそのルールは永久に失効します。「解錠している間」ではなく「この解錠の回の間」になるので、一度ロックして解錠し直してもルールが生き返りません。

この形にすると、どの scope も「一度終われば戻らない」ことが自動的に保証され、アプリが足すのも「世代を返す関数」1つで済みます。世代を判定できない(関数が値を返せない)ときは失効とみなします。安全側に倒れるためです。

scope は複数並べられ、すべてが生きている間だけルールが効きます(AND)。「24時間、ただし再起動まで」のように組み合わせます。

### 組み込みの語彙

| 名前 | 終わる時点 | 世代の取り方(macOS) |
| --- | --- | --- |
| `until` | 指定の時刻 | 時計(世代ではなく時刻で判定) |
| `age` | 作成からの経過時間 | 作成時に `until` に変換して保存 |
| `uses` | N 回使ったら | ルールごとの回数(世代ではなくカウンタ) |
| `os.boot` | 再起動 | `kern.bootsessionuuid` |
| `os.wake` | スリープ、ハイバネーション | IOKit の電源通知で数える起床の回数 |
| `os.screen_unlock` | 画面ロック、スクリーンセーバー | 画面のロック解除の通知で数える回数 |
| `os.login_session` | ログアウト、ssh の切断 | audit token の asid(作成時の接続相手のもの) |
| `os.console_user` | ユーザーの切り替え | コンソールユーザーの変化で数える回数 |
| `process` | 指定プロセスの終了 | 接続相手または祖先の unique\_id。「このターミナルのタブのシェルが生きている間」が書ける |

通知で数える世代(`os.wake`、`os.screen_unlock`、`os.console_user`)は、デーモンの起動中しか数えられません。デーモンが再起動したら、それらに紐づくルールはすべて失効させます(間に何が起きたか分からないため)。世代の値にはデーモンの起動 ID を含めれば、これも自動的に守られます。

### アプリが足す語彙

アプリ固有の語彙は `app.` の名前空間に置きます。名前空間は組み込み(`os.`、`time.` など)と `app.` だけで、アプリが自由に作ることはしません。評価するアプリは常に1つなので複数の名前空間は要らず、自由にすると今後 crate に足す名前空間とぶつかり得るためです。cw なら次のようなものです。

- `app.unlock`: vault を開いた回。手動ロックや vkey\_ttl 切れで終わる。
- `app.passphrase`: P を発行した回。Sealed になると終わる。

登録されていない名前を持つルールは、読み込み時にエラーにします(黙って無視すると、意図より長く効くルールになるため)。

## 条件、ルールの作成、保存

### 条件

状態型の条件は、評価のたびに真偽が変わり得るものです。scope と違い、偽になってもルールは失効せず、そのときだけ当たらなくなります。scope と同じく、組み込みに加えてアプリが `app.` の名前で足せます。

| 名前 | 真になるとき |
| --- | --- |
| `os.not_remote` | 接続相手のセッションが ssh 経由でない(祖先に sshd がいない、asid がコンソールのもの) |
| `os.console_active` | 画面がロックされていない |
| `os.tty` | 接続相手が指定の tty を持つ |
| `time.window` | 指定の曜日・時間帯 |

「自宅の Wi-Fi にいる間」のような場所の条件は、アプリが必要に応じて足します。

### ルールの作成と強さの制約

ルールは、収集した情報から項目を選んで作ります(RuleBuilder)。承認画面で「このプロセスの署名で」「1つ上の祖先の Team ID で」と選ぶと、その値がそのまま条件になります。

ルールの強さは、subject の中で最も強い条件で決まります。build 時に次の制約を検査し、満たさなければエラーにします。制約の値はアプリが変えられます。

| ルールの強さ | `allow` で許される scope(既定) |
| --- | --- |
| 強(署名、unique\_id) | 制限なし |
| 中(実行パス、責任プロセス) | `until` が 7 日以内、または世代の scope を含む |
| 弱(名前、cwd、argv、env) | 世代の scope(`process`、`os.login_session`、`app.unlock` など)を含む |

`deny` には制約をかけません。弱い条件の拒否も、少なくとも安全側には働くからです。画面では、弱い条件を選んだ時点で「同じユーザーの他のプロセスも名乗れる条件です」と表示します。

### 保存

ルールの一覧は JSON で、保存と保護はアプリの責務です。crate は「一覧のバイト列と署名を受け取り、検証してから読む」ための入口を用意します。cw は一覧に D 側の鍵で署名し、同じ uid のプロセスが勝手に許可ルールを書き足せないようにします(PasskeyRegistry と同じ扱い)。

## API の骨格

収集、評価、ルールの作成の3つが入口です。語彙の拡張は、scope と条件で同じ形の trait を使います。

```rust
// 収集(procinfo-macos)
let chain: ProcessChain = collect_peer(&stream, &CollectOptions {
    env: EnvPolicy::Allowlist(&["PWD", "SSH_CONNECTION"]),
    icon: true,
    max_ancestors: 32,
})?;
// chain.processes()[0] が対象、以降が祖先。chain.truncated
// 各 ProcessInfo は項目ごとに Strength(Strong / Medium / Weak) を持つ
// p.signature.trust(): Platform / Notarized / DeveloperId / AdHoc / Unsigned / Invalid

// 語彙の拡張(proc-acl)
trait EpochProvider {
    fn name(&self) -> &str;                          // "app.unlock"
    fn current(&self, ctx: &EvalContext) -> Option<Epoch>;
}
trait Condition {
    fn name(&self) -> &str;                          // "os.not_remote"
    fn eval(&self, chain: &ProcessChain, args: &Value, ctx: &EvalContext) -> bool;
}

let mut vocab = Vocabulary::builtin();               // os.* と until / age / uses / process
vocab.register_app_epoch("unlock", CwUnlockEpoch::new(&vault));  // app.unlock として登録

// 一覧(subject、tag、rule、preset)の読み込みと評価
let policy = Policy::load_verified(bytes, sig, &verifier, &vocab)?;  // 未登録の語彙、タグの循環はエラー
let tagged = policy.tag(&chain);                     // 各プロセスに付いたタグ(画面の表示にも使う)
let decision = policy.evaluate(&tagged, &Target::key("github/token"), &ctx);
// decision.effect / decision.matched_rule / decision.trace

// 承認画面からルールを作る
let subject = SubjectBuilder::from(&tagged, 0)       // 対象プロセスの項目から選ぶ
    .tag("claude-pj1")
    .build()?;
let rule = RuleBuilder::new(subject, &vocab)
    .targets(["key:k1"])
    .condition(Cond::age(Duration::from_secs(3600)))
    .condition(Cond::named("os.boot"))              // 寿命型なので今の世代をここで記録
    .allow()
    .build()?;                                       // 強さと scope の制約を検査

// preset を適用する(世代の記録と age の時刻化をして普通のルールにする)
let rule = policy.instantiate_preset("pj1-claude-usual", &ctx)?;
```

- `EvalContext` は現在時刻と世代の値を評価の開始時に一度だけ取り、評価の途中で値が変わらないようにします。テストでは全部を差し替えられます。
- `uses` の回数は評価では増やさず、アプリが「実際に値を渡した」ときに `policy.record_use(rule_id)` で増やします。

## 未決事項

- [x] subject、tag、preset の名前の参照の書き方(`{"ref": "…"}` か、文字列だけか)。 → 文字列だけ。置き場所で種類が決まる(`tags` の中はタグ名、`subject` に文字列があれば subject 名)。
- [ ] crate の名前(候補を出すときは crates.io と GitHub の衝突を確認する)。
- [x] `p_uniqueid` と責任プロセスの私的 API を、実機でどの macOS の版まで確かめるか。 → 自分が使う最新版だけ。取れなければ空にするだけなので、古い版で壊れても安全側。
- [x] 公証の有無をどう判定するか(`SecStaticCodeCheckValidity` に公証の requirement を渡すか)と、そのコスト。 → requirement `notarized` を渡して真偽で判定する。重いことがあるので、結果は cdhash でキャッシュする。
- [x] env の伏せ字の既定の規則の中身。 → 対象の判定と伏せ方を差し替え可能な関数にし、既定は既存のリストを参考に決める(本文の env の節)。
- [x] 「署名者が変わった」の判定に使う、bundle ID と Team ID の組の記録を、crate に持たせるかアプリに任せるか。 → 持たない。ルールは署名者で照合するので、署名者が変われば自然に外れる。
- [x] 強さの制約の既定値(中のルールの `until` の上限など)。 → アプリに任せる。crate は検査の仕組みだけを持つ。
- [x] Linux 版の収集(SO\_PEERCRED、pidfd、/proc)と、署名に相当する項目をどう扱うか。 → macOS と同じやり方。今は使わないので優先度は低い。
