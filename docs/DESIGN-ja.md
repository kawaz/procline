# 接続元プロセスの情報収集と ACL 設計

## 概要

プロセスとその祖先の情報を集め、その情報に対するアクセス制御(ACL)を定義・評価するための crate 群です。pam-passkey の承認画面と、cw の ACL 照合・後付けの許可ルールが同じものを必要とするので、両者から切り出して共通の部品にします。収集の入口は UNIX ドメインソケットの接続相手(audit token)が主ですが、中心はあくまでプロセスで、接続相手であることには依存しません。

**利用者と使い方**

- **pam-passkey**: 呼び出し元のプロセスとその祖先を集め、承認画面に表示する。照合は使わない。
- **cw**: 接続相手を集め、キーごとの ACL で許可・拒否・再認証を決める。承認画面から後付けでルールを作る。

**設計の柱**

1. **識別は pid より強いもので**: 接続相手は audit token、祖先はプロセスごとに一意な ID で特定し、pid の再利用で取り違えない。
2. **表示と照合を同じ型の上に置く**: 画面で見ている情報から、そのままルールを作れるようにする。
3. **項目ごとに強さを持つ**: 承認した個体・コードを特定する条件(コード署名、個体の識別)と、同じ uid なら誰でも満たせる条件(名前、cwd、argv、uid)を、項目を登録するときにクラスで区別し、特定しない条件だけの許可にアプリが制約をかけられるようにする。制約の値はアプリが与え、crate は検査の仕組みだけを持つ。
4. **語彙をアプリが足せる**: matcher の項目、scope(grant の寿命)、条件は、組み込みの語彙に加えて、アプリ固有のものを同じ形で登録できるようにする。

**範囲**

macOS を先に実装し、Linux は後から足せる形にします。Linux の収集(`SO_PEERCRED`、pidfd、`/proc`)も同じ型の上に同じやり方で足します。

**脅威モデルの前提**

守る相手は、同じ uid の別プロセスです。root と、評価するアプリ自身のなりすましは範囲外です(cw の設計文書と同じ)。

- 署名は code の同一性を示すだけで、その code が何を実行するか(インタプリタが読むスクリプト、AI エージェントの操作)は表しません。
- 署名由来の field は、署名の identity がそのプロセスの code を表している前提で使います。hardened runtime の無い署名済バイナリは同じ uid のプロセスが乗っ取れますが、乗っ取られたプロセスの識別はこの crate の範囲外で、クラスの判定には使いません。
- 一覧と grant の保存先と署名鍵の保護(同じ uid のプロセスから使えない鍵)はアプリの責務です。cw は Secure Enclave の鍵で担います。

## 構成

収集は OS ごとの crate に実装し、型と照合は OS に依存しない core に置きます。アプリが使うのは入口の procline だけで、これがビルドターゲットに応じて OS ごとの crate を読み込みます(`[target.'cfg(target_os = "macos")'.dependencies]`)。core 自体を入口にしないのは、OS ごとの crate が core の型に依存するので、core から読むと循環するためです。ACL は型だけに依存するので、Linux の収集を足してもそのまま使えます。`os.*` の語彙は OS ごとの crate が `procline_acl::Item` として提供するので、procline-macos は procline-acl にも依存します(procline-acl は core だけに依存するので循環しません)。名前は process lineage(プロセスとその祖先の列)から取っています(決定の記録: [DR-0001](decisions/DR-0001-crate-naming.md))。

| crate | 中身 | 依存 |
| --- | --- | --- |
| procline | 入口。core の型と、ビルドターゲットの OS の collect を再公開する | core、OS ごとの crate(target ごとに片方だけ) |
| procline-core | 収集結果の型、強さのクラスの型(`Strength`)、署名の信頼度の判定、表示用の無害化、env の方針と伏せ字、JSON の形 | なし(OS 非依存) |
| procline-macos | 接続相手と祖先の収集、コード署名の検証、アイコン、`os.*` の語彙の提供(`procline_macos::os_items()`) | core、procline-acl、Security framework、AppKit |
| procline-acl | rule と grant の型、評価、語彙(matcher の項目、scope、条件)とその登録、OS 非依存の組み込みの語彙、rule の作成と grant の発行 | core |

アプリ(cw、pam-passkey)は、必要なものだけを使います。pam-passkey は収集だけ、cw はすべてです。cw は `procline_macos::os_items()` の `os.*` の項目を `Vocabulary::register` で登録します。cw 固有の語彙(`app.unlock` など)は cw 側で定義して、`app.` の名前で procline-acl に登録します。

## 収集する情報

収集結果は、対象のプロセス(多くは接続相手)を先頭に launchd までの祖先を並べた列です。列は収集した起動の boot UUID(`kern.bootsessionuuid`、`ProcessChain.boot_uuid`)も持ちます。各プロセスが下の項目を持ち、取れなかった項目は空にします。表の「強さ」は、その項目を照合に使ったときのクラスで、その条件が承認した個体・コードをどれだけ特定するかで決まります(「強さ: クラスと深さ」)。

### 識別子

| 項目 | 取り方(macOS) | 強さ | 備考 |
| --- | --- | --- | --- |
| audit token(接続相手) | `getsockopt(LOCAL_PEERTOKEN)` | 強 | 公開 API。pid、pidversion、uid、asid を含む |
| unique\_id / parent\_unique\_id | `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` の `p_uniqueid`、`p_puniqueid` | 強 | 起動ごとに一意な 64bit ID。祖先を確実に辿れる。`#ifdef PRIVATE` の SPI なので、取れなければ pid と起動時刻の組に落とす |
| pid、起動時刻 | `sysctl(KERN_PROC_PID)` の `kinfo_proc`(uid を問わず読める) | 強(組で) | 組で識別子になる(unique\_id が無いときの識別)。audit token の pidversion は exec で変わるので、接続後に exec した相手の検出に使える |
| asid(audit session ID) | audit token | 強 | ログインや ssh のセッションごとに別。起動ごとに再利用されるので、`os.login_session` の pin 値に boot UUID と組で使う |

これらの識別子は収集の内部の分類で、ルールの語彙では audit token、unique\_id、pid と起動時刻が個体識別の `process` 1 項目に畳まれ(「matcher」)、asid は `os.login_session` の pin 値(`{boot_uuid, asid}`)として内部で使われるだけで語彙には出ません。

### プロセスの属性

| 項目 | 取り方(macOS) | 強さ |
| --- | --- | --- |
| uid、gid、所属グループ(照合は数値。表示用に名前も持つ。1つの ID に名前が複数あり得るので列で持つ) | `LOCAL_PEERCRED`、audit token(接続相手)、`kinfo_proc`(祖先。所属グループは `cr_groups` の最大 16 件で、先頭が実効 gid) | 弱 |
| コード署名(識別子、Team ID、cdhash、署名者の証明書チェーン、ad-hoc・hardened runtime・platform binary の別、entitlements、公証) | `SecCodeCopyGuestWithAttributes`(接続相手は audit token、祖先は pid)、`SecCodeCheckValidity`、`SecCodeCopySigningInformation` | 強(検証が通ったときだけ) |
| 実行パス。所有者(root か)と利用者の書き込み可否も取る(クラスの判定に使う。ファイル自体かパス上のいずれかのディレクトリに書ければ「書ける」) | `proc_pidpath` | 強(root 所有で利用者が書けない場所)、中(利用者が書ける場所) |
| 実行ファイルの digest | 実行パスのファイルの内容の sha256 | 中(パスと同じ。exec 後にファイルを置き換えられると稼働中の像と食い違う。Linux は `/proc/<pid>/exe` が稼働中の inode を指すので実質強い) |
| app bundle(bundle ID、版) | `SecCodeCopySigningInformation` の `kSecCodeInfoPList`(署名で封印された Info.plist)から取り、`Signature.bundle_id` に持つ(照合に使う)。実行パスから `.app` を遡って読む `ProcessInfo.bundle` は表示用 | 強(`binary` の field。`team_id`・`signing_id` と組) |
| 責任プロセス | `responsibility_get_pid_responsible_for_pid`(私的 API)。pid でなく個体の識別(`ProcessInfo.responsible: Option<ProcessIdentity>`)で持つ | 中 |
| プロセス名、argv、cwd、tty | `kinfo_proc`(名前と tty)、`KERN_PROCARGS2`(argv)、`PROC_PIDVNODEPATHINFO`(cwd)。argv と cwd は同じ uid か root のみ | 弱 |
| env | `KERN_PROCARGS2`(同じ uid か root のみ。platform binary の env は `KERN_PROCARGS2` が返さないので取れず、空でなく `None` になる) | 表示専用(伏せた後の値しか持たないので照合に使えない。方針は後述) |
| アイコン | `NSWorkspace.icon(forFile:)` を 64px PNG に縮小 | 表示専用(照合に使わない) |

BSD の情報(pid、ppid、uid / gid、起動時刻、名前、tty)は、`sysctl(KERN_PROC_PID)` の `kinfo_proc` から取ります。uid を問わず読めるので、別 uid の祖先(launchd など)も辿れます。`proc_pidinfo(PROC_PIDTBSDINFO)` は別 uid のプロセスには `EPERM` で失敗するので、同じ uid のときに名前を 32 バイトの `pbi_name` で補うのにだけ使います(`kinfo_proc` の `p_comm` はそれより短い)。

SPI や私的 API に依存する項目は、取れなければ空にするだけで、収集全体は止めません。実機では自分が使う最新の macOS だけで確かめます。古い版で取れなくても空になるだけで、安全側に倒れるためです。

## 署名の信頼度と警告

アイコンや名前は「何に見えるか」、署名は「実際は誰か」です。core は各プロセスに署名の信頼度を付け、両者が食い違うときに目立たせるための判定を提供します。pam-passkey の承認画面も cw のルール作成画面も、この判定をそのまま表示します。

| 信頼度 | 状態 | 表示 |
| --- | --- | --- |
| platform | Apple のプラットフォームバイナリ | 警告なし |
| app\_store | App Store 配布(Apple 署名、公証チケット無し) | 警告なし |
| notarized | Developer ID 署名で公証済み | 警告なし(署名者名と Team ID を併記) |
| developer\_id | Developer ID 署名だが公証なし | ⚠️ 未公証 |
| adhoc | ad-hoc 署名(Team ID なし) | ⚠️ ad-hoc |
| unknown | 有効な署名だが、Apple のルートへの連鎖を確かめられない(自作や第三者の証明書、または評価できなかった) | ⚠️ 署名者を確かめられない |
| unsigned / invalid | 署名なし、または検証に失敗 | ⛔ 署名なし / 署名が無効 |

platform、app\_store、notarized、developer\_id は、署名の証明書チェーンが Apple のルートに連鎖していること(`Signature.apple_anchored`。requirement `anchor apple generic` を渡した `SecCodeCheckValidity` の結果)を前提にします。platform binary の印も証明書の名前も署名者が書けるので、連鎖を確かめられない署名は unknown です。判定は、未署名 → 無効 → ad-hoc → Apple に連鎖しない(評価できなかったときも含む)なら unknown → platform → App Store → Developer ID(公証済みなら notarized)の順です。ad-hoc 署名は連鎖を持たず、OS の platform binary は ad-hoc で署名されていないので、ad-hoc を連鎖の判定より先に置いても OS のバイナリに誤った警告は出ません。証明書の種別は leaf の証明書の subject summary の文字列(`Apple Mac OS Application Signing` なら App Store、`Developer ID Application: …` なら Developer ID)で判定しています(暫定。それ以外の Apple の証明書は developer\_id に倒す)。

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

伏せ字は core に置き、2つの関数として差し替えられるようにします(`Redaction` を `CollectOptions.redaction` で渡す)。対象の判定 `Fn(&str) -> bool`(変数名を受け取る)と、伏せ方 `Fn(&str, &str) -> String`(名前と値を受け取る)です。既定は、名前に `TOKEN`、`SECRET`、`PASS`、`KEY`、`CRED`、`AUTH`、`COOKIE`、`SESSION`、`PRIVATE`、`CERT`、`SALT`、`PWD`、`OTP` を含む変数(大文字小文字を区別しない)の値を `[redacted]` に置き換え、名前だけ残します。語の選び方は Rails の `filter_parameters` や Sentry の既定の伏せ字など、既存のリストに合わせます。`PWD` は作業ディレクトリの変数も巻き込みますが、作業ディレクトリは cwd の項目で取れるので困りません。外したいときは、既定の判定関数を包んで PWD を除く関数に差し替えます。収集結果の env は伏せた後の値しか持たないので、照合には使えません(表示専用)。

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
4. 祖先は途中で終了していることがある。その場合は「ここで途切れた」と分かる形で列を終える。親が終了して launchd に付け替えられたプロセスは、ppid が 1 になっても `p_puniqueid` は元の親の値のままなので、列はそこで `ancestor_exited` として終わる(launchd を親として繋ぐと、実在しない親子関係になる)。

## ACL ルールの形と評価

ACL は4つの部品でできています。subject、tag、rule は名前を付けて使い回せる静的な定義で、署名付きの一覧に入り、設定ファイルにも承認画面にも同じ形で現れます。grant は rule を実際のプロセスに適用して subject の placeholder と条件を具体値に pin したもので、評価が見るのはこれだけです。

| 部品 | 中身 | 使い道 |
| --- | --- | --- |
| subject | 1つのプロセスへの条件。祖先への条件を順序付きの列で持てる | ルールの対象、タグの定義 |
| tag | 名前の付いた subject。当たるプロセスにタグが付く | 承認画面での表示、ほかの subject の条件 |
| rule | 誰が(subject)、何に(targets)、いつまで・どんなときに(conditions)、どうなるか(effect)。conditions は記号のまま | grant の元。「いつもの許可」を承認画面で選んで passkey 1回で適用 |
| grant | rule を承認の瞬間の接続相手に適用し、subject の placeholder を実値に、各 condition を具体値に pin したもの | 評価 |

どの grant にも当たらなければ既定の effect(アプリが `Policy::load_verified` の `default_effect` で与える)になり、拒否は許可より優先します。

### subject

subject は1つのプロセスへの条件で、接続相手か祖先かを区別しません。祖先への条件は `ancestors` に順序付きの列で書きます。値の `true` は placeholder で、grant を作るときにそのプロセスの実値で埋まります。placeholder を書けるのは rule の inline の subject だけです(「rule」)。

```json
{
  "match": { "binary": { "team_id": true, "signing_id": true } },
  "ancestors": [
    { "match": { "binary": { "signing_id": "com.anthropic.claude-code", "team_id": true } } },
    { "tags": ["terminal-app"] }
  ]
}
```

この例は「上に claude-code がいて、さらにその上に `terminal-app` のタグが付いたプロセスがいる」プロセスで、対象自身の Team ID と signing identifier、claude-code の Team ID は承認したときの値に固定されます。tmux の中のシェルの祖先には端末 app は現れません。tmux server はデーモン化して launchd の子になるので、lineage は tmux server で切れます。

| 要素 | 中身 |
| --- | --- |
| match | そのプロセス自身の項目への条件(形は後述の matcher) |
| tags | そのプロセスに付いているタグ |
| ancestors | 祖先への条件の順序付きの列。各要素は `match` と `tags`。この順で祖先のどこかに当たる(間に挟まってよい)。近い方から |
| include\_self | `true` なら、`ancestors` の列の照合を祖先ではなくそのプロセス自身から始めてよい(「自身か子孫」のタグの定義に使う)。subject に 1 つで、要素ごとには持たない |

`match` と `tags` はそのプロセス自身への条件で、`ancestors` は祖先への条件です(`include_self` がなければ自身は含まない)。`ancestors` しか書かなければ、そのプロセス自身には条件を付けないことになります。

`ancestors` は部分列として照合します。

- 列の順は対象に近い方からで、収集結果の列 `[対象, 親, 祖父, …]` と同じ向きです。
- 各要素は、前の要素が当たった祖先より上で、この順に祖先のどこかに当たればよく、間に別の祖先が挟まってもかまいません。direnv やラッパの有無で深さは安定しないので、「間に何も挟まらない」を区別する書き方は持ちません。
- 照合は近い側から貪欲に決めます。要素 1 を最も近い当たる祖先に、要素 2 をそのさらに上で最も近い当たる祖先に、と決めるので、要素の placeholder をどの祖先の値で埋めるかが一意に決まります。具体値もタグも無い要素(`{"match": {"binary": {"team_id": true}}}` だけ)は、その値を持つ最も近い祖先に当たります。
- 要素の中に `ancestors` は入れ子にせず、要素を名前で参照することもしません。深い条件はタグの定義に閉じ込めます。

subject の中の条件はすべて AND です。OR はルールを分けて書きます。ルールを読む人が入れ子の論理式を追わずに済むようにするためです。

### tag

tag は名前の付いた subject です。収集のたびに、列の各プロセスを tag の subject と照合し、当たったプロセスにタグを付けます。深い条件は tag(や名前付きの subject)の定義に閉じ込め、ルール側はその名前を参照するだけにします。次の例は、pj1 の claude セッション自身と、そこから起動されたプロセスのすべてにタグが付きます。

```json
{
  "tag": "claude-pj1",
  "subject": {
    "ancestors": [
      {
        "match": {
          "binary": { "signing_id": "com.anthropic.claude-code", "team_id": "VWXYZ67890" },
          "cwd": { "glob": "/Users/alice/src/pj1/**" }
        }
      },
      { "match": { "binary": { "team_id": "ABCDE12345" } } }
    ],
    "include_self": true
  }
}
```

これでルールの subject は `{"tags": ["claude-pj1"]}` だけで済みます。画面では、タグが付いたプロセスのすべてにタグを出します。そのタグを認可したときに通るプロセスと、画面でタグが付いているプロセスがそのまま一致します。

- タグを条件にした場合の強さは、タグの定義の subject の強さと同じです(算出の規則は「ルールの作成と強さの制約」)。
- 上の `claude-pj1` は `ancestors` だけで対象自身への条件を持たないので弱です。弱のルールの `allow` にどの scope を求めるかはアプリの制約表が決めます(「ルールの作成と強さの制約」の例の表なら世代の scope が要り、下の rule の例は `os.session` と `app.unlock` を持つので満たします)。
- タグの定義に placeholder(`true`)は書けません(「rule」)。
- タグの定義もルールと同じ署名付きの一覧に入れます。同じ uid のプロセスが定義を書き換えられると、そのタグを条件にしたルールが全部広がるためです。
- タグの定義が別のタグを参照してもよく、循環は読み込み時にエラーにします。
- 列が途切れていると、祖先への条件を持つタグは有無を判定できないことがあります。そうしたタグは `TaggedChain.undecidable_tags` に入り、承認画面は「付いていない」と区別して見せます(「評価」)。

### rule

rule は静的な定義です。conditions は記号のまま書き、世代や時刻はまだ持ちません。subject、tag と同じ署名付きの一覧に入ります。

```json
{
  "id": "pj1-claude-usual",
  "effect": "allow",
  "subject": { "tags": ["claude-pj1"] },
  "targets": ["key:k1"],
  "conditions": [{ "os.session": "unlocked" }, "app.unlock", { "age": "1h" }, { "uses": 3 }, "os.not_remote"]
}
```

| 要素 | 中身 |
| --- | --- |
| id | rule の名前。grant が `rule_id` で指す |
| effect | `allow`(無認証で通す)、`deny`(拒否)、`ask`(アプリの再認証を求める) |
| subject | 上の subject。名前で参照してもよい |
| targets | ルールが効く対象の列。要素は対象(`Target` の文字列)に対する glob。対象の語彙はアプリが決める。空の `targets` は全対象に当たる |
| conditions | 条件の名前の列(すべて AND)。寿命型と状態型があり、どちらかは語彙が決める(下記) |

subject の値は、具体値か placeholder(`true`)のどちらかです(決定の記録: [DR-0007](decisions/DR-0007-pin-placeholders-and-ordered-ancestors.md))。

| rule に書く値 | 意味 | 例 |
| --- | --- | --- |
| 具体値(文字列か数値。glob / 正規表現 / 数値範囲は `{"glob": …}` / `{"regex": …}` / `{"min": …, "max": …}`) | 手書きの具体値。そのまま照合する | `{"binary": {"team_id": "MYTEAM", "signing_id": "myapp"}}` = 自作アプリからは常に allow |
| `true` | placeholder。grant を作るときに、その subject が当たったプロセスの実値を pin する | `{"binary": {"team_id": true, "signing_id": true}}` = 承認したそのアプリに固定 |

- 構造を持つ値では field 単位で混ぜられます(`{"binary": {"signing_id": "com.googlecode.iterm2", "team_id": true}}` = signing identifier で見つけ、その Team ID を pin)。
- `process` は `true`(個体を pin)か具体値の複合です。
- 単純項目(`cwd`、`uid`、`path` …)も `true` で、実値を完全一致で pin します。
- これにより「いつもの許可」は 1 つの rule で済み、アプリごとに別の rule を保存しなくてよくなります。

placeholder を書けるのは rule の inline の subject だけです(決定の記録: [DR-0008](decisions/DR-0008-evaluation-semantics.md))。タグの定義と名前付きの subject に `true` があれば、読み込みはエラーにします(`LoadError::InvalidValue`)。placeholder を含む rule は、読み込み時に自動で grant にならず、承認を経てだけ grant になります(下記)。

条件には2つの種類があり、どちらかは語彙に登録するときに決まります。ルールには `conditions` に名前を並べるだけで、種類ごとに置き場を分けません(すべて AND)。

| 種類 | 偽になったとき | 例 |
| --- | --- | --- |
| 寿命型(scope) | 戻らない。その評価で失効が確定する(「評価」) | `os.session`、`app.unlock`、`age`、`until`、`uses` |
| 状態型 | 偽の間だけ当たらない | `os.not_remote`、`os.console_active`、`time.window` |

`uses`(消費型)も寿命型です。一度 0 になれば戻りません。種類はルールを書く人ではなく語彙が知っているので、承認画面や trace では各条件の横に種類を出し、読む人にどちらの意味かを見せます。

静的な rule を評価に直接使うことはしません。評価が見るのは grant だけです。一覧の rule のうち、寿命型・消費型の condition を持たず、placeholder を含まず、pin に chain や観測値を要する condition(`os.login_session` 等)も含まないものは、読み込み時に自動で永続の grant になります。手書きの deny を「許可する」操作なしに効かせるためです。それ以外の rule は、承認を経てだけ grant になります。

### grant

grant は、rule を実際のプロセス(承認の瞬間の接続相手)に適用し、subject の placeholder を実値に、各 condition を具体値に pin したものです。grant を作るときに、subject の `match` の placeholder は対象プロセス(列の先頭)の値で、`ancestors` の要素の placeholder はその要素が当たった祖先の値で埋め、寿命型の条件にはその時点の世代を記録し、`age` は時刻に直します。

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

- `conditions` の各要素は `key`、元の引数 `args`(必要なら)、`pinned`(pin 値。状態型には普通は無く、`os.login_session` のように接続相手に依存する値を固定するものだけが持つ)です。`age` は grant を作るときに `until` の pin 値に直します(`key` も `until` にする)。
- `os.session` の pin 値は、段階以下の世代を全部持ちます(`unlocked` なら `boot`、`awake`、`unlocked` の 3 つ。`awake` は起床の時刻、`unlocked` は解錠の時刻)。
- `id` は `Policy::grant` が一意に付けます(上の `g-…` は例示)。
- subject に placeholder は残りません(残っていれば読み込みエラー)。埋める値が無ければ(署名が無いのに `team_id: true` など)grant は作れません(`GrantError::ValueUnavailable`)。
- grant は自己完結です。effect、targets、pin 済みの conditions、placeholder を解決した subject を自分で持ち、元の rule の id を `rule_id` として持ちます(表示と掃除に使う)。rule が後で変わっても、既存の grant は変わりません。
- grant の subject は inline の subject です。rule の subject が名前で参照していれば、grant を作るときに展開します。subject の中のタグ名の参照だけは、名前のまま残します。タグの定義は署名付きの一覧にあり、その更新は意図した変更なので、既存の grant にも及んでよいためです。
- 寿命型・消費型の condition を持たない rule から作った grant は失効しません(永続の grant)。deny は普通こちらです。
- `Policy::grant` は grant を返すだけで、メモリ上の Policy には入れません。アプリが署名して永続化し、書けてから `Policy::add_grant` で入れたときに効き始めます(「保存」)。

保存した rule がそのまま再適用の対象になります。placeholder があるので、同じ rule を別のアプリの承認にも使えます。承認画面に rule の一覧を出し、選んで passkey を1回通せば grant ができます。承認画面でその場で条件を選んで許可する流れは「rule を組み立て、すぐ grant にする」の 2 段です。rule を一覧に保存するかは利用者が選び、保存しなければ使い捨ての rule になります。

### 名前と参照

subject、tag、rule、条件の組は、どれも名前を付けて一覧に置き、ほかから名前で参照できます。承認画面で作った subject を名前付きで保存すれば、次からはタグの定義にも別のルールにも使い回せます。

参照は文字列で書きます(`{"ref": "…"}` のような包みは使いません)。包みを使わないのは参照の書き方の話で、値の形には当てはめません(glob / 正規表現 / 数値範囲の値は `{"glob": …}` / `{"regex": …}` / `{"min": …, "max": …}` で書く。「matcher」)。

**決定の理由**: 参照が現れる場所ごとに、何を指すかが1つに決まっていて、種類が混ざる場所がないためです。

- `tags` の中はタグ名だけ。
- subject の位置(ルールの `subject`)は、文字列なら subject 名、オブジェクトならその場の定義。型で区別できる。`ancestors` の要素は名前で参照せず、その場の `match` と `tags` だけを書く。
- rule は適用するときに名前で指すだけで、一覧の中からは参照されない。
- `conditions` の要素は、文字列も `{"age": "1h"}` のような引数付きも、どちらも語彙の名前。

包みを入れても、書く量と読む手間が増えるだけで、曖昧さは減りません。この前提が崩れる(同じ場所に種類の違う名前が入り得る形を足す)ときにだけ、見直します。

### matcher

`match` の key は語彙(`Vocabulary`)に登録された項目の名前で、値はその項目への条件です。照合の形は項目ごとに決まります。

| 形 | JSON | 使える項目 |
| --- | --- | --- |
| 完全一致 | 文字列か数値 | すべて |
| glob | `{"glob": "…"}` | パス、プロセス名、cwd。パスと cwd は絶対パスで書き、`~` は解釈しない |
| 正規表現 | `{"regex": "…"}` | パス、argv(argv は要素ごとに当て、いずれかの要素に一致すれば真。結合した文字列には当てない) |
| 数値の範囲 | `{"min": …, "max": …}` | uid |

rule の値が placeholder(`true`)の項目や field は、grant で実値の完全一致になります(「rule」)。真偽値の完全一致はありません。JSON の `true` は placeholder 専用で、真偽値の項目は今は無く、要るときは文字列で表します。

値の妥当性は項目が検査し(`Matcher::validate`。読み込みと builder が呼ぶ)、placeholder を実値に置き換えるのも項目です(`Matcher::resolve`。そのプロセスに値が無ければ `ResolveError::ValueUnavailable`)。

`process`、`binary`、`os.session` は構造を持つ値で、完全一致だけにします(`binary` はどの field も完全一致)。署名の条件は、署名の検証が通ったときだけ一致とみなします。ad-hoc 署名は Team ID が空なので、Team ID の条件には決して一致しません。

**`process`** は「この個体のプロセス」を表す項目です(決定の記録: [DR-0005](decisions/DR-0005-process-identity-as-one-item.md))。rule では `true`(承認したその個体を pin)か具体値の複合を書き、grant では `Policy::grant` がその時点で取れた識別子と boot UUID(`kern.bootsessionuuid`)を全部持たせた複合値になります(例 `{"process": {"boot_uuid": "7B1E…", "unique_id": 12345, "pid": 501, "start_time": {"secs": 1762570683, "micros": 123456}}}`)。照合は両側に揃っている識別子を全部比べ、全部一致したときだけ当たります。最悪でも pid と起動時刻の組の一致を見ます。ルールを書く人は、どの識別子で比べたかを気にしません。クラスは強です。`match` にも `ancestors` の中にも書けるので、「このターミナルのタブのシェルの子孫」が書けます。pin したプロセスが終わればそのプロセスは列に居なくなり、grant は当たらなくなります。列に居るプロセスの寿命はこれで表せます。終わったプロセスを指す grant の削除は掃除(アプリ)の責務です。UI では「このプロセスだけ」の 1 選択肢として出します。`process` は個体の同一性で、exec で中身のコードが変わっても同じ個体です。コードの同一性は `binary` が担うので、コードも固定したいときは `binary` と併用して pin します。

**`binary`** は「このプロセスのコード」を表す項目です。値は任意個の field の複合 `{digest?, team_id?, signing_id?, bundle_id?, cdhash?}` です(例 `{"binary": {"team_id": "VWXYZ67890", "signing_id": "com.anthropic.claude-code"}}`)。field の値は文字列か placeholder の `true` で、grant ではどれも文字列です。`digest` は `sha256:<hex>`、`cdhash` は hex、`team_id`、`signing_id`、`bundle_id` は署名と署名で封印された Info.plist の値そのままです(`bundle_id` の照合元は `Signature.bundle_id`)。真偽値を値に取る field は無いので、`true` は placeholder の意味だけを持ちます。照合は値にある field をそれぞれ検証し、全部が一致したときだけ当たります(AND)。署名由来の field(`team_id`、`signing_id`、`bundle_id`、`cdhash`)は、署名の検証が通ったときだけ一致とみなします。署名が有効なことは署名由来の field の照合の性質なので、それだけを表す項目は持ちません。クラスは値にある field のうち最も強いもので、署名由来の field があれば強、`digest` だけなら中です。Apple の OS バイナリ(Terminal.app、`/bin/zsh` 等)は Team ID を持たないので、`binary` ではなく root 所有の `path` で書きます(強)。

値の妥当性の規則は `binary` の中に閉じています。

- `signing_id` があるなら `team_id` もある。signing identifier は開発者が自由に決める値で、ad-hoc 署名でも名乗れるため。
- `bundle_id` があるなら `team_id` と `signing_id` もある。Info.plist は誰でも書けるため。
- `cdhash` と `digest` は単独でよい。
- 空(field が 1 つも無い)は不正。
- 未知の field がある値は不正で、黙って捨てずにエラーにする(`process` の値も同じ)。
- placeholder の field も「ある」に数える(`{"signing_id": "com.googlecode.iterm2", "team_id": true}` は妥当)。

builder はこの規則を満たすように field を揃えて `true` を置き(利用者が `signing_id` を選べば `team_id` も入る)、読み込みは満たさない値をエラーにします。

- `cdhash` は、下の field の値を全部決める最も強い field です。CodeDirectory が identifier、Team ID、Info.plist のハッシュを含むためです(SDK の `cs_blobs.h` の `CS_SUPPORTSTEAMID`、`teamOffset`、`CSSLOT_INFOSLOT`)。
- `digest` は実行パス上のファイルの内容のハッシュで、署名に頼れないときの床として置きます。収集するかは `CollectOptions::digest` で選びます(既定は取らない)。macOS では `proc_pidpath` のパスを読むので、exec の後にファイルを置き換えられると稼働中の像と食い違います(クラスは中)。Linux では `/proc/<pid>/exe` が稼働中の inode を指すので、実質強い手段になります。署名由来の field が取れる環境・アプリでは `digest` を使わず、UI は署名由来の field を優先して出します。

**`os.session`** は OS の世代を段階で選ぶ寿命型の条件です(世代の定義は「scope: grant の寿命」)。subject の `match` ではなく rule の `conditions` に書きます。引数は段階 `boot` < `awake` < `unlocked` で、pin 値は選んだ段階以下の世代の複合です(例 `{"boot": "7B1E…", "awake": 起床の時刻, "unlocked": 解錠の時刻}`)。`check` は段階以下の世代が全部一致したときだけ真です。条件の項目なので、ルールの強さ(subject のクラス)には数えません。

### 項目の登録

条件に使える項目(`match` の key、寿命型の scope の名前、状態型の条件の名前)は、組み込みもアプリも同じ形で語彙に登録します(決定の記録: [DR-0006](decisions/DR-0006-structured-values-instead-of-depends.md))。

```
register(key, impl)
```

| 引数 | 中身 |
| --- | --- |
| key | 項目の名前(名前空間は下記) |
| impl | 項目の種類ごとの実装。matcher の項目は `Matcher` trait(照合する `matches`、値からクラスを決める `class`、値の妥当性を検査する `validate`、placeholder を実値に置き換える `resolve`)。寿命型と状態型は condition の trait(observe / pin / check / advance と、引数の妥当性を検査する validate\_args、「条件の実装」) |

登録先は procline-acl の `Vocabulary` で、matcher の項目、scope、条件が同じ器に入ります。登録の時点で検査するのは、key の重複と名前空間だけです。

- `Vocabulary::builtin()` は OS 非依存の項目だけを持ちます。matcher の項目(`process`、`binary`、`uid`、`gid`、`path`、`cwd`、`argv`、`name`、`tty`、`responsible`)、`until`、`age`、`uses`、`time.window` です。
- `os.*` の項目(`os.session`、`os.console_user`、`os.login_session`、`os.not_remote`、`os.console_active`)は procline-macos が `Item` として提供し(`procline_macos::os_items() -> Vec<procline_acl::Item>`)、アプリが `register` で登録します。

名前空間は項目のカテゴリで揃えます。

- 接頭辞なし: 対象プロセス自身の属性(`process`、`binary`、`uid`、`gid`、`path`、`cwd`、`argv`、`name`、`tty`、`responsible` …)。subject は「そのプロセスへの条件」なので無印にする。
- `os.`: ホストの状態と世代。`time.`: 時刻。`app.`: アプリ固有(規則は「アプリが足す語彙」)。
- `until`、`age`、`uses` は grant 自体の寿命で、組み込みの基本語として接頭辞なしにする。

値の形と妥当性は項目自身が持ちます。key をまたぐ依存は持たず、構造が要るものは 1 つの key の値に構造を持たせます(`process`、`binary`、`os.session`)。

- builder(承認画面からルールを作る `SubjectBuilder` / `RuleBuilder`)は収集結果を持たず、利用者が選んだもの(`process`、`binary` の field の組み合わせ、`os.session` の段階)から、選ばれた field を `true` で置いた subject を組む。実値は `Policy::grant` が `Matcher::resolve` で埋める。`binary` は妥当性の規則を満たすように field を揃え、`os.session` の段階は rule の条件の引数として書く(世代は grant を作るときに pin する)。
- 読み込み(`Policy::load_verified`、`Policy::load_grant`)は、項目の実装(`Matcher::validate`、`Condition::validate_args`)が検査して不正な値(未知の field を含む)をエラーにする。placeholder を書けない場所(grant、タグの定義、名前付きの subject)に placeholder があれば、それも不正な値としてエラーにする(`LoadError::InvalidValue`)。参照先の無いタグ名・subject 名は `LoadError::UnknownTag` / `LoadError::UnknownSubject`。
- UI(アプリ側)は key ごとに 1 つの選択肢を出し、その中で値の段階や field の組み合わせを選ばせる。
- アプリの項目を組み込みの項目と組で使いたいときは、同じ `match` に並べる(AND)。

### 強さ: クラスと深さ

項目の強さは 2 つの軸で表します。

| 軸 | 何を表すか | 値 |
| --- | --- | --- |
| クラス | その条件が、承認した個体・コードをどれだけ特定するか(「収集する情報」の表の強さ) | 強 / 中 / 弱 |
| 深さ | 値がどれだけ絞るか | 値の段階、または pin した field の数 |

クラスの定義と組み込みのクラスの決定の記録は [DR-0009](decisions/DR-0009-strength-class-as-specificity.md) です。

| クラス | 組み込みの項目 |
| --- | --- |
| 強 | `process`、署名由来の field を持つ `binary`、root 所有で利用者が書けない場所の `path` |
| 中 | 責任プロセス、`digest`(だけの `binary`)、利用者が書ける場所の `path` |
| 弱 | `name`、`cwd`、`argv`、`uid`、`gid`、`tty` |

- クラスは項目が値から決めます(`Matcher::class(value, process)`)。rule の placeholder 入りの値も受け、どの field に置かれているかで決めます(`{"binary": {"team_id": true}}` は強)。`process` は照合する相手のプロセスで、grant を作るときと評価のときには渡り、rule の build と読み込みのときには無い(`None`)。
- `binary` のクラスは値にある field のうち最も強いもので、署名由来の field があれば強、`digest` だけなら中です。
- `path` のクラスは、収集側(procline-macos)が path ごとに取る属性(所有者と利用者の書き込み可否、`PathMeta`)で決まります。プロセスがある grant の作成時と評価時に強 / 中を判定し、プロセスが無い rule の build 時と読み込み時は中(弱い側)とします。「利用者が書ける場所」は、ファイル自体か、パス上のいずれかのディレクトリに利用者が書ける(差し替えられる)ことを指します。
- `uid` と `gid` が弱なのは、同じ uid の全プロセスが満たすので、何も特定しないためです。
- どの項目がどのクラスかは語彙(登録された項目の実装)が持ちます。収集結果の各項目は強さを持ちません。
- 深さは UI の概念で、crate は算出も型も持ちません。UI の並び順と、アプリが追加で課す制約の材料です。ルールの強さの制約には使いません(「ルールの作成と強さの制約」)。

### 評価

評価の対象は grant です(決定の記録: [DR-0008](decisions/DR-0008-evaluation-semantics.md))。評価は、条件単位の真偽を決める段階と、grant 単位の採否を決める段階を分けます。

1. 各 grant の条件を判定する。
   - 観測に失敗した condition(`EvalContext` のその key が `Err(ObserveError)`)を使う grant は、その評価では判定できない。id を `Decision.undecidable` に載せ、許可にも失効にもしない。
   - 寿命型の `check` が偽になった grant は、その評価でその場で失効を確定し、`Decision.expired` に id を載せる。失効は一度確定したら戻らない(時計の巻き戻しや観測の回復で復活しない)。
   - targets が対象に当たらない grant を除く。
   - 各 grant の subject を照合し、状態型の `check` を取る。subject の `match` と `tags` は対象自身と、`ancestors` は列を近い側から貪欲に部分列として照合する。
   - 列が途切れている(`ProcessChain.truncated` が `Some`)とき: subject の条件(`match` ∧ `tags` ∧ `ancestors` の部分列)はすべて肯定条件で、列を延ばしても「当たった」が「当たらない」に変わらない(単調)。よって途切れた列で当たった grant は全列でも当たるので、効果の決定に使う。祖先への条件(`ancestors`、またはその定義が `ancestors` を持つタグ。タグが別のタグを参照するときは推移的に辿る)を持ち、途切れた列で subject が当たらなかった grant は判定できない。その id を `Decision.undecidable` に載せ、効果の決定には使わない。subject は当たったが状態型の `check` が偽の grant は、全列でも偽なので判定できなかったとは扱わない。
2. effect を決める。順序は deny > allow > ask。
   - `deny` が 1 つでも当たれば拒否。
   - `allow` が当たれば許可。当たった allow のうち採用するのは 1 件。advance で変わらない grant(永続、または `uses` を持たない)を優先し、同順なら作成の古い順。他の grant で通るのに、限りある `uses` を減らさないため。
   - `ask` が当たれば `Effect::Ask`(アプリの再認証)。`Decision.grant_id` は採用した ask の grant の id。
   - 何も当たらなければ既定の effect(`Policy::load_verified` の `default_effect`)。`Decision.grant_id` は None。
3. 採用された grant にだけ、各 condition の `advance` をかける。1 つでも新しい pin 値を返せば、pin 値を差し替えた新しい grant を作る(grant は immutable)。
4. アプリが、変わった grant を署名して永続化し、書けてから結果(allow)を使う。

評価の結果(`Decision`)は effect だけでなく、採用された grant の id と、各条件がどの項目に一致したか(trace)を返します。画面の「なぜ通ったか、なぜ聞かれたか」に使います。`Decision.trace` は接続相手に返しません(どの条件で落ちたかが見えるため)。手順 3 で grant が変わったときは、その新版も返します(`updated_grant`)。

評価の入口は 2 つです。`evaluate` は手順 3 まで行い、`updated_grant` を返すだけで、メモリ上の grant は差し替えません。`explain` は trace の表示用で、`advance` をかけず、`updated_grant` は常に空です。`explain` も `expired` を載せますが、失効を確定しません(アプリは `explain` の `expired` を削除に使いません)。

- アプリは `updated_grant` を署名して永続化し、書けてから `Policy::add_grant`(同じ id なら置換)でメモリ上の grant を差し替え、値を渡します。書けなかったときは allow を使いません。
- アプリは `evaluate` の `expired` の grant を `Policy::remove_grant` と保存先から消します。`uses` が 0 になった grant も、次の評価で失効が確定してここに載ります。
- `undecidable` があるとき、判定できない deny があるのに allow を通してよいかはアプリが決めます。crate は事実を返します。

## scope: grant の寿命

寿命型の条件(以下 scope)は、grant を作るときにその時点の世代(epoch)を pin し、評価のたびに今の世代と pin 値を比べて、違えばその grant は永久に失効します。「解錠している間」ではなく「この解錠の回の間」になるので、一度ロックして解錠し直しても grant が生き返りません。

この形にすると、どの scope も「一度終われば戻らない」ことが自動的に保証され、アプリが足すのも condition の trait の実装 1 つで済みます(「条件の実装」)。grant を作るときに今の世代を観測できなければ grant を作れず(`PinError::Unobservable`)、評価のときに期間の外で観測値が無ければ(`observe` が `Ok(None)`)`check` が偽になって失効が確定します。どちらも安全側に倒れるためです。観測そのものに失敗したとき(`observe` が `Err`)は、期間の外とは区別し、その評価ではその grant を判定できないものとします(許可にも失効にもしない。「評価」)。

scope は複数並べられ、すべてが生きている間だけ grant が効きます(AND)。「24時間、ただし再起動まで」のように組み合わせます。

### 組み込みの語彙

| 名前 | 終わる時点 | 世代の取り方(macOS) |
| --- | --- | --- |
| `until` | 指定の時刻 | 時計(世代ではなく時刻で判定) |
| `age` | grant の作成からの経過時間 | grant を作るときに `until` の pin 値に直す |
| `uses` | N 回採用されたら | 残り回数を pin し、採用されるたびに 1 減る(世代ではなくカウンタ) |
| `os.session` | 選んだ段階以下のどれかの期間の終わり。`boot` は再起動、`awake` はスリープ・ハイバネーション、`unlocked` は画面ロック(手動、離席の自動ロック、スクリーンセーバー) | `boot` は `kern.bootsessionuuid`、`awake` は直近の起床の時刻(`kern.waketime`)、`unlocked` は直近の解錠の時刻 |
| `os.console_user` | ユーザーの切り替え | ユーザーの切り替えの事象固有の値 |

`until`、`age`、`uses` は procline-acl の `Vocabulary::builtin()` に入り、`os.*` は procline-macos の `os_items()` が提供します(「項目の登録」)。

世代は事象固有の値(起動の UUID、起床・解錠の時刻など)です。デーモンの再起動と無関係に一意なので、再起動を跨いで読み直した grant も正しく判定できます。

`os.session` の段階の名前は期間の名前です。

- `boot` は起動してから再起動まで、`awake` は起床してからスリープ・ハイバネーションまで、`unlocked` は解錠してから画面ロックまでの期間です。
- 段階 N の pin 値はそれ以下の世代を全部持ちます。`awake` と `unlocked` は厳密には入れ子でありません(スリープせずにロックできる)が、`unlocked` を選ぶとスリープでも失効します。これは仕様です。
- observe は 3 つの段階の世代を 1 つの複合値 `{"boot": uuid, "awake": 起床の時刻, "unlocked": 解錠の時刻}` で返し、その期間の中にいる段階だけを含めます(期間の外、つまりロック中やスリープ中の段階は欠く。`boot` は `kern.bootsessionuuid`、他はその期間が始まった時刻)。pin は引数の段階以下の field を写し、`check` は pinned にある field が全部 observed にあって一致するときだけ真です。期間の外では field が欠けるので偽になって失効が確定し、次に期間が始まっても時刻が変わるので一致しません。解錠の時刻だけを世代にすると、ロック中も値が変わらず通ってしまうためです。
- ユーザーの切り替え(`os.console_user`)とログインセッション(`os.login_session`)は `os.session` の段階に入れず、独立の項目にします。省電力でモニタが消えるまでの期間は持ちません。ロックもスリープも伴わずに起き、マルチモニタの扱いも要るので、欲しいアプリが `app.` で足します。

### アプリが足す語彙

アプリ固有の語彙は `app.` の名前空間に置きます。名前空間は crate 群が使うもの(`os.`、`time.` など)と `app.` だけで、アプリが自由に作ることはしません。評価するアプリは常に1つなので複数の名前空間は要らず、自由にすると今後 crate に足す名前空間とぶつかり得るためです。cw なら次のようなものです。

- `app.unlock`: vault を開いた回。手動ロックや vkey\_ttl 切れで終わる。
- `app.passphrase`: P を発行した回。Sealed になると終わる。

登録されていない名前を持つルールは、読み込み時にエラーにします(黙って無視すると、そこから作る grant が意図より長く効くため)。

## 条件、ルールの作成、保存

### 条件

状態型の条件は、評価のたびに真偽が変わり得るものです。scope と違い、偽になっても grant は失効せず、そのときだけ当たらなくなります。scope と同じく、組み込みに加えてアプリが `app.` の名前で足せます。状態型の状態(`os.console_active` 等)は distributed notification ではなく、権威的な API(`CGSessionCopyCurrentDictionary` 等)で取ります。

| 名前 | 真になるとき |
| --- | --- |
| `os.not_remote` | 接続相手の asid がコンソールのセッションのもの。判定は asid だけで行う(祖先の有無は double-fork で変えられるので使わない) |
| `os.console_active` | 画面がロックされていない |
| `os.login_session` | 接続相手のログインセッションが grant を作ったときと同じ(作成時の boot UUID と asid の組 `{boot_uuid, asid}` を pin 値に持つ。asid は起動ごとに再利用されるので boot UUID と組にする。ログアウトの検知は約束しない) |
| `time.window` | 指定の曜日・時間帯 |

「自宅の Wi-Fi にいる間」のような場所の条件は、アプリが必要に応じて足します。

### 条件の実装: observe / pin / check / advance

寿命型(scope)、消費型(`uses`)、状態型は、同じ trait の関数で表します。外の状態(世代、画面ロックの状態など)を読むのは `observe` だけで、`pin` / `check` / `advance` は渡された値から結果を決めます。condition が触るのは自分の pin 値だけで、grant 全体は受け取りません。

```rust
/// この condition の観測値。EvalContext::capture が評価の最初に 1 回だけ観測し、評価の途中で変わらない
pub struct Observed<'a> {
    pub now: SystemTime,
    pub value: Result<Option<&'a Value>, &'a ObserveError>,   // observe() の結果そのまま。Err なら Policy は check を呼ばず判定不能にし、pin は PinError::Unobservable を返す
}

trait Condition {
    fn kind(&self) -> ConditionKind;                                   // Lifetime / State
    /// 今の値を観測する (世代の uuid、画面ロックの状態など)。評価の最初に EvalContext::capture が全 condition に 1 回呼ぶ。観測するものが無い condition と期間の外は Ok(None)(寿命型なら check が偽になり失効が確定する)。観測に失敗したとき(sysctl や IOKit の呼び出しの失敗)は Err で、その condition を使う grant はその評価で判定できない
    fn observe(&self) -> Result<Option<Value>, ObserveError>;
    /// grant を作るときに 1 回。pin 値を返す。os.login_session の {boot_uuid, asid} のように chain から取るものは chain を見る。状態型は普通 Ok(None) で、接続相手に依存する値を作成時に固定するもの(os.login_session)は pin 値を返す。寿命型で観測値が無ければ Err(PinError::Unobservable)。args が不正なら Err(PinError::InvalidArgs)
    fn pin(&self, args: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> Result<Option<Value>, PinError>;
    /// 判定。副作用なし
    fn check(&self, args: Option<&Value>, pinned: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> bool;
    /// 採用された grant にだけ呼ぶ。pin 値の新版。None なら変化なし
    fn advance(&self, pinned: Option<&Value>) -> Option<Value>;
    /// 引数の妥当性。読み込みと builder が呼ぶ
    fn validate_args(&self, args: Option<&Value>) -> Result<(), String>;
}

enum PinError { Unobservable, InvalidArgs { reason: String } }
struct ObserveError { reason: String }
```

| 項目 | observe | pin | check | advance |
| --- | --- | --- | --- | --- |
| 世代(`os.session`、`app.unlock` …) | 今の世代 | observed の値(無ければ Err)。`os.session` は段階以下の世代の複合 | pinned == observed。`os.session` は段階以下の世代が全部一致 | None |
| `until` | None | args の時刻 | obs.now < pinned | None |
| `age` | None | obs.now + args の期間(`until` の pin 値になる) | obs.now < pinned | None |
| `uses` | None | args の N | pinned > 0 | pinned − 1 |
| 状態型(`os.console_active` 等) | 今の状態(観測するものがあれば) | None | observed / args / chain を見る | None |
| 状態型 `os.login_session` | None | chain の `{boot_uuid, asid}`(`ProcessChain.boot_uuid` と接続相手の asid) | chain の `{boot_uuid, asid}` == pinned | None |

- `ConditionKind` は Lifetime / State の 2 値です。世代、`until`、`age`、`uses` は Lifetime で、`uses` も一度 0 になれば戻りません。
- `EvalContext` は `now` と「key → `observe()` の結果(`Result<Option<Value>, ObserveError>`)」を持ちます。Policy が condition ごとに `Observed { now, value: ctx.observed(key) }` を組んで渡します(condition は自分の key を知らない)。結果が `Err` の key の condition を使う grant は、その評価で判定できないものとして `Decision.undecidable` に載ります(「評価」)。
- 状態型の `check` には `args` が届くので、`time.window` の時間帯のような引数を判定に使えます。
- 状態型も pin 値を持てます。接続相手に依存する値(`os.login_session` の `{boot_uuid, asid}`)を grant の作成時に固定するためです。寿命型の「偽になれば失効が確定する」は、観測値(世界の状態)と pin 値を比べる condition にだけ当てはまります。接続相手に依存する値が一致しないのは別の相手が来ただけで、世界の状態が変わったのではないので、状態型にします。

### ルールの作成と強さの制約

ルールは、承認画面で項目を選んで作ります(RuleBuilder)。「このプロセスの署名で」「上にいる claude-code の Team ID で」と選ぶと、選んだ field を placeholder(`true`)にした subject ができ、実値は grant を作るときに埋まります。`binary` は選んだ field から builder が妥当な組に揃え、`os.session` は段階を条件の引数で選びます(「項目の登録」)。`SubjectBuilder` が subject を、`RuleBuilder` が静的な rule を作ります。

- `SubjectBuilder` は収集結果を受け取りません。`PinSpec` から `true` 入りの subject を組み、具体値は `exact` で書きます。祖先の要素は `AncestorBuilder` で組んで `ancestor` で順に足します。
- 同じ key への `pin` と `exact` は、`binary` では field 単位で 1 つの値に合成し(同じ field が両方にあればエラー)、単純項目と `process` では 2 回目をエラーにします(`BuildError::Conflict`)。`SubjectBuilder::build` / `AncestorBuilder::build` が検査するのは値の妥当性(`binary` の規則、空)だけで、語彙との照合(未登録の項目、`Matcher::validate`、`Condition::validate_args`)は `RuleBuilder::build` が行います。
- `RuleBuilder` は `Policy::rule_builder(id, subject)` から作ります。強さの算出に、タグ・名前付きの subject の定義と語彙の両方が要るためです。rule の `id` はこの引数で与えます。
- `RuleBuilder::build()` は静的な `Rule` を返し、世代は記録しません。検査するのは値の妥当性と、強さ(クラス)と scope の制約(下記)です。強さのクラスは placeholder のままでも判定できます。
- pin は `Policy::grant(rule, tagged, ctx)` が行います。subject の placeholder を `tagged` の実値で埋め、各 condition を pin した grant を返します。メモリ上の Policy には入れません(署名と保存はアプリで、書けてから `Policy::add_grant` で入れる)。`GrantError` は、placeholder を埋める値が無い(`ValueUnavailable`)、`pin` が失敗した(`PinError`: 観測値が無い、引数が不正)、値が妥当でない、制約を満たさない(`ScopeTooWeak`)、のどれかです。
- 承認画面は passkey の前に「何が pin されるか」を見せるため、`Policy::resolve_subject(subject, tagged)` で placeholder を埋めた subject を得られます(名前参照は一覧の subject に解決してから埋めます。`include_self` で対象自身に当たった要素は対象自身の値で埋めます)。`Policy::grant` も内部でこれを使います。

ルールの強さは、subject のうち対象プロセス自身への条件から決まります(決定の記録: [DR-0003](decisions/DR-0003-rule-strength-from-own-match.md))。

- 対象プロセス自身への条件は、`match` と、`tags` が指すタグの定義のうち自身への条件です。ルールの強さは、それらの項目のクラスのうち最も強いものです。
- `ancestors` の条件は数えません。祖先が強く特定されていても、対象は「その子孫なら何でも」で、対象自身は縛られないためです。`include_self` があっても同じです(列の照合を自身から始めてよいだけで、自身を縛らない)。
- 自身への条件が何も無い subject(`ancestors` だけ)は最も弱く、弱と同じ制約を受けます。
- タグを条件にしたときの強さは、タグの定義の subject を同じ規則で算出したものです。

制約の表(クラスごとに `allow` で許す scope の条件、`AllowConstraints`)はアプリが `RuleBuilder` / `Policy` に与えます。crate は既定値を持たず、検査の仕組みだけを持ちます。`Policy` が `AllowConstraints` を持ち(`Policy::load_verified` の引数で与える)、`RuleBuilder::build`、`Policy::load_verified`、`Policy::grant`、`Policy::load_grant` が同じ検査をして、満たさなければエラーにします(`BuildError::ScopeTooWeak`、`LoadError::ScopeTooWeak`、`GrantError::ScopeTooWeak`)。制約はクラスで判定し、深さは使いません。どの scope が制約を満たすかも、アプリの制約表が決めます。

- 制約表の形は、`strong` / `medium` / `weak` の 3 つ(どれも必須)に、それぞれ `Unrestricted`(制限なし)か `AnyOf([...])`(列挙したどれか 1 つを満たせばよい)を置きます。`AnyOf` の要素は `Condition(key)`(その key の condition を含む)か `UntilWithin(期間)`(その期間以内に失効する)です。
- 時間の制約は `ScopeOption::UntilWithin` で表します。`Condition("age")` / `Condition("until")` も書けますが、grant 側では `age` は `until` に変換されているので、`Condition("age")` は grant では満たされません。
- 判定の時機: `age` の長さと寿命型の condition の有無は rule の build 時(と読み込み時)に、`until` の絶対時刻は grant を作るとき(その時点の now)に判定します。`Policy::load_grant` の `UntilWithin` の基準時刻は grant の `created_at` です。`path` のクラスがプロセスで決まるのも grant を作るときです(build 時は中として判定する)。

| ルールの強さ(クラス) | `allow` で許される scope(アプリが与える制約の例) |
| --- | --- |
| 強(署名、`process`、root 所有で利用者が書けない場所の `path`) | 制限なし |
| 中(責任プロセス、`digest`、利用者が書ける場所の `path`) | `until` が 7 日以内、または世代の scope を含む |
| 弱(名前、cwd、argv、uid、gid、tty) | 世代の scope(`os.session`、`app.unlock` など)を含む |

`deny` には制約をかけません。弱い条件の拒否も、少なくとも安全側には働くからです。画面では、弱い条件を選んだ時点で「同じユーザーの他のプロセスも満たせる条件です」と表示します。

### 保存

保存形は「一覧 1 本」と「grant 1 件ずつ」の 2 系統です。どちらも JSON で、保存と署名はアプリの責務です。署名の検証はアプリが実装する `PolicyVerifier::verify(&self, kind: SignedKind, bytes, sig)` で行い、`enum SignedKind { List, Grant }` で一覧と grant の署名の用途を分けます。

**一覧**(subject、tag、rule): crate は「一覧のバイト列と署名を受け取り、検証してから読む」ための入口(`Policy::load_verified`)を用意します。cw は一覧に D 側の鍵で署名し、同じ uid のプロセスが勝手に許可ルールを書き足せないようにします(PasskeyRegistry と同じ扱い)。

**grant**: grant はメモリ上に持ち、デーモンの意図しない終了に備えて、作成時と更新時に 1 件ずつ署名して永続化し、起動時に全部読み直します。メモリ上の grant が変わるのは、アプリが永続化してから `add_grant` / `remove_grant` を呼んだときだけです(決定の記録: [DR-0008](decisions/DR-0008-evaluation-semantics.md))。crate は `Grant` の JSON の形と、次の入口を持ちます。

- `Policy::load_grant(bytes, sig, &verifier)`: 1 件のバイト列と署名を受け取り、検証してから `Grant` を返す。一覧と同じ検査(未登録の項目、値の妥当性、制約)をし、落ちればエラー。
- `Policy::add_grant(grant)`: grant をメモリ上の Policy に入れる。同じ id があれば置き換える。読み直した grant、`Policy::grant` で作って永続化した grant、永続化した `updated_grant` に使う。
- `Policy::remove_grant(id)`: grant をメモリ上の Policy から除く。
- `Policy::grants()`: メモリ上の grant を列挙する。

掃除(要らなくなった grant の削除)はアプリの責務で、`Decision.expired` と `Policy::grants()` / `remove_grant` を使います。

- 1 件ずつなので、`uses` の更新の書き込みは軽く済みます(実測は実装時のベンチで確かめる)。
- `uses` は二重に消費されません。値を渡すのは減らした grant の永続化に成功した後なので、永続化に失敗したときは値も渡していません。
- アプリは `evaluate` → 永続化 → `add_grant` を直列化します。同時に走らせると、どちらの評価も同じ残り回数の grant を見るので、上限を超えて消費できます。
- 一覧を読み直した後は、grant も `Policy::load_grant` で検査し直します。タグの定義が変わると、そのタグを subject に持つ grant の強さが下がり得るためです。
- 世代は事象固有の値なので、起動時に読み直した grant も、再起動を跨いで正しく判定できます(「scope: grant の寿命」)。
- 永続化先のディレクトリは、評価するデーモン以外(同じ uid の他プロセス)から書けない場所に置きます。書けると、使い切る前の grant ファイルを差し戻して `uses` を戻せるためです。置き場はアプリが決めます。

## API の骨格

収集、評価、rule の作成、grant の発行が入口です。語彙の拡張は、matcher の項目、scope、条件を同じ `register` で登録します。

JSON では、バイト列(証明書の DER など)を base64url(padding なし)で書き、enum の値を snake\_case で書きます。`code_signing` は `{"state": "signed", …}` か `{"state": "unsigned"}` です。

```rust
// 収集(procline-macos)
// examples/dump.rs は collect_pid で集めた列を JSON で出す(cargo run -p procline --example dump -- <pid>)
let chain: ProcessChain = collect_peer(&stream, &CollectOptions {
    env: EnvPolicy::Allowlist(&["PWD", "SSH_CONNECTION"]),
    icon: true,
    digest: false,                                   // 実行ファイルの digest(既定は取らない)
    max_ancestors: 32,
    redaction: Redaction::default(),                 // env の伏せ字(対象の判定と伏せ方の 2 関数)の差し替え
})?;
// chain.processes()[0] が対象、以降が祖先
// chain.truncated: Option<Truncated>。列が途切れた理由 enum Truncated { MaxAncestors, AncestorExited, Unavailable }
// chain.boot_uuid: String。収集側が kern.bootsessionuuid を取る
// p.signature_trust(): Platform / AppStore / Notarized / DeveloperId / AdHoc / Unknown / Unsigned / Invalid
// ProcessInfo は digest: Option<String> と path_meta: Option<PathMeta> を持つ。PathMeta { owner_uid: u32, writable_by_user: bool }(path のクラスの判定に使う)
// ProcessInfo.responsible: Option<ProcessIdentity>。責任プロセスは pid でなく個体の識別で持つ
// Signature.bundle_id: Option<String>(kSecCodeInfoPList 由来。照合に使い、BinaryPin.bundle_id の照合元)。ProcessInfo.bundle(実行パスから .app を遡って読む)は表示用
// ProcessIdentity(process の pin 値)は boot_uuid: String を持つ。Identity::process_identity(&self, boot_uuid) で作り、boot_uuid は ProcessChain.boot_uuid を渡す

// 強さ(procline-core の共有型)。どの項目がどのクラスかは Vocabulary が持ち、ProcessInfo の項目は持たない。深さは UI の概念で、型は持たない
enum Strength { Strong, Medium, Weak }               // クラス(項目が値から決める)

// rule に書く値(procline-core)。JSON では true が Pin、それ以外は T の値
enum Pinnable<T> { Pin, Value(T) }

// 構造を持つ値(procline-core)
struct BinaryPin { digest: Option<Pinnable<String>>, team_id: Option<Pinnable<String>>, signing_id: Option<Pinnable<String>>, bundle_id: Option<Pinnable<String>>, cdhash: Option<Pinnable<CdHash>> }  // JSON では field ごとに true(placeholder)か文字列(cdhash は hex)
// BinaryPin::validate(&self) -> Result<(), BinaryPinError>: 値の妥当性(signing_id には team_id、bundle_id には team_id と signing_id、空は不正。placeholder の field も「ある」に数える)。未知の field は読み込みでエラー
enum SessionLevel { Boot, Awake, Unlocked }          // os.session の段階(args の値。JSON では "boot" / "awake" / "unlocked")

// 語彙(procline-acl)
let mut vocab = Vocabulary::builtin();               // OS 非依存の項目だけ: matcher の項目(process / binary / uid / gid / path / cwd / argv / name / tty / responsible)、until / age / uses、time.window
for item in procline_macos::os_items() {             // os.* の項目(os.session / os.console_user / os.login_session / os.not_remote / os.console_active)は procline-macos が提供する
    vocab.register(item)?;
}
// matcher の項目、寿命型、状態型を同じ register で足す。key の重複と名前空間の違反はエラー
vocab.register(Item::matcher_fn("app.workspace", Strength::Weak, |p, v| ...))?;  // クラスが値によらず一定の項目は、クラスを明示してクロージャで登録する
// クラスが値で変わる項目は Matcher trait を実装し、Item::matcher(key, impl) で登録する
//   matches: 照合 / class(&self, value, process: Option<&ProcessInfo>) -> Strength(process が無い build / 読み込みでは、プロセスで決まる項目は弱い側)/ validate(&self, value: &MatchValue) -> Result<(), String>(値の妥当性。読み込みと builder が呼ぶ)
//   resolve(&self, value: &MatchValue, process: &ProcessInfo) -> Result<MatchValue, ResolveError>(placeholder を実値に。ResolveError::ValueUnavailable { field: Option<String> })
// vocab.class(key, &value, process: Option<&ProcessInfo>) -> Option<Strength>: 項目が値(とプロセス)から決めたクラス(未登録の key と条件の項目は None)
vocab.register(Item::condition("app.unlock", CwUnlock::new(&vault)))?;           // Condition を実装した値(寿命型)
// 状態型も同じ Item::condition(...) で register に渡す。寿命型か状態型かは Condition::kind が返す

trait Condition {
    fn kind(&self) -> ConditionKind;                 // Lifetime / State
    fn observe(&self) -> Result<Option<Value>, ObserveError>;  // 評価の最初に EvalContext::capture が 1 回呼ぶ。Ok(None) は観測するものが無い / 期間の外、Err は観測の失敗
    fn pin(&self, args: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> Result<Option<Value>, PinError>;  // chain は os.login_session の {boot_uuid, asid} を pin するため
    fn check(&self, args: Option<&Value>, pinned: Option<&Value>, obs: &Observed, chain: &ProcessChain) -> bool;
    fn advance(&self, pinned: Option<&Value>) -> Option<Value>;
    fn validate_args(&self, args: Option<&Value>) -> Result<(), String>;  // 引数の妥当性。読み込みと builder が呼ぶ
}
struct ObserveError { reason: String }
// EvalContext は key ごとに Result<Option<Value>, ObserveError> を持つ。Err の condition を使う grant はその評価で判定できない(Decision.undecidable)

// 署名の検証(アプリが実装する)。kind で一覧と grant の署名の用途を分ける
trait PolicyVerifier { fn verify(&self, kind: SignedKind, bytes: &[u8], sig: &[u8]) -> bool; }
enum SignedKind { List, Grant }

// 一覧(subject、tag、rule)の読み込みと、保存した grant の読み直し
// constraints: AllowConstraints はアプリが与える制約の表(クラスごとに allow で許す scope の条件)。crate は既定値を持たない。下は例示で、既定値ではない
let constraints = AllowConstraints {
    strong: ScopeRequirement::Unrestricted,
    medium: ScopeRequirement::AnyOf(vec![ScopeOption::UntilWithin(Duration::from_secs(7 * 24 * 3600)), ScopeOption::Condition("os.session".into())]),
    weak: ScopeRequirement::AnyOf(vec![ScopeOption::Condition("os.session".into()), ScopeOption::Condition("app.unlock".into())]),
};  // AnyOf は列挙のどれか 1 つ(OR)
let mut policy = Policy::load_verified(bytes, sig, &verifier, &vocab, constraints, default_effect)?;  // default_effect: Effect はどの grant にも当たらないとき(Decision.grant_id が None)の effect。未登録の項目、タグの循環、値の妥当性、placeholder の場所、制約の違反はエラー
// LoadError: InvalidValue(値の妥当性の違反、placeholder を書けない場所の true)、UnknownTag { name }、UnknownSubject { name }、ScopeTooWeak(制約の違反)…
let saved = policy.load_grant(grant_bytes, grant_sig, &verifier)?;  // grant 1 件を検証し、語彙と制約と照合する(UntilWithin の基準時刻は grant の created_at)。一覧を読み直した後も grant をこれで検査し直す
policy.add_grant(saved);                             // メモリ上の Policy に入れる(同じ id があれば置換)
// policy.remove_grant(id) / policy.grants() -> impl Iterator<Item = &Grant>: 掃除に使う

// 評価
let tagged = policy.tag(&chain);                     // 各プロセスに付いたタグ(画面の表示にも使う)。TaggedChain は語彙と chain だけを借り、policy を借りない
// tagged.undecidable_tags: BTreeSet<String>。途切れた列で有無を判定できなかったタグ(承認画面は「付いていない」と区別して見せる)
let decision = policy.evaluate(&tagged, &Target::key("github/token"), &ctx);  // 採用された grant に advance をかけ、新版を返す(メモリは変えない)。アプリは evaluate → 永続化 → add_grant を直列化する(同時に走らせると上限を超えて uses を消費できる)
if let Some(grant) = &decision.updated_grant {
    // 署名して永続化し、書けてから policy.add_grant(grant.clone()) で差し替え、値を渡す
}
for id in &decision.expired {
    // 保存先から消し、policy.remove_grant(id)
}
// decision.undecidable が空でないとき、判定できない grant を残して allow を通すかはアプリが決める
// decision.trace は接続相手に返さない(どの条件で落ちたかが見える)
let shown = policy.explain(&tagged, &Target::key("github/token"), &ctx);      // advance なし(trace の表示用)。expired は載せるが失効を確定しない(アプリは explain の expired を削除に使わない)

pub struct Decision {
    pub effect: Effect,
    pub grant_id: Option<String>,        // 採用された grant(ask なら採用した ask の grant)。None なら effect は load_verified の default_effect
    pub trace: Trace,
    pub updated_grant: Option<Grant>,    // advance で変わった grant の新版。explain では常に None
    pub expired: Vec<String>,            // この評価で失効が確定した grant の id。evaluate のものをアプリが削除する(explain のものは削除に使わない)
    pub undecidable: Vec<String>,        // 判定できない grant の id(祖先への条件を持ち途切れた列で当たらなかったもの、観測に失敗した condition を使うもの)。効果の決定には使っていない
}

// subject の形(procline-acl)
struct Subject { r#match: BTreeMap<String, MatchValue>, tags: Vec<String>, ancestors: Vec<AncestorMatch>, include_self: bool }
struct AncestorMatch { r#match: BTreeMap<String, MatchValue>, tags: Vec<String> }  // ancestors の要素。入れ子の ancestors は持たない
// MatchValue { Pin, Exact(Literal), Glob(..), Regex(..), Range { .. }, Process(Pinnable<ProcessIdentity>), Binary(BinaryPin) }: Pin は単純項目の placeholder
// JSON では Exact は文字列か数値、Glob は {"glob": …}、Regex は {"regex": …}、Range は {"min": …, "max": …}。argv の Regex は要素ごとに当てる
// SubjectRef { Inline(Box<Subject>), Named(String) }: rule の subject の位置。placeholder を書けるのは rule の Inline だけ
// Grant { id, rule_id: String, effect, subject: Subject, targets, conditions, … }: grant の subject は inline(名前付きの subject は grant を作るときに展開。タグ名は名前のまま)
// targets(rule と grant): 要素は対象(Target の文字列)に対する glob。空の targets は全対象に当たる

// 承認画面から rule を作る(収集結果は受け取らず、true 入りの subject を組む)
let subject = SubjectBuilder::new()
    .pin("binary", PinSpec::Binary(vec![BinaryField::TeamId, BinaryField::SigningId]))  // key と、その値のどの field を placeholder にするか
    .ancestor(
        AncestorBuilder::new()
            .exact("binary", MatchValue::Binary(BinaryPin {
                signing_id: Some(Pinnable::Value("com.anthropic.claude-code".into())),
                team_id: None, digest: None, bundle_id: None, cdhash: None,
            }))                                      // signing_id で見つけ、
            .pin("binary", PinSpec::Binary(vec![BinaryField::TeamId]))  // その Team ID を pin(同じ key の exact と field 単位で 1 つの値に合成)
            .build()?,
    )
    .ancestor(AncestorBuilder::new().tag("terminal-app").build()?)  // 近い方から順に足す
    .build()?;
// SubjectBuilder: new / pin(key, PinSpec) / exact(key, MatchValue) / tag(name) / ancestor(AncestorMatch) / include_self() / build() -> Result<Subject, BuildError>
// AncestorBuilder: new / pin / exact / tag / build() -> Result<AncestorMatch, BuildError>
// build が検査するのは値の妥当性だけ(binary の規則、空)。未登録の項目と Matcher::validate は RuleBuilder::build が検査する
// 同じ key への pin と exact: binary は field 単位で合成(同じ field が両方にあれば BuildError::Conflict)、単純項目と process は 2 回目で BuildError::Conflict
// PinSpec { All, Binary(Vec<BinaryField>) }: All は process と単純項目用(値全体を true にする)。os.session の段階は下の RuleBuilder::condition で指定する
// BinaryField { Digest, TeamId, SigningId, BundleId, CdHash }

// rule を作る。RuleBuilder は Policy から作る(タグ・名前付きの subject の定義と語彙を見て強さを算出するため)
let rule = policy.rule_builder("pj1-claude-usual", SubjectRef::Inline(Box::new(subject)))  // rule の id と subject
    .targets(["key:k1"])
    .condition(ConditionUse::with_args("age", json!("1h")))
    .condition(ConditionUse::with_args("os.session", json!("unlocked")))  // 記号のまま。世代は grant を作るときに pin する
    .allow()
    .build()?;                                       // 静的な Rule。値の妥当性と、強さ(クラス)と policy の AllowConstraints を検査(違反は BuildError::ScopeTooWeak)

// 承認画面のプレビュー: passkey の前に「何が pin されるか」を見せる
let preview = policy.resolve_subject(&rule.subject, &tagged)?;  // SubjectRef (名前でも可) の placeholder を Matcher::resolve で tagged の実値に埋めた Subject。値が無ければ GrantError::ValueUnavailable

// rule を適用して grant を作る(subject の placeholder と各 condition の pin。保存した rule も同じ入口)
let grant = policy.grant(&rule, &tagged, &ctx)?;     // &self。pin して id を付けた grant を返すだけで、メモリには入れない
// GrantError: ValueUnavailable { key, field: Option<String> }(placeholder を埋める値が無い)、pin の失敗(Unobservable / InvalidArgs)、値の妥当性の違反、ScopeTooWeak(制約の違反。until の絶対時刻と path のクラスはここで判定)
// アプリは grant を署名して永続化し、書けてから入れる
policy.add_grant(grant);
```

- `EvalContext::capture` は評価の開始時に現在時刻と各 condition の `observe()` の結果を一度だけ取り、評価の途中で値が変わらないようにします。Policy はそこから condition ごとに `Observed` を組んで `pin` と `check` に渡します。テストでは全部を差し替えられます。
- `uses` は `evaluate` の中で、採用された grant の `advance` で減ります。アプリは `decision.updated_grant` を署名して永続化し、書けてから `add_grant` で差し替えて値を渡します。

---

裁定待ちは [docs/QUESTIONS.md](QUESTIONS.md)、作業は `docs/issue/` にあります。
