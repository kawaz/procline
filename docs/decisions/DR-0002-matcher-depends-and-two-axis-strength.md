# DR-0002: matcher の項目を登録制にして depends を持たせ、強さをクラスと深さの 2 軸で表す

- Status: Active
- Date: 2026-11-08

## Context

ACL の条件に使う項目には、単独では意味を持たないものがある。

- `signing_id` は開発者が自由に決める値で、ad-hoc 署名でも名乗れる。Team ID と組になって初めて「誰のどのコードか」を指す。
- `bundle_id` は Info.plist から読むので誰でも書ける。署名者と signing identifier の組に乗せないと何も保証しない。
- `cdhash` や `team_id` は、署名の検証が通っていなければ何を指すか保証がない。
- 寿命型の `os.wake`(起床の回数)や `os.screen_unlock`(画面のロック解除の回数)は、起動セッションの中でだけ意味を持つ。

項目ごとに固定の強さだけを持たせると、これらを単独の条件として許してしまう。また、matcher の項目、寿命型の scope、状態型の条件はどれもアプリが足せる語彙で、同じ規則で扱いたい。

## Decision

### 登録の形

条件に使える項目(`match` の key、寿命型の scope の名前、状態型の条件の名前)は、組み込みもアプリも同じ形で登録する。

```
register(key, impl, depends: [key...])
```

- `key`: 項目の名前。組み込みは接頭辞なし(`signing_id`、`cwd`)か `os.` / `time.`、アプリは `app.`。
- `impl`: 項目の種類ごとの実装。matcher の項目は照合する関数、寿命型は世代を返す関数、状態型は真偽を返す関数。
- `depends`: この項目の値が意味を持つために、同じ `match`(寿命型なら同じ `conditions`)に値ごと pin されていなければならない項目の列。
- 登録先は procline-acl の `Vocabulary`。matcher の項目、scope、条件が同じ器に入る。
- `depends` に挙げた key が未登録なら、登録の時点でエラー。循環もエラー。

### 組み込みの depends

| 項目 | depends | 理由 |
| --- | --- | --- |
| `signature_valid` | (なし、根) | 署名の検証が通ったこと。値は真偽。署名系の項目はすべてここに依存する |
| `cdhash` | `signature_valid` | 検証が通っていない cdhash は、何を指すか保証がない |
| `team_id` | `signature_valid` | 同上 |
| `signing_id` | `team_id` | signing identifier は開発者が自由に決める値で、ad-hoc 署名でも名乗れる。単独では弱く、Team ID と組でだけ意味を持つ |
| `bundle_id` | `team_id`、`signing_id` | Info.plist は誰でも書ける。署名者と signing identifier の組に乗せてだけ使う |
| `os.wake` | `os.boot` | 起床の回数は起動セッションの中でだけ意味を持つ |
| `os.screen_unlock` | `os.boot` | 同上 |

寿命型にも同じ規則を当てはめる。ルールの `conditions` に `os.wake` を置くなら `os.boot` も置く。表に無い組み込みの項目(`unique_id`、`uid`、`path`、`cwd`、`argv`、`os.login_session`、`process` など)は depends を持たない独立項目。

### 規則と各部品の責務

規則は 1 つ: **depends に挙がった項目は、同じ match に値ごと pin されている**。

| 誰 | 何をする |
| --- | --- |
| builder(`SubjectBuilder` / `RuleBuilder`) | 利用者には項目を 1 つ選ばせる(多くは葉)。選んだ項目から根までの祖先は、builder が収集結果の値で埋める。利用者に祖先を手で選ばせない |
| 読み込み(`Policy::load_verified`) | 欠け(ある項目の depends の項目が同じ match に無い)はエラー。矛盾(同じ項目に食い違う値が与えられている)はエラー。重複(複数の葉が同じ祖先を共有し、値が一致している)は正常 |
| 評価 | 連鎖全体を見る。match の項目をすべて AND で照合し、葉だけを見て祖先を省くことはしない |
| UI(アプリ側。procline-acl は連鎖の列挙と並び順を提供する) | depends のある項目は、連鎖(depends で繋がった項目の集まり)ごとに 1 つの選択肢として見せ、候補を強度順に並べる(例: 署名の連鎖なら `signature_valid` < `team_id` < `signing_id` < `bundle_id`、別の枝に `cdhash`)。選ぶと、その項目から根までが pin される。依存の無い独立項目はそのまま並べる |

match の保存形は平坦な map(`key → 値`)。連鎖の構造は Vocabulary が知っているので、保存形に入れ子を持たせない。ただし平坦な map では「矛盾」が構造上起きにくく、loader の検査が何を対象にするかは裁定待ち(QUESTIONS.md の PL-Q1)。本 DR は「欠け・矛盾はエラー」「矛盾は同じ項目に食い違う値」までを決める。

### 強さの 2 軸

| 軸 | 何を表すか | 値 |
| --- | --- | --- |
| クラス(連鎖の間) | 同じ uid のプロセスがその値を偽れるか | `Strength { Strong, Medium, Weak }` |
| 深さ(連鎖の中) | どれだけ絞るか。葉ほど祖先の値をすべて pin するので厳しい | `Depth`(根からの距離) |

- クラスは連鎖に 1 つ。登録するときに根(depends が空の項目)に与え、depends を持つ項目は根のクラスを引き継ぐ。複数の根に至る項目は、最も強い根のクラス(AND は条件を狭めるだけなので)。
- 独立項目は 1 項目だけの連鎖で、自分が根。クラスは unique\_id、uid、署名系が Strong、実行パスと責任プロセスが Medium、名前、argv、cwd、tty、env が Weak。
- bundle\_id は Strong の連鎖の葉(`team_id`、`signing_id` に依存)。実行パスは Medium の独立項目。
- `Strength` は procline-core に置く共有型。どの項目がどのクラスかは Vocabulary が持つので、`ProcessInfo` の各項目は Strength を持たない。
- ルールの強さの制約はクラスで判定する(算出の規則は [DR-0003](DR-0003-rule-strength-from-own-match.md))。深さは制約に使わず、UI の並び順と、アプリが追加で課す制約の材料にする。

## Alternatives Considered

- 案 A: 項目ごとに固定の強さだけを持ち、depends を持たない
  - 不採用理由: `signing_id` や `bundle_id` を単独の条件として許すことになる。ad-hoc 署名なら `signing_id` を、Info.plist を書けば `bundle_id` を誰でも名乗れるので、強い項目に見えて同じ uid のプロセスに偽られる。「署名と組でなければ弱い」のような注記では型として検査できない。
- 案 B: 連鎖を保存形に入れ子で持つ(葉ごとに祖先の値を持つ)
  - 不採用理由: 同じ祖先の値を葉ごとに繰り返して書くことになり、現行の JSON 例より読みにくい。連鎖の構造は Vocabulary が持っているので保存形に要らない。ただし「矛盾」の検査対象が平坦な map では消えるので、どちらを採るかは裁定待ち(QUESTIONS.md の PL-Q1)。入れ子を採る裁定が出たらこの DR を改める。

## Consequences

- アプリが足す項目も depends を宣言でき、組み込みと同じ検査(登録時の未登録・循環、読み込み時の欠け・矛盾)を受ける。
- 承認画面は項目を 1 つ選ぶだけでよく、祖先の pin は builder が埋めるので、利用者が組を作り損ねることがない。
- 一覧を手で書く場合は、葉に加えて祖先もすべて書く必要がある(欠けは読み込み時にエラー)。
- `ProcessInfo` は強さを持たないので、収集の crate は強さの規則を知らずに済む。強さの規則を変えても収集側は変わらない。

## 関連

- [DESIGN-ja の「項目の登録と depends」「強さ: クラスと深さ」](../DESIGN-ja.md)
- [DR-0001](DR-0001-crate-naming.md): crate の分け方(`Strength` を置く procline-core、`Vocabulary` を置く procline-acl)
- [DR-0003](DR-0003-rule-strength-from-own-match.md): ルールの強さを対象プロセス自身の条件から算出する
- [QUESTIONS.md の PL-Q1](../QUESTIONS.md): match の保存形と「矛盾」の対象
