# DR-0009: 強さのクラスは、条件が承認した個体・コードをどれだけ特定するかで決める。世代は事象固有の値にし、識別子は boot UUID と組にする

- Status: Active
- Date: 2026-11-09

## Context

ルールの強さ(クラス)は、`allow` にどの scope を許すかの制約に使う([DR-0003](DR-0003-rule-strength-from-own-match.md))。クラスを「同じ uid のプロセスがその値を偽れるか」で定義すると、`uid` は偽れないので強になる。ところが `uid` の条件は同じ uid の全プロセスが満たすので、承認したものを何も特定しない。強なら制限なしの `allow` を許す制約の表では、同じ uid の全プロセスに無期限の許可が及ぶ。

制約の表そのもの(どのクラスにどの scope を許すか)は、許可の方針でありアプリが決めるものである。crate が既定値を持つと、方針を crate が決めることになる。

世代の値にも同じ種類の問題がある。`os.session` の `awake` / `unlocked` と `os.console_user` を、デーモンが通知を数える回数で表すと、デーモンが動いていない間の事象を数えられず、再起動を跨いだ grant を判定できない。`process` の pin 値も、両側に揃う最も強い識別子 1 つだけで比べると、再起動を跨いで同じ値が再び現れる識別子(pid、unique\_id)で取り違えうる。`os.login_session` の pin 値の asid も起動ごとに再利用され、責任プロセスを pid で持つと pid の再利用で取り違える。

## Decision

### クラスの定義

- クラスは、その条件が、承認した個体・コードをどれだけ特定するかで決める。3 段階(強 / 中 / 弱)と `Strength` 型はそのまま。
- 組み込みのクラス:

| クラス | 項目 |
| --- | --- |
| 強 | `process`、署名由来の field を持つ `binary`、root 所有で利用者が書けない場所の `path` |
| 中 | 責任プロセス、`digest`、利用者が書ける場所の `path` |
| 弱 | `name`、`cwd`、`argv`、`uid`、`gid`、`tty` |

- `uid` / `gid` が弱なのは、同じ uid の全プロセスが満たすので何も特定しないため。
- クラスは `Matcher::class(value, process: Option<&ProcessInfo>) -> Strength` が決める。`digest` のクラスは値で決まる。
- `path` のクラスは、収集側(procline-macos)が path ごとに取る属性(所有者と利用者の書き込み可否、`PathMeta`)で決まる。プロセスがある grant の作成時と評価時に強 / 中を判定し、プロセスが無い rule の build 時と読み込み時は中(弱い側)とする。
- 「利用者が書ける場所」は、ファイル自体か、パス上のいずれかのディレクトリに利用者が書ける(差し替えられる)こと。
- env は伏せた後の値しか持たないので照合に使えず(表示専用)、クラスを持たない。
- 署名由来の field は、署名の identity がそのプロセスの code を表している前提で強とする。hardened runtime の無い署名済バイナリは同じ uid のプロセスが乗っ取れるが、これは脅威モデルの前提として書き、クラスの判定には使わない(乗っ取られたプロセスの識別はこの crate の範囲外)。

### 制約の表はアプリが与える

- 制約の表(クラスごとに `allow` で許す scope の条件、`AllowConstraints`)はアプリが与える。crate は既定値を持たず、検査の仕組みだけを持つ。
- `Policy` が `AllowConstraints` を持ち(`Policy::load_verified` の引数)、`RuleBuilder::build`、`Policy::load_verified`、`Policy::grant`、`Policy::load_grant` が同じ検査に使う。違反は `BuildError::ScopeTooWeak` / `LoadError::ScopeTooWeak` / `GrantError::ScopeTooWeak`。
- 形は `AllowConstraints { strong, medium, weak }`(3 つとも必須)で、各値は `Unrestricted` か `AnyOf([Condition(key) | UntilWithin(duration)])`(列挙のどれか 1 つを満たせばよい)。
- 判定の時機: `age` の長さと寿命型の condition の有無は rule の build 時と読み込み時、`until` の絶対時刻は grant を作るとき(その時点の now)。
- どの scope が制約を満たすかもアプリの制約表が決める。crate は `uses` を世代の scope と同じ扱いにするような読み替えをしない。
- 文書の制約の表(強 = 制限なし、中 = `until` 7 日以内か世代の scope、弱 = 世代の scope)は、アプリが与える制約の例。

### 世代は事象固有の値

- `os.session` の世代は、デーモンが数える回数ではなく事象固有の値にする。`boot` は `kern.bootsessionuuid`、`awake` は直近の起床の時刻(`kern.waketime`)、`unlocked` は直近の解錠の時刻。
- `os.console_user` も同じく、ユーザーの切り替えの事象固有の値にする。
- どれもデーモンの再起動と無関係に一意なので、再起動を跨いで読み直した grant も正しく判定できる。

### 識別子と boot UUID

- `ProcessChain` が `boot_uuid: String` を持つ(収集側が `kern.bootsessionuuid` を取る)。
- `process` の pin 値に boot UUID を含める(`ProcessIdentity.boot_uuid: String`)。`Identity::process_identity(&self, boot_uuid)` には `ProcessChain.boot_uuid` を渡す。
- `process` の照合は、両側に揃っている識別子を全部比べて、全部一致したときだけ当たる(最も強い 1 つで比べるのではない)。
- `os.login_session` の pin 値は `{boot_uuid, asid}`。asid は起動ごとに再利用されるため。
- 責任プロセスは pid でなく `ProcessIdentity` で持つ(`ProcessInfo.responsible: Option<ProcessIdentity>`)。

## Alternatives Considered

- 案 A: クラスを「同じ uid のプロセスがその値を偽れるか」で定義する
  - 不採用理由: `uid` が強になり、`uid` だけの subject に制限なしの `allow` が許され、同じ uid の全プロセスに無期限の許可が及ぶ。偽れないことと、承認したものを特定することは別で、制約が守りたいのは後者。
- 案 B: クラスを 2 値(特定する / しない)にする
  - 不採用理由: 中(`until` の期限付きで許したい条件。責任プロセス、`digest`、利用者が書ける場所の `path`)が表せない。個体やコードをある程度は絞るが、同じ uid のプロセスが置き換えうる条件を、特定しない条件と同じ制約に押し込むことになる。

## Consequences

- `uid` / `gid` だけで絞ったルールは弱になり、アプリの制約表が弱に課す scope が要る。
- アプリは `AllowConstraints` を用意して `Policy::load_verified` に渡す必要がある。crate に既定の表は無い。
- `path` のクラスの判定のために、収集は path の所有者と利用者の書き込み可否を取る(`ProcessInfo.path_meta`)。`path` を自身の条件に持つ rule は、build 時と読み込み時には中として制約を検査し、grant を作るときに実際のプロセスで強 / 中を決めて検査し直す。
- 世代を事象の値にしたので、デーモンの再起動を理由に grant が失効することはなくなる。
- `process` の pin 値は boot UUID を持つので、再起動の後に同じ pid・unique\_id のプロセスが現れても当たらない。
- `os.login_session` の grant は、再起動の後に同じ asid のセッションが現れても当たらない。

## 関連

- [DESIGN-ja の「概要」「収集する情報」「強さ: クラスと深さ」「ルールの作成と強さの制約」「scope: grant の寿命」「matcher」](../DESIGN-ja.md)
- [DR-0003](DR-0003-rule-strength-from-own-match.md): ルールの強さを対象プロセス自身への条件から算出する
- [DR-0005](DR-0005-process-identity-as-one-item.md): `process` の値の形と照合
- [DR-0006](DR-0006-structured-values-instead-of-depends.md): 構造を持つ値の座と、強さのクラスと深さ
- [DR-0008](DR-0008-evaluation-semantics.md): 評価の意味論(失効の確定)
