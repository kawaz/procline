# DR-0012: プロセスとコードを特定する項目の強さのクラスは、照合したプロセスの保護の状態で決め、評価のたびに確かめ直す

- Status: Accepted
- Date: 2026-11-15

## Context

強さのクラスは、その条件が承認した個体・コードをどれだけ特定するかで決める ([DR-0009](DR-0009-strength-class-as-specificity.md))。弱は「同じ uid なら誰でも満たせる」。署名由来の `binary`、`process`、root 所有の `path` は強で、その前提として「署名の identity がそのプロセスの code を表している」ことを置き、hardened runtime の無い署名済バイナリの乗っ取りは範囲外としていた。

macOS 26.5.2 で、同じ uid の root でないプロセスから試験プログラム (署名だけを変えたもの) と Developer ID で署名した実物に 4 つの手段を当てた観測 (別リポ pam-passkey の findings `2026-11-15-process-memory-probe.md`、`2026-11-15-add-setup-process-protection.md`。要点はここに書く):

| 対象の署名 | entitlement を持たないプロセスからの task port と ptrace | 宣言済みのデバッガ (`com.apple.security.cs.debugger` を自分に付けた ad-hoc 署名のプロセスでもなれる) | 起動時の `DYLD_INSERT_LIBRARIES` |
|---|---|---|---|
| hardened runtime なし、`get-task-allow` なし | カーネルが断る | カーネルを通り、利用者の認可の段に進む。認可があれば読み書きできる | 読み込まれる |
| hardened runtime、`get-task-allow` なし | カーネルが断る | カーネルが断る (認可があっても) | 読み込まれない |
| hardened runtime、`get-task-allow` あり | カーネルが断る | 認可があれば読み書きできる | dyld は変数を読むが、library validation が Team ID の不一致で拒む |
| hardened runtime なし、`get-task-allow` あり | 取れる。読み書きでき、ptrace も接続できる | 同上 | 読み込まれる |

- 起動時に差し込んだライブラリの constructor は `main` より前に、そのバイナリのコードの身元で動く。Keychain の ACL (コードの身元で判定する) も通った。つまり hardened runtime でない署名済みのバイナリは、乗っ取らなくても、攻撃者が自分で `DYLD_INSERT_LIBRARIES` を付けて起動するだけで、そのコードの署名由来の条件を満たす攻撃者のコードを動かせる
- 攻撃者が使うバイナリは、承認した時のプロセスと同じファイルである必要は無い。Team ID と signing identifier の条件は、同じ身元で hardened runtime なしに署名された別のビルド (古い版、開発中の版) でも満たせる。持ち込めばよい
- 利用者の認可のダイアログは、要求したプログラムも対象のプロセスも示さず、Touch ID で応じられ、1 度下りると 10 時間共有される。強い境界ではない
- カーネル (AMFI) が「hardened」と扱う基準は CodeDirectory の flags ではない。Xcode の `sample` (flags は `library-validation` だけ) にも、platform binary の `/usr/bin/sample` にも、宣言済みのデバッガの要求は「is hardened, … doesn't have get-task-allow」で断られた。platform binary の `/usr/bin/leaks` への差し込みも効かなかった。走っているプロセスの動的な status (`kSecCodeInfoStatus`) では、観測した platform binary 4 つ (launchd、zsh、configd、sudo) は全部 `CS_RUNTIME` (0x10000) を持ち、sudo は flags に hardened runtime が無いのに status にはあった
- 保護を緩める entitlement のうち、`com.apple.security.cs.allow-dyld-environment-variables`、`com.apple.security.cs.disable-library-validation`、`com.apple.security.cs.disable-executable-page-protection` は、一次資料が差し込みや改変を許すと書くだけで、観測していない

この状況で、hardened runtime の無い署名済みのバイナリに `binary {team_id, signing_id}` で制限なしの `allow` を与えると、同じ uid の攻撃者がそのバイナリ (か同じ身元の別のビルド) に差し込んで、条件を満たすプロセスを作れる。クラスの定義に照らせば弱にあたる。

- 目的: ACL の強さのクラスが、同じ uid の攻撃者が実際に満たせる条件を強と数えない
- 増やしたくないもの: 推定によるクラス (観測の無い組は弱い側に倒す)、評価の手順の分岐

## Decision

### 保護の状態

照合したプロセスの検証に成功した署名 ([DR-0011](DR-0011-verified-signature-and-trust-mark.md) の `VerifiedSignature`) の、カーネルの動的な status と entitlements から決める。

| 状態 | 条件 |
|---|---|
| 保護あり | status の `CS_RUNTIME` があり、`debugged` でなく、保護を緩める 4 つの entitlement (`com.apple.security.get-task-allow`、`…cs.allow-dyld-environment-variables`、`…cs.disable-library-validation`、`…cs.disable-executable-page-protection`) のどれも無い (key があれば値を見ない) |
| 認可で開く | status の `CS_RUNTIME` があり、`debugged` でなく、4 つのうち `get-task-allow` だけがある |
| 開いている | 上のどちらでもない (`CS_RUNTIME` が無い、`debugged`、`get-task-allow` 以外の 3 つのどれかがある)。署名を検証できなかった (`Failed`、`Unsigned`、`NotChecked`、収集しなかった) 時もこれ |

`process` だけは、走っている個体を乗っ取る経路しか関係しないので、もう 1 つ区別する: `CS_RUNTIME` が無く、4 つのどれも無く、`debugged` でない時は「認可で開く」(宣言済みのデバッガの要求が利用者の認可の段に進むだけで、entitlement を持たないプロセスは断られる。観測)。

### クラス

| 項目 | 保護あり | 認可で開く | 開いている |
|---|---|---|---|
| `binary` の署名由来の field (`team_id`、`signing_id`、`bundle_id`、`cdhash`) | 強 | 中 | 弱 |
| `binary` の `digest` だけ | 中 | 中 | 弱 |
| `path` (root 所有で利用者が書けない場所) | 強 | 中 | 弱 |
| `path` (利用者が書ける場所) | 中 | 中 | 弱 |
| `process` | 強 | 中 | 弱 |
| `name`、`cwd`、`argv`、`uid`、`gid`、`tty` | 弱 | 弱 | 弱 |
| 責任プロセス | 中 | 中 | 中 |

- `binary`、`path`、`digest` は「そのコードから新しく起動したプロセス」も満たすので、起動時の差し込みと、起動した後に認可で開くことの両方を見る
- 「認可で開く」を中にするのは、満たすのに利用者の認可が要り、同じ uid のプロセスだけでは満たせないため。認可は強い境界ではないので強にはしない
- `get-task-allow` 以外の 3 つの entitlement は観測していないので、開いている (弱い側) に倒す
- platform binary も同じ規則で決める。観測した platform binary は status に `CS_RUNTIME` を持ち、宣言済みのデバッガは断られ、差し込みは効かなかった
- 責任プロセスは、今回の観測の対象でないので中のまま (未観測)

### いつ決めるか

- grant を作る時 (`Policy::grant`) と評価の時 (`Policy::evaluate` / `explain`) は、照合したプロセスでクラスを決める
- 評価の時、`allow` の grant の自身への条件のクラスが、その grant の scope で満たせないものになったら (制約の表に照らして)、その grant を採用しない。id を `Decision.too_weak` に載せる。攻撃者が持ち込んだ保護の無い同じ身元のビルドが、保護のあるビルドで作った grant に当たるのを、ここで止める
- rule の build と一覧の読み込み (プロセスが無い時) は、保護ありとしたクラス (上限) で制約を検査する。`path` も同じで、root 所有で利用者が書けない場所を指しうる値は強として検査する。実際のクラスは grant を作る時と評価の時に、照合したプロセスで決まる
- `deny` と `ask` には制約をかけないので、評価の時のクラスで採否は変わらない

### 範囲

- 署名と保護の状態が示すのは、その code が差し込みや改変なしに動いていることまで。その code が何を実行するか (インタプリタが読むスクリプト、AI エージェントの操作) は表さない。署名済みのインタプリタを `binary` で書いた条件は、そのインタプリタが動かす任意のスクリプトにも当たる
- Linux の収集は保護の状態をまだ持たない。持つまでは、保護の状態で決まる項目は開いている (弱) として扱う

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| hardened runtime の無い署名済みのバイナリの乗っ取りを範囲外のままにする | 乗っ取りでなく、攻撃者が自分で起動して差し込むだけで署名由来の条件を満たせる (観測)。範囲外にすると、同じ uid の誰でも満たせる条件を強と数えることになる |
| クラスを grant を作った時のプロセスだけで決める | `team_id` と `signing_id` は同じ身元の別のビルドでも満たせる。保護のあるビルドで作った grant に、持ち込んだ保護の無いビルドが当たる。評価の時に照合したプロセスで確かめ直す必要がある |
| 保護の無いプロセスには署名由来の field を当てない (照合の側で外す) | `deny` が当たらなくなり、攻撃者が保護の無いビルドを使うだけで `deny` を外せる。照合は事実のまま行い、クラス (`allow` の制約) で扱う |
| 保護の状態を CodeDirectory の flags (`kSecCodeSignatureRuntime`) から取る | カーネル (AMFI) は flags に hardened runtime の無い Apple のコードも hardened と扱い、走っている sudo は flags に無いのに status にはあった (観測)。保護を決めているのは動的な status |
| 認可で開く状態を強にする | 利用者の認可のダイアログは要求元も対象も示さず、1 度下りると共有される (観測)。強い境界ではない |
| build と読み込みの時は弱い側 (開いている) で制約を検査する | 署名由来の field を持つ rule が全部弱になり、手書きの「このアプリは常に allow」が書けなくなる。評価の時に確かめ直すので、上限で検査しても弱い条件の grant は採用されない |

## Consequences

- hardened runtime の無い署名済みのアプリを `binary` で書いた `allow` には、制約の表が弱に課す scope が要る。保護のあるアプリ (公証済みの Developer ID は hardened runtime が要件) は今と同じく強
- 保護のあるビルドで作った grant に、同じ身元の保護の無いビルドが当たった時は、評価で採用されず `Decision.too_weak` に出る
- `path` の build と読み込みの時のクラスが中から強 (上限) に変わる。実際のクラスは grant と評価で決まる
- 評価のたびに、`allow` の grant の自身への条件のクラスを照合したプロセスで算出する。収集した署名の情報から決めるので、評価中に OS を呼ばない
- 開発用のビルド (Xcode の Debug は `get-task-allow` を付ける) は「認可で開く」になり、署名由来の field は中
- 未観測の点:
  - `allow-dyld-environment-variables`、`disable-library-validation`、`disable-executable-page-protection` を持つ対象への差し込みと接続 (弱に倒している)
  - 宣言済みのデバッガと認可が、root が降格して起動した対象にどう働くか (認可がある時)
  - 開発者モード (`DevToolsSecurity -enable`) の Mac での、認可の段の振る舞い
  - SIP を無効にした Mac
  - Linux での保護の状態の取り方
  - 責任プロセスの強さを保護の状態で変えるべきか

## 関連

- [DR-0009](DR-0009-strength-class-as-specificity.md): クラスの定義 (この DR が署名由来の field、`path`、`process` のクラスの決め方を置き換える)
- [DR-0011](DR-0011-verified-signature-and-trust-mark.md): 検証した署名の型 (`RuntimeState`、entitlements)
- [DR-0003](DR-0003-rule-strength-from-own-match.md): ルールの強さは自身への条件で決める
- [DR-0008](DR-0008-evaluation-semantics.md): 評価の手順 (この DR が `allow` の採否の確かめ直しを足す)
- [DESIGN-ja の「脅威モデルの前提」「強さ: クラスと深さ」「評価」](../DESIGN-ja.md)
- pam-passkey (`~/.local/share/repos/github.com/kawaz/pam-passkey/main`): findings `2026-11-15-process-memory-probe.md`、`2026-11-15-add-setup-process-protection.md`
