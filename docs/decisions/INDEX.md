# Decision Records 一覧

Status は各 DR ファイルの `Status:` 行が正本。ここに載るのは今立っている DR だけで、置き換えられた DR は `archive/INDEX.md` に移す。

状態は絵文字とラベルだけ。日付・Phase・裁定の内訳は各 DR 本文に書く。

- `💭 提案`: Decision がまだ裁定されていない。実装に着手しない (本文の `Status: Proposed`)
- `✅ 実装済`: Decision の全部に実装エビデンスがある
- `🟡 部分実装`: 一部のみ実装
- `⬜ 未実装`: 裁定済みで設計のみ、実装エビデンスなし (着手してよい)
- `🚧 進行中`: 実装の途中
- `N/A`: 実装対象でない (命名・思想・プロセス等)
- `❌ 撤退`: 撤退判断済

| DR | 状態 | 説明 |
|---|---|---|
| [DR-0001](DR-0001-crate-naming.md) | N/A | crate 名を procline / procline-core / procline-macos / procline-acl にし、入口は procline。`os.*` の語彙は procline-macos が提供し(macos → acl の依存)、acl の builtin は OS 非依存の項目だけ |
| [DR-0003](DR-0003-rule-strength-from-own-match.md) | ✅ 実装済 | ルールの強さは対象プロセス自身への条件のクラスで決め、祖先への条件は数えない |
| [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md) | 🟡 部分実装 | 静的な rule と pin 済みの grant を分け、condition を observe / pin / check / advance で表す。評価は grant だけを見て、採用された grant だけを advance し、grant は 1 件ずつ永続化する |
| [DR-0005](DR-0005-process-identity-as-one-item.md) | ✅ 実装済 | プロセスの個体識別はルールの語彙では `process` 1 項目(Strong)。pin 値は取れた識別子と boot UUID の複合値で、両側に揃う識別子を全部比べて照合する。寿命型 scope の `process` は持たない |
| [DR-0006](DR-0006-structured-values-instead-of-depends.md) | ✅ 実装済 | key をまたぐ依存を持たず、`process` / `binary` / `os.session` は 1 つの key に構造を持つ値を置き、値の妥当性は項目自身が検査する。強さはクラス(項目が値から決める)と深さ(値の段階 / field の数)の 2 軸 |
| [DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md) | 🟡 部分実装 | rule の subject の値は具体値か placeholder(`true`)で、placeholder は `Policy::grant` が当たったプロセスの実値で埋める。`ancestors` は `match` と `tags` だけを持つ要素の順序付きの列で、近い側から貪欲に部分列として照合する |
| [DR-0008](DR-0008-evaluation-semantics.md) | 🟡 部分実装 | 評価は条件の判定 → deny > allow > ask の決定 → 採用した grant の advance → アプリの永続化の順で、書けてから結果を使う。`Policy::grant` / `evaluate` はメモリを変えず `add_grant` で効かせる。寿命型の失効はその場で確定して `expired` で返す。祖先への条件を持ち途切れた列で当たらなかった grant と、観測に失敗した condition を使う grant は `undecidable` で返す。既定の effect はアプリが与える。placeholder は rule の inline の subject だけで、自動で grant になるのは寿命型・消費型・placeholder・chain や観測値を要する pin を持たない rule だけ |
| [DR-0009](DR-0009-strength-class-as-specificity.md) | ✅ 実装済 | 強さのクラスは条件が承認した個体・コードをどれだけ特定するかで決める(`uid` は弱、`path` は場所で決まる)。制約の表はアプリが与え、crate は既定値を持たない。世代は事象固有の値にし、`process` は boot UUID を含めて全識別子の一致で照合する。`os.login_session` の pin 値は `{boot_uuid, asid}`、責任プロセスは `ProcessIdentity` で持つ |
| [DR-0010](DR-0010-or-in-values-and-tag-definitions.md) | 🟡 部分実装 | OR は値の列(`MatchValue::AnyOf`、1 段だけ・placeholder なし・空は不正)とタグの同名の複数定義の 2 か所にだけ置き、subject に `any_of` のような構文は足さない。列のクラスは要素の最弱、タグの強さは定義の最弱。同名タグの判定は三値の OR |

置き換えられた DR は [archive/INDEX.md](archive/INDEX.md) にある。
