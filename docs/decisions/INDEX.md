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
| [DR-0001](DR-0001-crate-naming.md) | N/A | crate 名を procline / procline-core / procline-macos / procline-acl にし、入口は procline |
| [DR-0002](DR-0002-matcher-depends-and-two-axis-strength.md) | ⬜ 未実装 | matcher の項目を depends 付きで登録し、depends は同じ match に値ごと pin する。強さはクラスと深さの 2 軸 |
| [DR-0003](DR-0003-rule-strength-from-own-match.md) | ⬜ 未実装 | ルールの強さは対象プロセス自身への条件のクラスで決め、祖先への条件は数えない |
