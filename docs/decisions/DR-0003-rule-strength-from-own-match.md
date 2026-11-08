# DR-0003: ルールの強さは対象プロセス自身への条件から算出する

- Status: Active
- Date: 2026-11-08

## Context

ルールの強さ(クラス)は、`allow` に許す scope の制約を決める(強なら制限なし、中なら期限か世代の scope、弱なら世代の scope が要る)。subject は対象プロセス自身への条件(`match`、`tags`)と、祖先への条件(`ancestors`)を持てるので、どの条件から強さを決めるかを定める必要がある。

祖先への条件は、祖先を特定しても対象プロセス自身を縛らない。例えば「Team ID が ABCDE12345 のターミナルの子孫」は、そのターミナルから起動されたプロセスなら何でも当たる。

## Decision

- ルールの強さは、subject のうち **対象プロセス自身への条件**(`match` と、`tags` が指すタグの定義の自身への条件)のクラスのうち最も強いもの。
- `ancestors` の条件は数えない。`include_self` があっても同じ(「自身か祖先のどれか」であって、自身を pin していない)。
- 自身への条件が何も無い subject(`ancestors` だけ)は最弱(Weak と同じ制約)。
- タグを条件にしたときの強さは、タグの定義の subject を同じ規則で算出したもの。
- 制約の表(強 / 中 / 弱 → `allow` で許される scope)はクラスで判定する。深さ([DR-0006](DR-0006-structured-values-instead-of-depends.md))は制約に使わない。

## Alternatives Considered

- 案 A: subject の中で最も強い条件(祖先への条件を含む)で決める
  - 不採用理由: 祖先への条件は対象自身を縛らないので、祖先が Strong の項目で特定されていても、対象は「その子孫なら何でも」になる。祖先の強さを数えると、同じ uid のどのプロセスでもその祖先の下で起動すれば当たるルールに、制限なしの `allow` を許してしまう。

## Consequences

- `ancestors` だけで定義したタグ(DESIGN-ja の例の `claude-pj1`)は Weak で、それを subject にした `allow` ルールには世代の scope(`os.login_session`、`os.session`、`app.unlock` など)が要る。
- 祖先で絞った上で制限の緩い許可を出したいときは、対象自身にも強い条件(署名由来の field を持つ `binary` など)を付ける必要がある。

## 関連

- [DESIGN-ja の「ルールの作成と強さの制約」](../DESIGN-ja.md)
- [DR-0001](DR-0001-crate-naming.md): crate の分け方
- [DR-0006](DR-0006-structured-values-instead-of-depends.md): 項目の登録と、強さのクラスと深さ
