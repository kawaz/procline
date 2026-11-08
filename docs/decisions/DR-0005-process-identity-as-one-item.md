# DR-0005: プロセスの個体識別をルールの語彙では `process` 1 項目に畳む

- Status: Active
- Date: 2026-11-08

## Context

収集の内部では、1 つのプロセスを特定する識別子が 4 種ある(audit token、unique\_id、pid と起動時刻の組、asid)。どれが取れるかは OS と API の可用性で変わる(接続相手には audit token があるが祖先には無い、unique\_id は SPI なので取れないことがある、Linux では pidfd と starttime になる)。

これらをルールの語彙に個別の項目として出すと、ルールを書く人に「どの識別子が取れる状況か」という収集の内部事情を学ばせることになる。また Linux の収集を足したときに、語彙そのものが変わる。

## Decision

- ルールの語彙では、プロセスの個体識別は `process` という 1 つの matcher 項目にする。意味は「この個体のプロセス」。収集の内部で使う識別子(audit token、unique\_id、pid と起動時刻、pidversion)はルール定義に個別には出さない。
- rule には placeholder の `true`(承認したその個体を pin)か具体値の複合を書く。pin 値は複合値で、grant を作るとき(`Policy::grant`)にその時点で取れた識別子と boot UUID を全部持たせる(例 `{"process": {"boot_uuid": "7B1E…", "unique_id": 12345, "pid": 501, "start_time": {"secs": 1762570683, "micros": 123456}}}`。boot UUID は [DR-0009](DR-0009-strength-class-as-specificity.md)。placeholder の解決は [DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md))。
- 照合は、両側に揃っている識別子を全部比べ、全部一致したときだけ当たる([DR-0009](DR-0009-strength-class-as-specificity.md))。最悪でも pid と起動時刻の組の一致を見る。ルールを書く人はどれで比べたかを気にしない。
- クラスは Strong。照合は完全一致だけ。`match` にも `ancestors` の中にも書ける(「このターミナルのタブのシェルの子孫」)。UI では「このプロセスだけ」の 1 選択肢として出す。
- 寿命型の scope としての `process`(「指定プロセスの終了まで」)は持たない。chain に居るプロセスの寿命は matcher の `process` で表す(そのプロセスが終われば chain に居なくなり当たらない)。死んだプロセスを指す grant の削除は掃除(アプリ)の責務([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md) の掃除と同じ)。

## Alternatives Considered

- 案 A: `unique_id` / `pid` 等を個別の matcher 項目にする
  - 不採用理由: どの識別子が取れるかは OS と API の可用性で変わるので、ルールを書く人に収集の内部事情を学ばせることになる。Linux を足したときに語彙が変わる。
- 案 B: 寿命型の scope `process` を残す
  - 不採用理由: matcher の `process` と重なる。残す利点は失効の検出だけで、その `check` が pin したプロセスの生存を観測しに行くと、「外の状態を読むのは observe だけ」([DR-0004](DR-0004-rule-grant-split-and-condition-advance.md))を崩す。縁を切ったバックグラウンドプロセスに元の親の寿命を付ける場面は想定しない(要れば `app.` で足せる)。

## Consequences

- UI はプロセスの個体識別を「このプロセスだけ」の 1 選択肢で出せばよく、識別子の種類を見せない。
- Linux の収集を足しても語彙は変わらず、同じ `process` の中身が pidfd と starttime になるだけ。
- 死んだプロセスを指す grant は当たらなくなるだけで失効扱いにはならないので、掃除で消す。
- `allow` の強さの制約では、`process` を自身の条件に持つルールは Strong になる([DR-0003](DR-0003-rule-strength-from-own-match.md))。

## 関連

- [DESIGN-ja の「識別子」「matcher」「項目の登録」](../DESIGN-ja.md)
- [DR-0006](DR-0006-structured-values-instead-of-depends.md): 構造を持つ値の座と強さのクラス(`process` は Strong)
- [DR-0003](DR-0003-rule-strength-from-own-match.md): ルールの強さと、`allow` に許す scope の制約
- [DR-0004](DR-0004-rule-grant-split-and-condition-advance.md): condition の observe / pin / check / advance と、grant の掃除
- [DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md): subject の placeholder と、grant を作るときの解決
- [DR-0009](DR-0009-strength-class-as-specificity.md): `process` の pin 値の boot UUID と、全識別子の一致
