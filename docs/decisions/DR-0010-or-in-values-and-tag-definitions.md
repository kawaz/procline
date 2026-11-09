# DR-0010: OR は値の列とタグの複数定義の 2 か所にだけ置き、subject に論理式の構文を足さない

- Status: Active
- Date: 2026-11-10

## Context

subject の中の条件は AND で、`ancestors` の要素の中も AND である。OR が要る条件(「Team ID が A か B」「引数が `/opt/a.sh` か `/opt/b.sh`」「祖先が Terminal か iTerm2」)を rule の分割だけで書くと、選択肢の数の積で rule が増える。祖先の選択肢が 2、対象の選択肢が 2、条件の組が 2 なら 8 本の rule になり、どれか 1 本を直し忘れると許可の範囲が食い違う。

一方で、ルールを読む人が入れ子の論理式を追わずに済むことは、subject を AND だけにした理由そのものである。OR を入れる場所と形を決めないと、どちらかを失う。

## Decision

subject の中は AND のまま、`ancestors` の要素も AND のまま。OR は次の 2 か所にだけ置く。subject に `any_of` のような論理式の構文は足さない。

| 置き場 | 書き方 | 意味 |
| --- | --- | --- |
| 値 | 1 つの key に値の列。JSON では配列(`"argv": [{"regex": "^/opt/a\\.sh$"}, {"regex": "^/opt/b\\.sh$"}]`、`"binary": [{"team_id": "A"}, {"team_id": "B"}]`) | その key について、列のどれかの値に一致すれば真 |
| タグ | 同じタグ名の定義を複数置く | どれかの定義に当たればタグが付く。項目をまたぐ選択肢を吸収する |

### 値の列

- 型は `MatchValue::AnyOf(Vec<MatchValue>)`。
- 列の中は 1 段だけ(列の入れ子は不正)。placeholder(`true`、構造を持つ値の field の `true` も)は列に入れられない。grant で 1 つの値に pin できないため。空の列は不正。
- 列は語彙が要素に分けて項目に渡し、項目(組み込みもアプリのものも)は列を見ない。`validate` は列の形を検査してから要素を項目の規則で検査し、`matches` は要素のどれかが真なら真、`resolve` は placeholder が無いので列をそのまま返し、`class` は要素のクラスのうち最も弱いもの。
- `argv` の列は「どれかの要素(正規表現)がどれかの引数に一致」。
- builder の入口は `SubjectBuilder::any_of(key, values)` / `AncestorBuilder::any_of(key, values)`(`exact` の列版)。列も 1 つの値で、同じ key の `pin` / `exact` とは合成しない(`BuildError::Conflict`)。

### タグの複数定義

- `Tag` の一覧で同名を許す。`Policy::tag` は同名の定義のどれかが当たればタグを付ける。判定は三値のままで、どれかが True なら True、全部が False なら False、それ以外は Unknown(`undecidable_tags`)。
- タグの循環の検査は名前単位。同名の定義のどれかが循環すれば不正。

### 強さ

- 値の列のクラスは、列の要素のクラスのうち最も弱いもの。どれでも通るので弱い側に倒す。
- タグは定義ごとに強さを算出し、タグを条件にしたときの強さは定義のうち最も弱いもの。自身への条件を持たない定義が 1 つでもあれば、そのタグは強さに何も足さない。

## Alternatives Considered

- 案 A: OR は rule を分けて書くだけにする
  - 不採用理由: 祖先 × 対象 × 条件の選択肢の積で rule が増える(組み合わせ爆発)。同じ意図の rule が何本にも分かれ、直すときに全部を揃える手間と、揃え損ねたときに許可の範囲が食い違う危険が増える。
- 案 B: subject に `any_of`(subject や条件の列の OR)を足す
  - 不採用理由: subject の中に入れ子の論理式が始まり、`any_of` の中の `ancestors` や、`any_of` の入れ子を読み手が追わなければならなくなる。subject を AND だけにした現行の方針に反する。強さの算出も、入れ子の各枝の自身への条件を辿る規則が要るようになる。

## Consequences

- ルールを読む人が追う論理は変わらない。「どれか」は値の列かタグ名の後ろに隠れ、subject の上では AND のままに見える。
- 列を使った条件とタグの複数定義のクラスは、弱い側に倒れる。強い選択肢と弱い選択肢を 1 つの列やタグに混ぜると、全体が弱い方の制約を受ける。強い選択肢だけの許可を広く通したいなら、列やタグを分ける。
- タグの定義の重複は正常で、読み込みはエラーにしない。同じ名前の定義は一覧の中で離れて置かれ得るので、承認画面や設定の表示はタグ名ごとに定義をまとめて見せる必要がある。
- アプリが登録する項目は列を扱う実装を持たなくてよい(語彙が要素に分けて渡す)。

## 関連

- [DESIGN-ja の「subject」「tag」「matcher」「強さ: クラスと深さ」「ルールの作成と強さの制約」「API の骨格」](../DESIGN-ja.md)
- [DR-0003](DR-0003-rule-strength-from-own-match.md): ルールの強さを対象プロセス自身への条件から算出する
- [DR-0007](DR-0007-pin-placeholders-and-ordered-ancestors.md): placeholder と `ancestors` の順序付きの列
- [DR-0009](DR-0009-strength-class-as-specificity.md): 強さのクラスの定義
