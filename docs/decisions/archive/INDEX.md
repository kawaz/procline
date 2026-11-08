# 退避した Decision Records

後続の DR に置き換えられた DR。各ファイルの `Status: Superseded by DR-NNNN` が正本で、現役の文書からはここも各ファイルも名指ししない (置き換え先を指す)。

| DR | タイトル | 説明 | 置き換え先 |
|---|---|---|---|
| [DR-0002](DR-0002-matcher-depends-and-two-axis-strength.md) | matcher の項目を登録制にして depends を持たせ、強さをクラスと深さの 2 軸で表す | 項目の key の間に depends を宣言し、depends は同じ match に値ごと pin する | [DR-0006](../DR-0006-structured-values-instead-of-depends.md) |
