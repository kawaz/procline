# 裁定・確認待ち一覧 (ユーザ用)

## 運用規約

<details>
<summary>ゼロコンテキストエージェント向け（本セクションは消さない）</summary>

- 裁定/確認待ち項目を 1項目=1ラベル=1セクション で記載
- ラベル形式: XX-Q1（XX は 2-3 文字、バッチやセッション内で一意、Qn単独の使い回し禁止、長期一意性は不要)
- 依頼形式: 「👺XX-Q1 の裁定お願いします」（参照用途ではラベルに👺を付けない。誤陽性がユーザのハイライト/アラームを汚す）
- チャット提示と同一ターンで本ファイルに記録 + path 指定 commit (push はリリース窓に同乗)
- 裁定が下りたら該当セクションを即削除し、内容は正規の記録先 (DR / issue / journal / close_reason) へ反映。本ファイルは常に「現在待ち」だけを持つ
- 参照は[]()で提示（リポ内は相対、リポ外はフルパス）
- 初版質問/依頼は長文で書かない（ユーザが説明を求めらたら本ファイルに説明を追加し、チャットで👺ラベルで再依頼）
- **選択肢・確認項目は `- [ ] a: …` 形式（チェックボックス + ラベル）で書く**。Q / C で記法を分けない。回答は「チェックを付ける」でも「XX-Q1a」と言葉で返すでも通る（複数まとめてチェックし「チェックしたよ」の一言で済ませる運用を想定）

</details>

## 裁定待ち

HO-Q4 は、別リポ (kawaz/pam-passkey) の作業から出た問いをこのリポに移したもの。推奨は起票側のもの。判断の軸は procline 自身の層と型の設計で、特定のアプリの都合ではない (kawaz 2026-11-15)。

### 👺HO-Q4: アイコンを収集の中に持つか、外に出すか

選択肢を書き直した (前の a「外す」は今の b)。今は `ProcessInfo.icon_png` と `CollectOptions.icon` があり、未実装で常に `None`。[DR-0015](decisions/DR-0015-icon-outside-collection.md) (提案) は外に出す案。

収集の中に持つことの良い面:

- 1 回の収集で、表示に要るもの (名前、パス、bundle、アイコン) が列と一緒に揃う。アプリが収集の後にパスを渡して別の関数を呼ぶ 2 段にならない
- `CollectOptions.icon` で切れる。`digest` / `bundle` / `signature` と同じ形で、feature で型が変わらない
- 今ある field と JSON の形がそのまま使える

悪い面:

- ImageIO と CoreGraphics を、アイコンを使わない利用者のバイナリにもリンクする (読み込みのコストは未計測。AppKit は要らないことを観測済み)
- `icon: true` の収集は、列の全部の行の `.icns` を読む。最初の 1 つは 10〜27 ms、2 つ目からは 1.7〜3.3 ms (観測)。切れば 0
- アプリが cdhash でアイコンをキャッシュしていても、「無い分だけ取る」ができない (全部取るか、全部取らないか)
- 同じ uid が中身を決められる `.icns` を画像のデコーダに渡す。`icon: false` なら通らない。Info.plist と同じく、読む大きさの上限が要る
- JSON が大きくなる (PNG を base64 で持つ)

取れない app (アイコンを宣言しない、アセットカタログだけ) は `None` になるだけで、問題ではない。DR-0015 が外す理由にした AppKit は、ImageIO で取れば収集の中に置いても要らない。特定のアプリが AppKit を読み込めない、という事情は理由にしない。

- [ ] a (統括の推奨): 収集の中に持つ。ImageIO で実装し (AppKit を使わない)、`CollectOptions.icon` で選ぶ。DR-0015 は「ImageIO で実装する」決定に書き直す
- [ ] b: 外に出す (DR-0015 のまま)。型とオプションからアイコンを消し、実行パスから PNG を返す feature `icon` の関数にする。使わない利用者に ImageIO が入らず、キャッシュに無い分だけ取れる
- [ ] c: a に加えて、ImageIO のリンクを feature `icon` で切れるようにする (field は常にあり、feature が無いと `icon: true` でも `None`)

### 👺LJ-Q1: DR-0016 (一覧と grant の JSON の読み書き) を採るか

提案中の [DR-0016](decisions/DR-0016-list-and-grant-json.md)。未実装の読み込みの入口 (`Policy::load_verified`、`Policy::load_grant`) と書き出しを実装する前提になる。分岐のないところ (crate が読む側も書く側も持つ、未知のキー・重複・空はエラー、版は持たず新しさの検査はアプリの `PolicyVerifier`、自動の grant は読み込みが作って永続化しない) は DR の「どの選択肢でも変わらない部分」。裁定待ちの分岐は 7 つで、J2・J4・J5 は既存の DR の型や trait を改める。

具体例 (説明のために足した)。端末の中の `claude` が `git push` をして、`ssh` が鍵を持つアプリに繋いでくる場面。列は `ssh` ← `git` ← `claude` ← `zsh` ← `login` ← Ghostty ← launchd。

アプリが持つ一覧 (J1 の b の形):

```json
{
  "subjects": [{ "name": "ghostty", "subject": { "match": { "binary": { "team_id": "24VZTF6M5V", "signing_id": "com.mitchellh.ghostty" } } } }],
  "tags": [{ "tag": "terminal-app", "subject": "ghostty" }],
  "rules": [
    { "id": "ssh-in-terminal", "effect": "allow",
      "subject": { "match": { "path": "/usr/bin/ssh", "process": true }, "ancestors": [{ "tags": ["terminal-app"] }] },
      "targets": ["github-*"], "conditions": [{ "age": "1h" }, { "uses": 3 }] },
    { "id": "no-curl", "effect": "deny", "subject": { "match": { "path": "/usr/bin/curl" } } }
  ]
}
```

操作の流れ: 承認画面で利用者が `ssh-in-terminal` を選ぶ → `Policy::grant` が `"process": true` をこの `ssh` の個体の識別子で埋め、`age` を 1 時間後の `until` に直し、`uses` の残り 3 を pin した grant を返す → アプリが grant を JSON に書き出して署名し、保存する → 評価のたびに残りが減り、そのつど保存し直す → アプリを再起動したら、一覧を `load_verified` で、保存した grant を `load_grant` で読む。

この流れの中で、各分岐が効く所:

- J1: `ghostty` という名前付きの subject を、一覧のどこにどう書くか
- J2: `"process": true` を読む時、今は key が `process` だと知らないと正しい値にできない (`path` の `true` とは別の型)。a は `true` を 1 つの値に揃えて、key を見ずに読めるようにする
- J3: アプリが、保存した grant のバイト列を `load_grant` (署名の検証と検査) を通さずに、直接 `Grant` の型として読めるか。b は読めなくする
- J4: 保存した grant の `uses` の残りが壊れていた (数でない) 時。a は読み込みは通り、評価の時に黙って失効する。b は `load_grant` がエラーにして、アプリが気づける
- J5: `no-curl` は承認なしで効いてほしい deny。読み込みが自動で grant にする。自動にしてよいのは「承認の時の値 (pin 値) を持たない rule」で、`ssh-in-terminal` (`uses` と `process: true` を持つ) は対象外。その見分けを項目に聞く口を足す。同じ口で、`uses` を持つ grant より持たない grant を先に採用する (残りを無駄に減らさない) 順も決まる
- J6: 自動で作った `no-curl` の grant の id (`rule:no-curl`) と作成時刻
- J7: 一覧の tag 名を `terminl-app` と書き間違えた時、エラーが「`/rules/0/subject/ancestors/0/tags/0`」と場所を言うか、「未知のタグ `terminl-app`」だけか

- [ ] a (統括の推奨): 分岐のないところと、7 つの分岐の推奨を全部採る
- [ ] b: 採るが、下でチェックした分岐は推奨と違う案にする (案の記号か内容を教えてください)
  - [ ] J1 一覧の入れ物と名前付きの subject の形 (推奨 b: `subjects` / `tags` / `rules` の 3 つの配列)
  - [ ] J2 placeholder の型 (推奨 a: 値全体の placeholder を `MatchValue::Pin` 1 つにする。`process` / `responsible` の名指しが消える。DR-0007 の型の形を改める)
  - [ ] J3 ACL の型の公開の `Deserialize` (推奨 b: 持たない。JSON から値になるのは 2 つの入口だけ)
  - [ ] J4 grant の condition の検査 (推奨 b: `Condition` に検査の method を足す。DR-0004 の trait を改める)
  - [ ] J5 pin 値の性質の印 (推奨 a: `Condition` に 3 値の method を 1 つ足す。自動の grant の対象と採用の順が決まり、消費型の印の issue も片づく。DR-0008 の文言を改める)
  - [ ] J6 自動の grant の値 (推奨 a: `id` は `rule:<rule の id>`、`created_at` は epoch)
  - [ ] J7 検査のエラーの場所 (推奨 a: JSON Pointer で持たせる)
- [ ] c: 採らない・分岐のないところに異論がある (内容を教えてください)

### 👺SR-Q1: DR-0019 (条件の強さを、理由のコードと組で返す) を採るか

提案中の [DR-0019](decisions/DR-0019-strength-reasons-with-codes.md)。「判定の関数・結果の強さ・理由・コード」の 4 つ 1 組の表 (今のコードの判定を洗い出した 24 行) と、返し方。

例 (推奨を全部採った時に API が返すもの):

- Team ID で `binary` を条件にし、相手が `disable-library-validation` を持つプロセスだった → 強さ: 弱、理由: `protection.disable_library_validation` (上限 弱)
- `cwd` を条件にした → 強さ: 弱、理由: `cwd` (項目そのものが弱)、`cwd.snapshot` (収集した時点の値、という注意点。強さは下げない)
- `process` で、hardened runtime が無く `get-task-allow` もある → 理由が 3 つ返り (それぞれ中、中、組み合わせで弱)、強さは弱

分岐のないところ: 当てはまる理由は全部返す。コードは事実ごとに 1 つ (`binary` / `path` / `process` で共有)。項目そのものが弱い時のコードは項目の key。アプリの項目のコードは `app.` で始まる。subject 全体の強さと理由を返す口を足す。コードは変えてよく、廃止・改名・消えたコードの跡地を残す。

- [ ] a (統括の推奨): 分岐のないところと、7 つの分岐の推奨を全部採る
- [ ] b: 採るが、下でチェックした分岐は推奨と違う案にする
  - [ ] S1 コードの形 (推奨 a: `protection.disable_library_validation` のような `.` 区切りの文字列を、定数で持つ。enum にしない)
  - [ ] S2 結果の型 (推奨 a: 「コードと、その事実が抑える強さの上限」の列だけを持ち、強さはそこから出す。強さと理由が食い違えない)
  - [ ] S3 項目の実装 (推奨 a: `Matcher::class` の戻り値を変える。アプリが自分で実装した項目は書き換えが要る。DR-0006・DR-0009 の記述を改める)
  - [ ] S4 注意点 (推奨 a: 理由と同じ列に、上限が強のものとして載せる)
  - [ ] S5 評価で採らなかった grant (`too_weak`) に理由を付ける (推奨 a: 付ける。DR-0008・DR-0004 の型を改める)
  - [ ] S6 保護の状態の判定の置き場 (推奨 a: procline-core。収集だけの画面でも「保護なし」と理由を出せる。core に macOS の entitlement の名前が入る)
  - [ ] S7 コードの表の正本 (推奨 a: Rust のソースの定数)
- [ ] c: 採らない・分岐のないところに異論がある

## 確認待ち

### 👺HO-C1: 「allow の条件の強さを、照合したプロセスが守られているかで下げる」(DR-0012) を採るか

裁定してほしいのは [DR-0012](decisions/DR-0012-strength-class-from-protection.md) の 1 点。別のセッションが設計して実装まで済ませたもので、kawaz の裁定の記録が無い。[DR-0011](decisions/DR-0011-verified-signature-and-trust-mark.md) (署名は検証した事実だけを持つ) は、これの前提で、論点は無いと見ている。

何が決まるか: 「Team ID が X の binary を allow」のような署名由来の条件の強さ (強 / 中 / 弱)。強さごとに何を許すか (例: 弱なら 1 時間まで) は、アプリが与える表で決まる。

- DR-0012: 署名が正しくても、そのプロセスが hardened runtime でない、または保護を緩める entitlement を持つなら、弱にする。理由: 同じ uid の攻撃者は、その署名済みのバイナリを `DYLD_INSERT_LIBRARIES` を付けて自分で起動するだけで、中で自分のコードを動かせる (観測済み)。署名の条件は満たしたままになる
- 採らない場合: 署名が検証できれば、守られていなくても強

この Mac での帰結: `zsh` や `ssh` (Apple、保護あり) は強。Claude Code は公証済みで hardened runtime だが、entitlement `disable-library-validation` を持つので弱。Electron や node を抱える app の多くも同じ見込み。自作の ad-hoc のバイナリは弱。つまり「Claude Code を署名で長く allow」は、アプリの表が弱に長い allow を許さない限り、できなくなる。

統括の考え: 採る (a)。守る相手 (同じ uid の別プロセス) が実際に満たせる条件を強と呼ぶと、強さの意味が無くなる。悪い面は、よく使う app が弱に落ちて、利用者が「署名で allow したのに短い」と感じること。これは、強さごとの許し方を決めるアプリの表で調整する話。もう 1 つ、4 つの entitlement のうち 2 つ (`allow-dyld-environment-variables` 単独、`disable-executable-page-protection`) は、差し込む経路を観測しないまま弱に倒している (安全側)。

- [ ] a (統括の推奨): 採る (DR-0011 と DR-0012 をこのまま)
- [ ] b: 採るが、変えたい点がある (内容を教えてください)
- [ ] c: 採らない (署名が検証できれば、保護の状態で強さを変えない)
