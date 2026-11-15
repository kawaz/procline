---
title: 署名の検証と収集の実装へのレビューの指摘 (7 件)
status: open
category: bug
created: 2026-11-15T09:25:00+09:00
origin: pam-passkey のセッションから (別系統のレビュアーによる検査)
---

# 署名の検証と収集の実装へのレビューの指摘 (7 件)

DR-0011 / DR-0012 の実装 (2026-11-15) を別系統のレビュアーが検査した結果。どれもコードの読み取りによる指摘で、再現は確かめていない。採否の前に、該当箇所を読んで裏を取ること。重いと見られる順。

1. `crates/procline-macos/src/collect.rs:367` — 祖先が収集の途中で exec しても、記録した署名が無効にならない。署名を検証した後、属性を読む前に祖先が exec すると、最後の検査 (`same_individual`) は exec を許すので、返る path と argv は新しいイメージのもの、`code_signing` は古いイメージのものになる
2. `crates/procline-core/src/verify.rs:166` — 要求なしの検証と署名の情報の取得の間に実行ファイルが差し替えられると、差し替え先の identifier と cdhash が、検証に成功した結果に付く。証明書の無い (ad-hoc の) 結果では、その後の requirement の評価が無いので、変化に気づかない
3. `crates/procline-macos/src/sys/security.rs:221` — subject の要約を持たない証明書で、収集が panic しうる。`SecCertificateCopySubjectSummary` は NULL を返しうるが、security-framework の `subject_summary` は NULL でない前提で包んでいる
4. `crates/procline-macos/src/sys/security.rs:212` — 証明書の配列が無い、または要素を取り出せない時を、ad-hoc 署名の証拠として扱う。`certificates()` が黙って空か短い列を返し、検証は空を `AdHoc` に分類する (署名者の情報を確かめられなかった、とは報告しない)
5. `crates/procline-core/src/signature.rs:327` — cdhash の読み込みが `+` を受け付ける。40 文字で先頭が `+f` の値は `u8::from_str_radix` を通り、書き出すと `0f` に変わる
6. `crates/procline-macos/src/signing.rs:81` — 検証の予算が 0 でも、requirement を 6 本コンパイルする (検証しないのに、その同期の費用を払う)
7. `crates/procline-macos/src/sys/security.rs:116` — `SecCodeCopySigningInformation` が出力のポインタを埋めたうえで 0 以外を返した時、辞書を解放しない

同じ検査で確認されたこと: 手順・印の 11 値・失敗の分類・クラスの表の全セル・確かめ直しは DR と整合。「検証に失敗なのに identifier を持つ」形は型でも serde でも作れない。`Policy::load_verified` と `Policy::load_grant` は `todo!()` のままで、読み込みの経路での「上限で検査する」は検証できていない。

## 指摘ごとの結果

1. **該当、直した**。腕を重複させた途中の修正のまま実機で再現した: 祖先 (sh) の `code_signing` が exec の前の `com.apple.bash`、`path` と `argv` が exec の後の `/bin/sleep` のまま `Ok` で返った。最後の確かめ直しで、同じ個体のまま pid version が変わった祖先は結果を捨てて `IdentityChanged` にし、終わった祖先は従来どおり列をその手前で `AncestorExited` で終える。収集を記録・署名の検証・属性の読み取りと確かめ直しの段に分け、テスト (`collect::tests::the_recheck_tells_an_ancestor_exec_from_an_ancestor_exit`) は段の間で sh に exec させる / 終わらせる (kqueue の `NOTE_EXEC` と `wait` で待ち、時間待ちをしない)。何も起きない・exec・終了の 3 通りを固定し、腕を `same_individual` の重複に戻すとテストが落ちることも確かめた
2. **該当しない (macOS 26.5.2 で観測)**。走っている ad-hoc のコード (テストのバイナリのコピー) で、要求なしの検証と署名の情報の取得の間に実行ファイルを、Apple の署名のファイル・identifier を変えた ad-hoc のファイル・削除の 3 通りで差し替えた。3 通りとも、差し替えの前に開いた SecCode は検証した静的なコードを持ち続け、署名の情報は走っているコードのもの (`verified_from` は disk) だった。対照として、差し替えの後に開き直すと気づく (置き換えは running_code に切り替え、削除は `Failed(Missing)`)。SecCode.h は「Code の署名の情報の一部はディスクから読む」と書くので、OS の更新で変わりうる。テスト (`signing::tests::replacement_between_the_check_and_the_signing_information`) で、結果が走っているコードの身元か `Failed` であることを、対照と合わせて固定した
3. **該当、直した**。subject が空の自己署名の証明書 (openssl で作成、`tests/fixtures/empty-subject.der`) で `SecCertificateCopySubjectSummary` が NULL を返し、security-framework 3.7.0 の `subject_summary` は `Attempted to create a NULL object.` で panic した (変異で確かめた)。`Certificate.summary` を `Option<String>` にし (JSON は null)、関数を自前で包んで NULL を None にする。DR-0011 の JSON の節に `summary` の説明を足した。テストは、fixture の要約が None になること (対照: launchd の leaf は `Software Signing`)、JSON の null の往復、要約の無い証明書でも印が requirement だけで決まること (根が Apple でなければ `other_certificate`)。その証明書で実際に署名したプロセスの検証は観測していない: `codesign` で自己署名の identity を使うには鍵束への取り込みと信頼の設定が要り、鍵束の検索リストの変更や認可のダイアログを伴うため
4. **該当。2 つに分けた**。SecCode.h の `kSecCodeInfoCertificates` は「ad-hoc では無い。エラーの時は欠けるか一部だけになりうる」
   - (b) **直した**: 証明書の列の値が配列でない・要素が証明書でない・NULL を含む (要素の数が配列の長さと合わない) 時は、空や短い列を返さず、署名の情報の取得の失敗 (`Failed(Other)`) にする。DR-0011 の手順 4 の「取れなければ Failed(Other)」と同じ考え方で、手順の文面は変わらない。テストは、key が無い (空の列)・配列でない・証明書でない要素を含む・証明書の配列の 4 通り
   - (a) **未決 (観測だけ)**: ad-hoc の判定を CodeDirectory の flags の `kSecCodeSignatureAdhoc` (0x2) に変える案は実装していない。flags は署名する側が書く値で、DR-0011 の「requirement で検証した事実だけを持つ」に触るため。今の規則でも、証明書の列を取れずに `AdHoc` になった時は印が `adhoc` (赤)、Team ID と根は無しで、信頼を強く言う方向の誤りにはならない (実装を読んで確かめた)。走っている全プロセス (検証に成功した 999 個) で「証明書の列が空か」と「ad-hoc の bit」を数え、食い違いは 0 件だった ([findings](../findings/2026-11-15-adhoc-flag-and-certificate-list.md))。入れるかは統括と kawaz が決める
5. **該当、直した**。`"+f"` が `u8::from_str_radix` を通って 0x0f になることを、テストで再現した (修正前に RED)。読み込みを 16 進の数字 40 文字だけに限り、符号・空白・全角の数字を拒むテストを足した。ルールの `binary` の cdhash もこの読み込みを通る
6. **該当、直した**。予算 0 でも `Requirements::compile()` が先に 6 本をコンパイルしていた。requirement を、検証がそれを初めて問う時にコンパイルし、収集の残りで使い回す。テストで、予算 0 と ad-hoc ではどれもコンパイルせず、Apple (launchd) では `anchor apple` だけ (2 度目も増えない) を確かめる
7. **該当 (防御として直した)**。失敗の戻り値の時に、出力のポインタの辞書を包まずに返していた。Security framework が失敗の時に辞書を入れるかは確かめていない (ソースが手元に無い)。CF の約束 (`CF_RETURNS_RETAINED`) に沿い、NULL でなければ戻り値によらず所有を受け取って解放する。テストは本物の辞書を retain して渡し、retain count が戻ることを見る。順序を戻すとテストが落ちることも確かめた

## 受け入れ条件

- [x] 各指摘について、該当するかを確かめた結果 (直した / 該当しない理由) がある (4 の (a) は採否が未決で、観測の結果まで)
- [x] 直したものにテストがある (1 と 2 は、差し替えと exec の時機を作るテスト)

status は open のまま: 4 の (a) の採否が決まっていない。
