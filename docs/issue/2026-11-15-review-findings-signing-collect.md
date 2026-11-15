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

## 受け入れ条件

- [ ] 各指摘について、該当するかを確かめた結果 (直した / 該当しない理由) がある
- [ ] 直したものにテストがある (1 と 2 は、差し替えと exec の時機を作るテスト)
