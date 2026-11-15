---
title: 引き継いだコードのレビューで残した点 (裁定や設計の後で決めるもの)
status: open
category: design
created: 2026-11-15T12:30:00+09:00
origin: 自リポ TODO (引き継いだコードのレビューから)
---

# 引き継いだコードのレビューで残した点 (裁定や設計の後で決めるもの)

## 概要

2026-11-15 に引き継いだ署名の検証と収集の実装をレビューし、テストの穴と衛生はその場で直した。次の点は、他の裁定や設計に依るので残す。

## 残した点

1. **`code_signing` の JSON の読み込みが、Option の field のキーの欠落を受け付ける**。`entitlements` のキーが落ちた JSON は「保護を緩める entitlement なし」と読まれる (`crates/procline-core/src/signature.rs` の読み込みの型)。収集した事実の型から `Deserialize` を外すか (QUESTIONS の HO-Q1) で扱いが決まる。外さないなら、キーの存在を必須にする (null は可、欠落はエラー)
2. **保護の状態の判定が procline-acl の非公開の型にある** (`crates/procline-acl/src/matchers.rs` の `Protection`)。承認画面が「保護なし」を出すには、アプリが同じ規則を持つことになる。`VerifiedSignature` から保護の状態を返す関数を procline-core に置くか
3. **`get-task-allow` を署名の entitlements の dict だけで見ている**。カーネルの status にも `CS_GET_TASK_ALLOW` (0x4) が立つ (試験バイナリ 1 つで観測)。status の bit も取って、どちらかにあれば「ある」とするか ([DR-0012](../decisions/DR-0012-strength-class-from-protection.md) の範囲)。他の entitlement も status に映る (`disable-library-validation` は `CS_FORCED_LV` が消え、`disable-executable-page-protection` は `CS_HARD` と `CS_ENFORCEMENT` が消える。別リポ kawaz/pam-passkey の findings `2026-11-15-process-memory-probe.md`) ので、dict の読み落としの検出に使える。ただし platform binary は `CS_FORCED_LV` の代わりに `CS_REQUIRE_LV` を持つものがあり、採るなら観測してから決める
4. **`SecCodeCopySigningInformation` に `kSecCSRequirementInformation` を渡しているが、それで増えるキーを読んでいない**。外しても 72 プロセスの `code_signing` の出力は同じだった (macOS 26.5.2 の 1 環境)。外すか、要る理由を確かめてコメントに書くか
5. **収集の crate (procline-macos) に、実プロセスの entitlements と hardened runtime を読めていることを確かめるテストが無い**。保護の状態ごとのクラスの結合テストは ACL を使うので procline-acl-macos にある (`tests/protection_class.rs`)。workspace 全体のテストでは読み取りの壊れを検出できるが、収集の crate だけのテストでは検出できない。4 通りに署名したコピーを起こして、収集した entitlements の key と `runtime.hardened_runtime` だけを確かめるテストを procline-macos に足す
6. **[DR-0014](../decisions/DR-0014-chain-trust-boundary-and-caller-supplied-values.md) (提案) と [DR-0015](../decisions/DR-0015-icon-outside-collection.md) (提案) の Context が、特定のアプリの都合を理由にしている箇所がある**。裁定 (QUESTIONS の HO-Q1 / HO-Q2 / HO-Q4) を反映する時に、procline 自身の理由 (型と層の設計、利用者を特定しない) で書き直す

## 受け入れ条件

- [ ] 1 は HO-Q1 の裁定の後に、外すか必須にするかを反映する
- [ ] 2〜4 は、採否を決めて反映する (採らないものは理由を DR か doc comment に書く)
- [x] 5 のテストを足す (`crates/procline-macos/tests/signed_copies.rs`)
- [ ] 6 は裁定の反映と同じ変更で直す
