---
title: 引き継いだコードのレビューで残した 4 点 (裁定や設計の後で決めるもの)
status: open
category: design
created: 2026-11-15T12:30:00+09:00
origin: 自リポ TODO (引き継いだコードのレビューから)
---

# 引き継いだコードのレビューで残した 4 点 (裁定や設計の後で決めるもの)

## 概要

2026-11-15 に引き継いだ署名の検証と収集の実装をレビューし、テストの穴と衛生はその場で直した。次の 4 点は、他の裁定や設計に依るので残す。

## 残した点

1. **`code_signing` の JSON の読み込みが、Option の field のキーの欠落を受け付ける**。`entitlements` のキーが落ちた JSON は「保護を緩める entitlement なし」と読まれる (`crates/procline-core/src/signature.rs` の読み込みの型)。収集した事実の型から `Deserialize` を外すか (QUESTIONS の HO-Q1) で扱いが決まる。外さないなら、キーの存在を必須にする (null は可、欠落はエラー)
2. **保護の状態の判定が procline-acl の非公開の型にある** (`crates/procline-acl/src/matchers.rs` の `Protection`)。承認画面が「保護なし」を出すには、アプリが同じ規則を持つことになる。`VerifiedSignature` から保護の状態を返す関数を procline-core に置くか
3. **`get-task-allow` を署名の entitlements の dict だけで見ている**。カーネルの status にも `CS_GET_TASK_ALLOW` (0x4) が立つ (試験バイナリ 1 つで観測)。status の bit も取って、どちらかにあれば「ある」とするか ([DR-0012](../decisions/DR-0012-strength-class-from-protection.md) の範囲)
4. **`SecCodeCopySigningInformation` に `kSecCSRequirementInformation` を渡しているが、それで増えるキーを読んでいない**。外しても 72 プロセスの `code_signing` の出力は同じだった (macOS 26.5.2 の 1 環境)。外すか、要る理由を確かめてコメントに書くか

## 受け入れ条件

- [ ] 1 は HO-Q1 の裁定の後に、外すか必須にするかを反映する
- [ ] 2〜4 は、採否を決めて反映する (採らないものは理由を DR か doc comment に書く)
