---
title: 署名付きの grant と一覧が、古い署名済みのファイルに差し戻せる
status: open
category: design
created: 2026-11-15T08:32:54+09:00
origin: 自リポ TODO (pam-passkey のセッションからの起票)
---

# 署名付きの grant と一覧が、古い署名済みのファイルに差し戻せる

## 概要

一覧 (subject、tag、rule) と grant はアプリが署名して保存し、読み込みは署名を検証する (`Policy::load_verified`、`Policy::load_grant`)。署名は改ざんを防ぐが、同じ鍵で過去に署名した古いファイルへの差し戻しは防がない。差し戻せると、`uses` を減らす前の grant (残り回数が戻る)、deny を足す前の一覧 (足した deny が消える)、失効を確定して消した grant (消す前のファイル) に戻せる。

## 背景 (事実)

- DESIGN-ja の「保存」は、grant の永続化先を「評価するデーモン以外(同じ uid の他プロセス)から書けない場所に置きます。書けると、使い切る前の grant ファイルを差し戻して `uses` を戻せるためです。置き場はアプリが決めます」とする
- 脅威モデルの相手は同じ uid の別プロセス (DESIGN-ja「脅威モデルの前提」)。同じ uid のプロセス同士はファイルの所有者と mode では区別できないので、「同じ uid の他プロセスから書けない場所」は、ファイルの権限だけでは作れない
- 署名の検証 (`PolicyVerifier::verify(kind, bytes, sig)`) は、バイト列と署名の組が正しいかだけを見る。版や新しさは見ない
- 一覧の差し戻しは grant にも及ぶ: 一覧を読み直した後に grant を `Policy::load_grant` で検査し直す (DESIGN-ja「保存」) が、検査は差し戻した一覧に対して行われる

## 確かめること

置き場と鍵の保護はアプリの責務 (DESIGN-ja「脅威モデルの前提」)。同じ uid の他プロセスから書けない置き場を何で作るか、差し戻しをどこまで防ぐかは、アプリの永続化の設計で決める (cache-warden は Secure Enclave の鍵と epoch で扱い、epoch まで揃えた差し戻しは守らないものとしている)。この issue が持つ crate の論点は 1 つ:

- crate の読み込みの入口 (`Policy::load_verified`、`Policy::load_grant`) が、アプリから版 (単調な番号) を受け取って検査する形を持つか、版の検査はアプリが読み込みの前に行うものとして境界の記述だけにするか。読み込みの実装 (JSON の形と署名の検証の噛み合わせ) を決める時に一緒に決める

## 関連

- DESIGN-ja「保存」「脅威モデルの前提」
- [DR-0004](../decisions/DR-0004-rule-grant-split-and-condition-advance.md): grant 単位の永続化
- [DR-0008](../decisions/DR-0008-evaluation-semantics.md): 評価と永続化の順序
