---
title: entitlements の辞書を JSON にする変換が入れ子の深さを抑えていない
status: open
category: bug
created: 2026-11-15T18:37:00+09:00
origin: 自リポ TODO (bundle の Info.plist の読み取りを直した時のコードの読み取りから)
---

# entitlements の辞書を JSON にする変換が入れ子の深さを抑えていない

## 概要

収集は、署名の情報の `kSecCodeInfoEntitlementsDict` を `cf::dictionary_to_json` で JSON にする (`crates/procline-macos/src/sys/security.rs` の `entitlements`)。この変換は `cf::to_json` で入れ子 1 段ごとに再帰して辿り、深さを抑えていない。

- entitlements は署名に封じられた値だが、ad-hoc の署名なら同じ uid のプロセス (脅威モデルで守る相手) が自由に決められる
- 深い入れ子の entitlements を持つバイナリを起動されると、収集するプロセスのスタックがあふれるおそれがある
- Security framework の側に、entitlements の入れ子の深さや大きさの上限があるかは確かめていない
- コードを読んだだけで、実測していない

## 受け入れ条件

- [ ] 深い入れ子の entitlements を持つ ad-hoc 署名のバイナリを実際に作って収集し、あふれるか・Security framework が先に拒むかを観測する
- [ ] 要るなら、変換の深さに上限を置く
