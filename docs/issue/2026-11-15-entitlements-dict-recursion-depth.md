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

- entitlements は署名に封じられた値だが、ad-hoc の署名なら同じ uid のプロセス (脅威モデルで守る相手) が決められる (どこまで決められるかは `codesign` と起動の段で制限される。下の観測)
- 深い入れ子の entitlements を持つバイナリを起動されると、収集するプロセスのスタックがあふれるおそれがある
- 再帰の箇所は `crates/procline-macos/src/sys/cf.rs` の `to_json` (配列は要素ごと、辞書は `dictionary_to_json` を通して値ごとに再帰)。CLI は main のスレッドで同期に収集する

## 背景 (観測)

[findings: entitlements の入れ子の上限](../findings/2026-11-15-entitlements-nesting-limits.md) (macOS 26.5.2、uid 501、ad-hoc 署名):

- `codesign` が entitlements として受け付けた入れ子の深さは 11 まで。12 以上は拒むか、35 秒で終わらなかった。binary plist の entitlements は単純なものでも拒んだ
- 未知の key を持つ entitlements のバイナリは、署名できても起動した直後に SIGKILL された (深さ 0 や幅だけのものを含む)
- そのため、深い入れ子の entitlements を持つ走っているプロセスを作れず、収集でスタックがあふれる深さは観測できていない
- 未観測: `codesign` を使わずに組んだ署名の blob、Apple が定義した key の値に深い入れ子を置いた時の起動、`to_json` の 1 段あたりのスタックの使用量

## 残る問い (決めていない)

到達できる深さが観測の範囲で 11 までと分かった上で:

- `to_json` の再帰に深さの上限を置くか
- 置くなら、上限を超えた entitlements を収集の結果でどう表すか。「entitlement なし」に読むと保護の状態が強い側に倒れる (保護を緩める 4 つの entitlement が無いことが「保護あり」の条件の 1 つ。[DR-0012](../decisions/DR-0012-strength-class-from-protection.md)) ので、そうは読めない、という制約がある
- 置かないなら、何に依っているかを書く。依っているのは AMFI と `codesign` の受理の境界で、手で組んだ署名の blob は未観測

## 受け入れ条件

- [x] 深い入れ子の entitlements を持つ ad-hoc 署名のバイナリを実際に作って収集し、あふれるか・Security framework が先に拒むかを観測する (`codesign` が深さ 12 以上を拒み、未知の key のバイナリは起動で殺され、走っているプロセスを作れなかった。findings)
- [ ] 手で組んだ署名の blob、Apple が定義した key の値の深い入れ子で、深い entitlements の走っているプロセスを作れるかを観測する
- [ ] 上の残る問いを決め、要るなら変換の深さに上限を置く
