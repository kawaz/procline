---
title: 種類が Other の Apple 発行の証明書では、CodeDirectory の Team ID が leaf の OU と照らされない場合がある
status: open
category: design
created: 2026-11-15T12:30:00+09:00
origin: 自リポ TODO (引き継いだコードのレビューと観測から)
---

# 種類が Other の Apple 発行の証明書では、CodeDirectory の Team ID が leaf の OU と照らされない場合がある

## 概要

procline は検証に成功した署名の Team ID を CodeDirectory の値 (`kSecCodeInfoTeamIdentifier`) から取り、根が Apple か Apple 発行の時に身元として持つ。Security framework の検証が「CodeDirectory の Team ID = leaf 証明書の OU」を強制するのは、開発者の証明書の 5 種類 (Developer ID、Mac と iPhone の開発用、配布用 2 種) だけ ([findings](../findings/2026-11-15-team-id-and-leaf-certificate-ou.md))。

根が Apple 発行で、種類が Developer ID・開発用・Mac App Store のどれでもない署名 (`CertificateKind::Other`) には、照らされる証明書 (配布用など) と、照らされない Apple 発行の証明書の両方が入りうる。照らされない証明書でコードに署名でき、その署名が `SecCodeCheckValidity` を通るなら、他人の Team ID を CodeDirectory に入れた署名を、procline がその Team ID の身元として持つことになる。

## 分かっていること / いないこと

- 観測 (2026-11-15、macOS 26.5.2): 走っている Developer ID と開発用の 138 個は Team ID と OU が全部一致。Mac App Store と Apple 自身のコードは一致しないが、署名するのは Apple
- 未確認: コード署名用でない Apple 発行の証明書 (インストーラ用など) で付けた署名が、検証を通るか。署名を作る実験はしていない
- 未確認: 種類が Other になる正規のプロセスが実際にどれだけあるか (観測した 934 個には無かった)

## 直し方の案

種類が Other の時は、Team ID の文字種を確かめた上で requirement `anchor apple generic and certificate leaf[subject.OU] = "<Team ID>"` を評価し、通った時だけ Team ID を持つ (reference `macos-process-protection` の M7 と同じ形)。[DR-0011](../decisions/DR-0011-verified-signature-and-trust-mark.md) の手順が 1 つ増える。

## 受け入れ条件

- [ ] 照らされない Apple 発行の証明書の署名が検証を通るかを、観測か一次資料で確かめる
- [ ] 採るなら DR-0011、`crates/procline-core/src/verify.rs`、テストを直す。採らないなら DR-0011 に範囲と理由を書く
