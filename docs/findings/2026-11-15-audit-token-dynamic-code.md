# 接続相手を audit token で参照した時も、kSecGuestAttributeDynamicCode でカーネルが持つ署名を検証できる

- Date: 2026-11-15

観測環境: macOS 26.5.2 (25F84)、Apple silicon (arm64)。利用者 (uid 501) の権限だけで、自分で作った試験プログラムに対して観測した。

## 判明した事実

- `SecCodeCopyGuestWithAttributes` に `kSecGuestAttributeAudit` (`LOCAL_PEERTOKEN` で取った接続相手の audit token) と `kSecGuestAttributeDynamicCode` を組で渡すと、pid で参照した時 (`kSecGuestAttributePid` + `kSecGuestAttributeDynamicCode`) と同じ結果になった。4 通り全部で同じ
- 接続の後に接続相手の実行ファイルを rename で差し替えると、通常の方法 (audit token でも pid でも) は `errSecCSStaticCodeChanged` (-67034) で失敗し、署名の情報は差し替えた先のファイル (`com.apple.true`) を返した。audit token + `kSecGuestAttributeDynamicCode` は検証に成功し、identifier と cdhash は走っているコード (差し替える前のファイル) のものだった
- 接続の後に接続相手の実行ファイルを削除すると、通常の方法は audit token でも pid でも SecCode が得られない (100002)。`kSecGuestAttributeDynamicCode` を足すと SecCode は得られ、requirement 無しの `SecCodeCheckValidity` は 0 を返したが、requirement つきの評価は -67065 (`errSecCSNoSuchCode`)、`SecCodeCopySigningInformation` は 100002 で失敗した
- 接続の後に接続相手が exec すると、audit token での参照は通常の方法も `kSecGuestAttributeDynamicCode` つきも -67065 で失敗した (audit token の pidversion が今のプロセスと合わない)。pid での参照は、exec した先 (`/bin/sleep`) を検証した

## 実用的な示唆

- 接続相手の検証は、audit token のまま `kSecGuestAttributeDynamicCode` を足して検証し直せる (DR-0011 の手順 3 をそのまま接続相手に使える)。exec した相手を取り違えない性質も保たれる
- 実行ファイルが消えた相手は、`kSecGuestAttributeDynamicCode` を足しても身元を取れない (署名の情報が 100002)。DR-0011 の手順どおり、通常の方法の 100002 で `Failed(Missing)` にする
- `kSecGuestAttributeDynamicCode` つきの検証で、requirement 無しの検証が通っても、署名の情報か requirement の評価で失敗しうる (削除の場合)。手順の後段の失敗も `Failed` に分類する必要がある

## 検証の詳細

### 方法

試験のサーバが Unix ドメインソケットを listen し、試験のクライアント (linker の ad-hoc 署名、identifier `client`) を `posix_spawn` で起動する。クライアントが接続したら、サーバは `getsockopt(LOCAL_PEERTOKEN)` で audit token を取り、クライアントの実行ファイルに操作をしてから、4 通りの参照で検証する。どの参照も `SecCodeCheckValidity` は `kSecCSNoNetworkAccess`。

| 操作 | 内容 |
|---|---|
| none | 何もしない |
| rename | `/usr/bin/true` のコピーを作り、rename でクライアントの実行ファイルのパスに置く (元の inode は unlink) |
| delete | クライアントの実行ファイルを削除する |
| exec | クライアントが接続の後に `/bin/sleep` を exec する |

### 結果

| 操作 | audit token (通常) | pid (通常) | audit token + dynamic | pid + dynamic |
|---|---|---|---|---|
| none | 検証 0、`anchor apple generic` -67050、identifier `client`、cdhash `d683a1e4…` | 同左 | 同左 | 同左 |
| rename | 検証 -67034、identifier `com.apple.true`、cdhash `18077a0b…` | 同左 | 検証 0、identifier `client`、cdhash `d683a1e4…` | 同左 |
| delete | SecCode が得られない (100002) | 同左 | 検証 0、requirement -67065、署名の情報 100002 | 同左 |
| exec | SecCode が得られない (-67065) | 検証 0、`com.apple.sleep` | SecCode が得られない (-67065) | 検証 0、`com.apple.sleep` |

実出力 (rename):

```
peer pid=70241 (token pid=70241 pidversion=13294785) action=rename
  audit (usual)        guest=0 valid=-67034 generic=-67034 info=0 identifier=com.apple.true cdhash=18077a0b2c9fb4a00b784732529f943a876cf214
  pid (usual)          guest=0 valid=-67034 generic=-67034 info=0 identifier=com.apple.true cdhash=18077a0b2c9fb4a00b784732529f943a876cf214
  audit + dynamic      guest=0 valid=0 generic=-67050 info=0 identifier=client cdhash=d683a1e4e29ea456214cb46757341cc3bfd194e6
  pid + dynamic        guest=0 valid=0 generic=-67050 info=0 identifier=client cdhash=d683a1e4e29ea456214cb46757341cc3bfd194e6
```

## 未観測

- setuid の接続相手 (実効 uid が root で、実行ファイルを利用者が読めないもの) を audit token で参照した場合。ユーザ権限で、setuid のプロセスに自分のソケットへ接続させる手段が無かった。pid での参照は、別の観測 (別リポ pam-passkey の findings `2026-11-15-running-code-identity.md`) で通常の方法が 100013、`kSecGuestAttributeDynamicCode` つきが成功だった
- Developer ID や app bundle の接続相手 (試験のクライアントは ad-hoc 署名の単体のバイナリだけ)
