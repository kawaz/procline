# カーネルの code signing の status の bit は、保護を緩める entitlement の辞書の逆写像ではない

- Date: 2026-11-15

観測環境: macOS 26.5.2 (25F84)、カーネル `xnu-12377.121.10~1`、arm64。利用者の権限だけで (sudo なし) 観測した。

## 何を確かめたか

[DR-0012](../decisions/DR-0012-strength-class-from-protection.md) の保護の状態は、保護を緩める 4 つの entitlement (`com.apple.security.get-task-allow`、`…cs.disable-library-validation`、`…cs.disable-executable-page-protection`、`…cs.allow-dyld-environment-variables`) を署名の entitlements の辞書 (`kSecCodeInfoEntitlementsDict`) だけで見る。カーネルの動的な status にも entitlement に連れて変わる bit がある (`CS_GET_TASK_ALLOW` など) ので、status の bit も併せて見れば辞書の読み落としを検出できるか、を確かめた。そのために、走っている全プロセスで辞書の key と status の bit の対応を数え、自作のバイナリに key を 1 つずつ付けた対照で bit の動きを見た。

status の側の候補 (その entitlement があると bit がこうなる、という仮説):

| key | status の側の候補 |
|---|---|
| `get-task-allow` | `CS_GET_TASK_ALLOW` (0x4) が立つ |
| `disable-library-validation` | `CS_FORCED_LV` (0x10) と `CS_REQUIRE_LV` (0x2000) がどちらも無い |
| `disable-executable-page-protection` | `CS_HARD` (0x100) と `CS_ENFORCEMENT` (0x1000) がどちらも無い |
| `allow-dyld-environment-variables` | 対応する bit が見つからない |

## 判明した事実

### 走っている全プロセス

走っている 1,029 プロセスのうち、status と entitlements の辞書を取れたのは 1,021 件。

- `kSecCodeInfoStatus` と `csops(pid, CS_OPS_STATUS)` の値の食い違いは 0 件
- `CS_RUNTIME` (0x10000) が立つのは 962 件
- entitlements の辞書そのものが無いのは 122 件
- 4 つの key のどれかの値が false のものは 0 件

辞書の key (true / 無い) × status の側の候補 (各行の合計 1,021):

| key | 辞書に無い・候補に当たらない | 辞書に無い・候補に当たる | 辞書に true・候補に当たらない | 辞書に true・候補に当たる |
|---|---:|---:|---:|---:|
| `get-task-allow` | 1,020 | 0 | 0 | 1 |
| `disable-library-validation` | 897 | 39 | 0 | 85 |
| `disable-executable-page-protection` | 962 | 38 | 0 | 21 |
| `allow-dyld-environment-variables` | 辞書に無い 998 | — | 辞書に true 23 | — |

食い違い (辞書に無いのに候補に当たる) は 41 プロセス:

- hardened runtime の無い、platform でない ad-hoc の署名: 35 件 (library validation と実行ページの保護の、2 つの候補の両方に当たる)
- Apple の platform binary で hardened runtime ありの `/bin/zsh`: 3 件 (library validation の 2 つの bit が無い)
- Apple の platform binary で hardened runtime なし: 2 件 (開発ツールに付く XPC service。実行ページの保護の候補に当たる)
- 署名なしと判定された app: 1 件 (両方の候補に当たる)
- Developer ID の署名での食い違いは無かった

hardened runtime ありに限ると、library validation の食い違いは `/bin/zsh` の 3 件、実行ページの保護の食い違いは 0 件。辞書に true なのに候補に当たらない組は、どの key でも 0 件。

### 自作のバイナリの対照

同じ小さなプログラムを ad-hoc で署名し分け、起こして準備の合図を pipe で受けてから status を読んだ:

| 署名 | status (16 進) | 対象の key |
|---|---|---|
| hardened runtime だけ | `22011311` | 無い |
| + `get-task-allow` | `22011315` | true |
| + `disable-library-validation` | `22011301` | true |
| + `disable-executable-page-protection` | `22010211` | true |
| + `allow-dyld-environment-variables` | `22011311` | true |
| hardened runtime なし | `22000201` | 無い |
| + `get-task-allow` = false | `22011311` | false (key はある) |

- `get-task-allow` は `CS_GET_TASK_ALLOW` (0x4) を足した。値が false の key では立たない
- `disable-library-validation` は `CS_FORCED_LV` (0x10) を消した
- `disable-executable-page-protection` は `CS_HARD` (0x100) と `CS_ENFORCEMENT` (0x1000) を消した。`CS_KILL` (0x200) は立ったまま
- `allow-dyld-environment-variables` は status を変えなかった
- hardened runtime なしの署名は、`CS_RUNTIME` に加えて `CS_FORCED_LV`、`CS_HARD`、`CS_ENFORCEMENT` も持たない

### XNU の公開ソース

実機と版が違う `xnu-12377.121.6` を読んだ。

- [`osfmk/kern/cs_blobs.h` 35〜76 行](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/kern/cs_blobs.h#L35-L76): bit の値と `CS_ENTITLEMENT_FLAGS` を定義する。この 4 つの key に当たるもので `CS_ENTITLEMENT_FLAGS` に入るのは `CS_GET_TASK_ALLOW` だけ
- [`bsd/kern/kern_proc.c` 3780〜3803 行](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_proc.c#L3780-L3803): `CS_OPS_STATUS` は、enforcement の設定で bit を足し、`CS_FORCED_LV` があれば報告する値から `CS_REQUIRE_LV` を消す
- [`bsd/kern/kern_exec.c` 2166〜2184 行](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_exec.c#L2166-L2184): exec の時に flags を引き継ぐ
- entitlement から bit を決める AMFI の中は公開されていない

## 実用的な示唆

観測から言えること:

- status の bit は entitlement の辞書の逆写像ではない
- `CS_GET_TASK_ALLOW` だけは、値が true の `get-task-allow` と全部の例で一致した
- library validation と実行ページの保護は、bit が無いことを entitlement の印にすると、entitlement を持たないプロセス (hardened runtime の無い ad-hoc の署名、`/bin/zsh` など) を誤って拾う
- `allow-dyld-environment-variables` には対応する bit が無い

推論 (観測の外):

- bit の不在は「その entitlement がある」ことでなく「カーネルがその保護を課していない」ことを表している。hardened runtime の無いプロセスが保護の bit を持たないのはその現れで、`/bin/zsh` の library validation の bit が無いのも、entitlement でなく platform binary の扱いの違いと見るのが自然 (AMFI の中は読めないので確かめていない)
- status の bit を併用しても、辞書の読み落としを検出できるのは `get-task-allow` だけで、それも辞書と食い違った例は無かった。保護を緩める entitlement の判定は辞書だけで行い、辞書を読めない時は検証の失敗にする今の設計 ([DR-0011](../decisions/DR-0011-verified-signature-and-trust-mark.md) の手順 4) を変える根拠は無い

未観測:

- 辞書の読み落としを故意に起こした組
- Developer ID の署名に保護を緩める entitlement を付けて起動した対照
- 他の版の macOS

## 検証の詳細

C の試験プログラムで、pid ごとに `SecCodeCopyGuestWithAttributes` (pid) で SecCode を得て、`SecCodeCopySigningInformation(kSecCSSigningInformation | kSecCSDynamicInformation)` の `kSecCodeInfoStatus` と `kSecCodeInfoEntitlementsDict` の 4 つの key (true / false / 他の型 / 無い) を読み、`csops(pid, CS_OPS_STATUS)` の値と比べた。全プロセスは `ps` で列挙した pid を順に渡した。食い違いの分類は、同じ pid を procline の CLI で収集した印 (`code_signing.mark`) と status の `CS_PLATFORM_BINARY`・`CS_RUNTIME` で行った。

対照は、終了の合図を stdin で待つだけのプログラムを `codesign --sign - --force [--options runtime] [--entitlements <plist>]` で署名し分け、空の環境で起こし、stdout の `ready` を読んでから同じ試験プログラムで status を読んだ。

```c
CFDictionaryRef dict = NULL;
SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSDynamicInformation, &dict);
uint32_t status = 0;
CFNumberGetValue(CFDictionaryGetValue(dict, kSecCodeInfoStatus), kCFNumberSInt32Type, &status);
CFDictionaryRef e = CFDictionaryGetValue(dict, kSecCodeInfoEntitlementsDict);
uint32_t direct = 0;
csops(pid, 0 /* CS_OPS_STATUS */, &direct, sizeof(direct));
```

status の側の候補の判定:

```python
get_task_allow = bool(status & 0x4)
disable_library_validation = not (status & (0x10 | 0x2000))
disable_executable_page_protection = not (status & (0x100 | 0x1000))
```
