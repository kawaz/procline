# CodeDirectory の Team ID と leaf 証明書の OU は、開発者の証明書では Security framework が照らし合わせ、App Store 配布と Apple 自身のコードでは照らし合わせない

- Date: 2026-11-15

観測環境: macOS 26.5.2 (25F84)、Apple M1 Max。利用者の権限だけで (sudo なし)、1 回観測した。一次資料は Apple の公開ソース `apple-oss-distributions/Security` の tag `Security-61901.0.87.0.1` と `apple-oss-distributions/xnu` の tag `xnu-12377.1.9` (どちらも取得時点の main の先頭)。

## 何を確かめたか

procline は、検証に成功した署名の Team ID を CodeDirectory の値 (`SecCodeCopySigningInformation` の `kSecCodeInfoTeamIdentifier`) から取り、根が Apple か Apple 発行の時だけ持たせる (`crates/procline-core/src/verify.rs` の `Root::Apple { team_id }` と `Root::AppleIssued { team_id, kind }`)。証明書の subject の OU とは結び付けていない。OS が「CodeDirectory の Team ID = leaf 証明書の OU」を強制していなければ、Apple 発行の証明書を持つ誰でも他人の Team ID を CodeDirectory に入れた署名を作れ、procline はそれをその Team ID の身元として扱う。そこで次の 2 つを確かめた。

- A: Security framework か AMFI に、CodeDirectory の Team ID と証明書を照らす検査があるか (一次資料)
- B: 今走っているプロセスで、CodeDirectory の Team ID と leaf の OU が証明書の種類ごとに一致するか (観測)。あわせて `certificate leaf[subject.OU] = "<Team ID>"` の requirement が正規のプロセスを通すか

## 判明した事実

### A: Security framework (libsecurity_codesigning) には照合がある。対象は「開発者の証明書」の 5 種類だけ

`SecStaticCode::verifySignature()` が、CMS の検証で証明書の列を組み立てた直後に、CodeDirectory の Team ID と leaf の OU を比べ、違えば `errSecCSBadTeamIdentifier` (-66997) で検証を失敗させる。

[StaticCode.cpp L1024-L1051](https://github.com/apple-oss-distributions/Security/blob/Security-61901.0.87.0.1/OSX/libsecurity_codesigning/lib/StaticCode.cpp#L1024-L1051):

```cpp
			// if this is an Apple developer cert....
			if (teamID() && SecStaticCode::isAppleDeveloperCert(mCertChain)) {
				CFRef<CFStringRef> teamIDFromCert;
				if (CFArrayGetCount(mCertChain) > 0) {
					SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(mCertChain, Requirement::leafCert);
					CFArrayRef organizationalUnits = SecCertificateCopyOrganizationalUnit(leaf);
					if (organizationalUnits) {
						teamIDFromCert.take((CFStringRef)CFRetain(CFArrayGetValueAtIndex(organizationalUnits, 0)));
						CFRelease(organizationalUnits);
					} else {
						teamIDFromCert = NULL;
					}

					if (teamIDFromCert) {
						...
						if (CFStringCompare(teamIDFromCert, teamIDFromCD, 0) != kCFCompareEqualTo) {
							Security::Syslog::error("Team identifier in the signing certificate (%s) does not match the team identifier (%s) in the code directory",
													cfString(teamIDFromCert).c_str(), teamID());
							MacOSError::throwMe(errSecCSBadTeamIdentifier);
						}
					}
				}
			}
```

照合する証明書の範囲は `SecStaticCode::isAppleDeveloperCert()` ([StaticCode.cpp L3129-L3136](https://github.com/apple-oss-distributions/Security/blob/Security-61901.0.87.0.1/OSX/libsecurity_codesigning/lib/StaticCode.cpp#L3129-L3136)) が決め、その中身は [StaticCode.cpp L100-L105](https://github.com/apple-oss-distributions/Security/blob/Security-61901.0.87.0.1/OSX/libsecurity_codesigning/lib/StaticCode.cpp#L100-L105) の 5 つの requirement の or:

| 名前 (ソース上) | 条件 |
| --- | --- |
| `WWDRRequirement` | `anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.2] exists` (iPhone の開発用) |
| `MACWWDRRequirement` | `anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.12] exists` (Mac の開発用) |
| `developerID` | `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists` |
| `distributionCertificate` | `anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.7] exists` |
| `iPhoneDistributionCert` | `anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.4] exists` |

ソースから読める条件:

- 照合は CodeDirectory に Team ID がある時だけ行う (`teamID() &&`)
- leaf に OU が無ければ照合しない (エラーにもしない)。OU が複数あれば先頭だけを比べる
- 範囲に入らない証明書では照合しない。Mac App Store で配られたもの (leaf の拡張 `1.2.840.113635.100.6.1.9`、Apple が署名し直したもの) と Apple 自身のコード (`anchor apple`) は範囲の外
- この照合は `#if TARGET_OS_OSX` かつ `kSecCSApplyEmbeddedPolicy` が立っていない枝 ([StaticCode.cpp L867](https://github.com/apple-oss-distributions/Security/blob/Security-61901.0.87.0.1/OSX/libsecurity_codesigning/lib/StaticCode.cpp#L867)) の中にある。もう一方の枝 (`SecCMSVerifyCopyDataAndAttributes` を使う方) には同じ照合は無い
- `SecCodeCheckValidity` (procline が使う、`kSecCSNoNetworkAccess` だけを渡す) は `SecCode::checkValidity()` から `validateNonResourceComponents()` を呼び、それが `validateDirectory()` → `verifySignature()` に至る ([Code.cpp L181-L208](https://github.com/apple-oss-distributions/Security/blob/Security-61901.0.87.0.1/OSX/libsecurity_codesigning/lib/Code.cpp#L181-L208)。L208 に `myDisk->validateNonResourceComponents();	// also validates the CodeDirectory`)

観測した OS の版で同じ照合が入っているかは、ソースの版と OS の版が一致する保証が無いので、dyld shared cache (`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e.01`) を文字列で探した。上の Syslog の書式文字列 `Team identifier in the signing certificate (%s) does not match the team identifier (%s) in the code directory` がそのまま見つかった。どのライブラリの中にあるかまでは確かめていない。

requirement の言語には、CodeDirectory の Team ID を述語として書く手段が無い。`ExprOp` の列挙 ([requirement.h L160-L185](https://github.com/apple-oss-distributions/Security/blob/Security-61901.0.87.0.1/OSX/libsecurity_codesigning/lib/requirement.h#L160-L185)) は `opIdent` から `opLegacyDevID` までで、Team ID を見る opcode は無い。Team ID で縛るには `certificate leaf[subject.OU]` を使う。TN3127 (Inside Code Signing: Requirements) もそう書く: 「The certificate leaf[subject.OU] = SKMME9E2Y8 term requires that the leaf certificate's Organization Unit field be SKMME9E2Y8. In a Developer ID certificate, this is where you'll find the Team ID.」

### A: カーネル (XNU) と AMFI では、照合する箇所は見つからなかった

- XNU の `csblob_parse_teamid()` ([bsd/kern/ubc_subr.c L3059](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/bsd/kern/ubc_subr.c#L3059)) は CodeDirectory の `teamOffset` の文字列を指すだけで、証明書は見ない。ubc_subr.c の Team ID の比較は、universal binary の slice 同士で Team ID が揃っているかを見るもの (L4939 付近) で、証明書との照合ではない
- 署名の CMS と証明書の検証は AMFI が CoreTrust の `CTEvaluateAMFICodeSignatureCMS()` ([EXTERNAL_HEADERS/CoreTrust/CTEvaluate.h L478](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/EXTERNAL_HEADERS/CoreTrust/CTEvaluate.h#L478)) で行う。この関数は検証した leaf 証明書と満たした policy の flags を返すだけで、Team ID を受け取らない。返った leaf を AMFI が OU と比べるかは、AMFI (AppleMobileFileIntegrity.kext) のソースが公開されていないので確かめられない

### B: 観測

`ps -axo pid=` で列挙した 1015 個の pid ごとに `cargo run --release -p procline --example dump -- <pid>` (ビルド済みの `target/release/examples/dump`) を走らせ、JSON の `processes[0].code_signing` を読んだ。`signer.kind` が `certificate` のものについて、`signer.root.team_id` (CodeDirectory の Team ID) と、`signer.chain[0].der` (base64url) を `openssl x509 -inform der -noout -subject -nameopt RFC2253 -text` で読んだ subject の OU と拡張の OID を比べた。

全体の内訳: `apple` 794、`developer_id_notarized` 137、`adhoc` 56、`mac_app_store` 2、`development` 1、`failed` 12、`unsigned` 1、dump が失敗 (列挙と dump の間に終わったもの) 12。

証明書のある 934 個:

| procline の根と種類 | leaf の拡張 (Apple の OID のうち 100.6.1.* と 100.6.22) | leaf の OU | Team ID と OU | 件数 |
| --- | --- | --- | --- | --- |
| Apple 発行、Developer ID (公証済み) | 6.1.13、6.1.18、6.1.33 | Team ID の形 | 一致 | 65 |
| Apple 発行、Developer ID (公証済み) | 6.1.13、6.1.33 | Team ID の形 | 一致 | 71 |
| Apple 発行、Developer ID (公証済み) | 6.1.13、6.1.32、6.1.33 | Team ID の形 | 一致 | 1 |
| Apple 発行、開発用 | 6.1.12、6.1.2 | Team ID の形 | 一致 | 1 |
| Apple 発行、Mac App Store | 6.1.9 | なし (subject は Apple Inc. の `Apple Mac OS Application Signing`) | 不一致 (Team ID は `W5364U7YZB`) | 2 |
| Apple | 6.22 | `Apple Software` | 不一致 (Team ID は `59GAB85EFG`) | 5 |
| Apple | 6.22 | `Apple Software` | Team ID なし | 784 |
| Apple | 6.22 | なし | Team ID なし | 5 |

- Developer ID と開発用 (138 個) では、Team ID と OU が全部一致した。食い違いは 0 件
- Mac App Store の 2 個 (Tailscale の `io.tailscale.ipn.macos` とその network extension) は、leaf が Apple の証明書で OU を持たず、Team ID `W5364U7YZB` は CodeDirectory にしか無い
- Apple の 5 個 (`com.apple.CoreSimulator.*`、`com.apple.CoreDevice.CoreDeviceService` で、Xcode に入っているもの) は、CodeDirectory に Team ID `59GAB85EFG` を持ち、leaf の OU は `Apple Software` だった
- 開発用の leaf (Apple Development) では、subject の CN の括弧内の 10 文字は OU (Team ID) と違う値だった。CN の括弧は Team ID ではない
- 6.1.18、6.1.32、6.1.33 の意味は調べていない (種類の判定には使っていない)

### B: requirement を当てた結果

Team ID を持つ証明書つきのプロセス全部 (145 個) に `codesign -v -R='anchor apple generic and certificate leaf[subject.OU] = "<CodeDirectory の Team ID>"' <pid>` を当てた:

| 種類 | 通った (終了コード 0) | 落ちた (3、requirement を満たさない) | その他 |
| --- | --- | --- | --- |
| Developer ID | 136 | 0 | 1 (終了コード 1、`No such process`。当てる前に終わっていた) |
| 開発用 | 1 | 0 | 0 |
| Mac App Store | 0 | 2 | 0 |
| Apple (Team ID あり) | 0 | 5 | 0 |

代表の 6 個 (Developer ID 2、開発用 1、Mac App Store 1、Apple で Team ID あり 1、Apple で Team ID なし 1) には、別の Team ID (`AAAAAAAAAA`) で同じ形を当て、全部が終了コード 3 で落ちた。

あわせて同じ 6 個の designated requirement (`codesign -d -r- <pid>`) を見た:

- Developer ID: `identifier "<id>" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = <Team ID>`
- 開発用: `identifier "<id>" and anchor apple generic and certificate leaf[subject.CN] = "<CN>" and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */` (OU でなく CN で縛る)
- Mac App Store (Tailscale): `(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = W5364U7YZB) and identifier "io.tailscale.ipn.macos"`。App Store の枝は Team ID で縛らない
- Apple: `identifier "<id>" and anchor apple`

## 言えること

- Developer ID と開発用 (と、範囲に入る配布用の 6.1.7 / 6.1.4) では、Security framework の検証 (procline が使う `SecCodeCheckValidity` の経路) が CodeDirectory の Team ID と leaf の OU の一致を強制している (ソース)。観測でも 138 個全部が一致した
- Mac App Store で配られたものと Apple 自身のコードでは、CodeDirectory の Team ID は leaf の OU と照らされない (ソースで範囲の外、観測でも OU と一致しない)。ただし、どちらも leaf を発行・署名するのは Apple で、CodeDirectory の Team ID を入れたのも Apple の署名である
- `certificate leaf[subject.OU] = "<Team ID>"` を足した requirement は、Developer ID と開発用の正規のプロセスを通し、Mac App Store と Apple のプロセスを落とす。違う Team ID では落ちる
- procline の分類の requirement (`crates/procline-core/src/verify.rs` の 38〜44 行) と照合の範囲の対応:
  - `CertificateKind::DeveloperId` の requirement は `developerID` と同じ文で、範囲に入る
  - `CertificateKind::Development` の requirement (leaf に 6.1.12) は `MACWWDRRequirement` と同じ文で、範囲に入る
  - `CertificateKind::MacAppStore` (leaf に 6.1.9) は範囲の外
  - `CertificateKind::Other` (Apple 発行で、上のどれでもない) は、範囲に入るもの (6.1.2 だけの iPhone の開発用、6.1.7、6.1.4) と範囲の外の Apple 発行の証明書の両方を含みうる。範囲の外なら Team ID は照らされない
- 照合には抜けがある: leaf に OU が無ければ照合されない。範囲に入る証明書で OU が無いものを Apple が発行するかは分からない

## 言えないこと

- AMFI (カーネル) が照合するかどうか (ソースが無い)。プロセスの起動時に照合されているかは分からない。procline の検証が通る経路は上の Security framework の照合を通る
- 観測した OS の Security framework が公開ソースと同じ条件で照合しているか。書式文字列が shared cache にあることまでは確かめたが、範囲 (`isAppleDeveloperCert`) が同じかは確かめていない
- 照合が実際に失敗を返すこと。偽の Team ID を入れた署名を作る実験はしていない (禁止事項)

## 未観測

- Team ID と OU が食い違う、範囲に入る証明書の署名を検証した時の結果 (`errSecCSBadTeamIdentifier` が返るか)
- 配布用 (6.1.7、6.1.4) や、範囲の外の Apple 発行の証明書 (`CertificateKind::Other` になるもの) で署名されたプロセス。この Mac には無かった
- `verified_from` が running code で、証明書のある署名
- 別の macOS の版、別の Mac
