# DR-0011: コード署名は requirement で検証した事実だけを持ち、検証に成功した時だけ身元を持つ型にする。信頼の印は事実から core の 1 か所で決める

- Status: Active
- Date: 2026-11-15

## Context

収集結果の署名 (`ProcessInfo.code_signing`) は、表示 (承認画面の印) と照合 (`binary` の署名由来の field) の両方の元になる。どちらも「確かめたこと」より強く言ってはいけない。macOS 26.5.2 で、走っているプロセスに対して次を観測した (別リポ pam-passkey の findings `2026-11-15-process-signing-elements.md`、`2026-11-15-running-code-identity.md` と、その DR-0014。要点はここに書く)。

- requirement を付けない `SecCodeCheckValidity` は自己署名の証明書でも通る。証明書の subject は署名する側が自由に名乗れ、自己署名で `Software Signing` (Apple 自身の leaf と同じ名前) や `Developer ID Application: … (<Team ID>)` を名乗れた。名前の文字列では Apple も Developer ID も判定できない
- 証明書の拡張の OID (Developer ID、Mac App Store 等の印) も名乗れる。`anchor apple generic` を付けない OID / OU の条件は、偽の Developer ID の自己署名が満たした。OID の条件は `anchor apple generic` と組の時だけ意味を持つ (Apple の TN3127 の注意と同じ)
- 証明書の種類: Developer ID は中間の 1.2.840.113635.100.6.2.6 と leaf の 6.1.13、Mac App Store は leaf の 6.1.9、開発用 (Apple Development) は leaf の 6.1.12 (取り出した証明書での観測。一次資料での裏取りは未)。TN3127 の開発用の条件 `certificate 1[field.1.2.840.113635.100.6.2.1]` は Mac App Store の中間も満たす
- 公証 (requirement `notarized`) は Developer ID の時だけ成り立つ。Apple 自身、Mac App Store、開発用、ad-hoc では常に不成立。1 本 0.1〜0.5 ms で、`kSecCSNoNetworkAccess` を付けても観測した全部で結果は同じ
- Team ID (`kSecCodeInfoTeamIdentifier`) は CodeDirectory の値で、意味を持つのは根が Apple の時だけ。開発者が持つ証明書 (Developer ID、開発用、配布用) では、Security framework の検証 (`SecCodeCheckValidity` が通る `SecStaticCode::verifySignature`) が CodeDirectory の Team ID と leaf 証明書の OU の一致を強制する。Mac App Store で配られたものと Apple 自身のコードは照らされないが、署名するのが Apple (findings `2026-11-15-team-id-and-leaf-certificate-ou.md`)。Apple 自身のコードにも Team ID を持つものがある (Xcode の CoreSimulator)
- 検証の失敗には種類がある: 走っている間に実行ファイルが更新・差し替えされた (`errSecCSStaticCodeChanged`、-67034)、実行ファイルが消えている (SecCode が得られず 100002)、それ以外。差し替えられた時に `SecCodeCopySigningInformation` が返すのは差し替えた先のディスク上のファイルの情報で、走っているコードの情報ではない
- カーネルは exec した vnode に紐づけて、起動した時のコードの署名を持ち続ける。Security.framework は `kSecGuestAttributeDynamicCode` を足した `SecCodeCopyGuestWithAttributes` (以下 pid ベース) で、ディスクの代わりにカーネルの署名の blob を検証する。単体の実行ファイルの差し替え (-67034) と、ユーザ権限から読めない setuid の実行ファイル (走っている `sudo`。通常の方法は SecCode すら得られず 100013) は、pid ベースなら検証でき、`anchor apple` / Developer ID の requirement も評価できた。通常の方法で通る対象 (9 つ) では、pid ベースも同じ結果を返した。実行中に更新された app bundle (-67030) と、実行ファイルが消えたもの (-67065) は pid ベースでも失敗する (Info.plist とバンドルの場所をディスクから取るため)。この属性は公開ヘッダに宣言があるだけで、意味の説明が無い
- 検証に成功した時の `kSecCodeInfoUnique` (cdhash) はカーネルの cdhash と一致した。Security.framework は検証の中でカーネルの cdhash と照合している (公開ソースの `cskernel.cpp`)
- hardened runtime と platform binary: 走っている `sudo` は、署名の flags (CodeDirectory) に hardened runtime が無いのに、カーネルの動的な status (`kSecCodeInfoStatus`) には `CS_RUNTIME` (0x10000) が立っていた。観測した platform binary 4 つ (launchd、zsh、configd、sudo) は全部 status に `CS_RUNTIME` と `CS_PLATFORM_BINARY` があった
- 所要時間: 走っているプロセス 1 つの検証は中央値 1.8 ms (987 プロセス)、大きな app bundle の 1 回目で最大 47 ms。最初の検証の後は requirement を足しても 1 本 0.5 ms 未満。ディスク全体の静的検査 (`SecStaticCodeCheckValidity`) は app bundle で 34 ms〜1.7 s

今の procline は、証明書の種類を leaf の subject summary の文字列で判定し (暫定と明記)、Apple 自身のコードを `anchor apple generic` と署名の情報の platform identifier で判定し、開発用を `DeveloperId` に倒し、公証を評価せず、検証に失敗しても identifier / Team ID / 証明書を持ち、`kSecCSDefaultFlags` で検証し、hardened runtime を CodeDirectory の flags から取る。信頼度の名前と表示の言葉 (「警告なし」「未公証」) は、署名の身元と操作の安全を区別しない。

- 目的: 収集結果の署名が、検証した事実だけを表し、表示と照合のどちらも確かめたことより強く言わない
- 増やしたくないもの:
  - 検証していないことを示す値 (名前の文字列からの推定、どの段階までを指すか分からない言葉)
  - 署名の判定の置き場: procline-core の 1 か所に置き、pam-passkey の `protocol::signature` と二重に持たない。pam-passkey が procline に載せ替える時に向こうの判定を消せる形にする
  - OS の版に依る危うい経路 (説明の無い属性) に頼る範囲

## Decision

### 型 (procline-core)

```rust
/// ProcessInfo.code_signing: Option<CodeSigning>。None は収集しなかった (CollectOptions.signature が false)
pub enum CodeSigning {
    Verified(VerifiedSignature),
    Failed(FailureReason),
    Unsigned,
    /// 収集の時間の予算で検証しなかった
    NotChecked,
}

pub enum FailureReason {
    /// 走っている間に実行ファイルが更新・差し替えされた
    Replaced,
    /// 実行ファイルが消えている
    Missing,
    Other,
}

/// 検証に成功した署名。身元はここにしか無い
pub struct VerifiedSignature {
    pub identifier: String,
    /// 検証に成功した code の kSecCodeInfoUnique (= カーネルが持つ走っているコードの cdhash)
    pub cdhash: CdHash,
    pub signer: Signer,
    /// カーネルの動的な status から取る
    pub runtime: RuntimeState,
    /// 署名に封印された entitlements (dict の形のもの)
    pub entitlements: Option<serde_json::Map<String, serde_json::Value>>,
    /// 署名で封印された Info.plist の CFBundleIdentifier
    pub bundle_id: Option<String>,
    /// 何を検証したか: ディスク上の実行ファイル (通常) か、カーネルが持つ署名 (pid ベース)
    pub verified_from: VerifiedFrom,
}

pub enum Signer {
    AdHoc { linker_signed: bool },
    Certificate { chain: Vec<Certificate>, root: Root },
}

/// 証明書の根。requirement で確かめた結果。Team ID は根が Apple の時だけ持つ
pub enum Root {
    /// anchor apple
    Apple { team_id: Option<String> },
    /// anchor apple generic (anchor apple でない)
    AppleIssued { team_id: Option<String>, kind: CertificateKind },
    /// どちらも満たさない (自己署名、独自の認証局)
    Other,
}

pub enum CertificateKind {
    DeveloperId { notarized: bool },
    MacAppStore,
    Development,
    Other,
}

pub struct RuntimeState {
    pub hardened_runtime: bool, // status の CS_RUNTIME (0x10000)
    pub platform_binary: bool,  // status の kSecCodeStatusPlatform (0x04000000)
    pub debugged: bool,         // status の kSecCodeStatusDebugged (0x10000000)
}

pub enum VerifiedFrom { Disk, RunningCode }

/// 信頼の印。CodeSigning::mark() が 1 か所で決める
pub enum Mark {
    Apple, DeveloperIdNotarized, DeveloperId, MacAppStore, Development, AppleIssuedOther,
    OtherCertificate, Adhoc, Failed, Unsigned, NotChecked,
}
```

- 「検証に失敗なのに identifier がある」形は作れない。身元 (identifier、cdhash、証明書、Team ID、bundle ID、entitlements) は `VerifiedSignature` にしか無い
- ACL が照合に使う値は `VerifiedSignature` のメソッドで取る: `team_id()` は根が `Apple` か `AppleIssued` の時だけ値を返す (根が `Other` の証明書や ad-hoc は `None`)。`signing_id()` は `identifier`、`bundle_id()`、`cdhash()`。`binary` の署名由来の field は、`code_signing` が `Verified` の時だけ当たる (今と同じ)
- `SignatureTrust`、`Signature`、`SignatureValidity`、`CodeSigning::trust()`、`ProcessInfo::signature_trust()` は、上の型と `CodeSigning::mark()` に置き換える
- 印は「このバイナリが誰のものと確かめられたか」を表す。操作が安全かどうかは表さない (`zsh` や `sudo` は常に `Apple`)

### 信頼の印 (CodeSigning::mark)

上の行から順に当てて最初に当たったもの。

| 印 | 条件 | 表示の推奨 |
|---|---|---|
| `apple` | 検証に成功、根が `Apple` | 緑 |
| `developer_id_notarized` | 検証に成功、根が `AppleIssued`、種類が Developer ID、公証済み | 色なし、Team ID を添える |
| `developer_id` | 同上で公証なし | 色なし、Team ID を添える |
| `mac_app_store` | 検証に成功、根が `AppleIssued`、種類が Mac App Store | 色なし、Team ID を添える |
| `development` | 検証に成功、根が `AppleIssued`、種類が開発用 | 色なし、Team ID を添える |
| `apple_issued_other` | 検証に成功、根が `AppleIssued`、種類がその他 | 色なし |
| `other_certificate` | 検証に成功、証明書あり、根が `Other` | 赤 |
| `adhoc` | 検証に成功、証明書なし | 赤 |
| `failed` | 検証に失敗 | 赤、理由を添える |
| `unsigned` | 署名なし | 赤 |
| `not_checked` | 時間の予算で検証しなかった | 赤 |

- 赤は「身元が確かめられない」に揃える。hardened runtime と platform binary は印に使わず、事実として出す (色を付けない)
- 印の値と言葉の対応は、表示する側 (アプリ) が持つ。procline は値と事実を返す

### 検証の手順 (1 プロセス)

1. SecCode を得る。接続相手は audit token (`kSecGuestAttributeAudit`)、祖先は pid
2. requirement 無しの `SecCodeCheckValidity`。`errSecCSUnsigned` (-67062) なら `Unsigned`
3. 2 か 1 が「実行ファイルを読めない」(100013) か「ディスク上の実行ファイルが走っているものと違う」(-67034) で失敗したら、pid ベース (同じ参照に `kSecGuestAttributeDynamicCode` を足す) で 1 と 2 をやり直す。それも失敗したら `Failed` で、理由は通常の方法の戻り値で分類する (-67034 → `Replaced`、100002 → `Missing`、それ以外 → `Other`)。その他の失敗は pid ベースに切り替えず `Failed`
4. 成功したら、`SecCodeCopySigningInformation` (署名と動的な情報) で identifier、cdhash (`kSecCodeInfoUnique`)、証明書の連なり、flags、動的な status、entitlements、Info.plist を取る。identifier・cdhash・flags・status のどれかが取れなければ `Failed(Other)`。status に valid (`CS_VALID`、0x1) が無ければ `Failed(Other)` (検証の後に valid が外れたコードに身元を付けない)。entitlements の blob (`kSecCodeInfoEntitlements`) があるのに dict の形 (`kSecCodeInfoEntitlementsDict`) で取れない時も `Failed(Other)` (保護を緩める entitlement の有無を確かめられないまま「無い」と言わない。[DR-0012](DR-0012-strength-class-from-protection.md) の保護の状態はこれで決まる)
5. 証明書が無ければ `AdHoc` (flags の `kSecCodeSignatureLinkerSigned` で linker が付けたものか)。あれば根を `anchor apple` → `anchor apple generic` の順に評価し、`AppleIssued` の時だけ種類を Mac App Store → Developer ID → 開発用の順に評価し、Developer ID の時だけ `notarized` を評価する。requirement の文字列は次に固定する
   - Mac App Store: `anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists`
   - Developer ID: `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists`
   - 開発用: `anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.12] exists`
6. requirement の評価が成立 (0) と不成立 (`errSecCSReqFailed`) 以外を返したら、その戻り値で `Failed` に分類する。コンパイルに失敗した requirement は、その戻り値を返したものとして扱う

- 検証の呼び出しには全部 `kSecCSNoNetworkAccess` を付ける (待ちの長さをネットワークに左右させない。結果は観測した全部で同じだった)。オンラインの失効確認 (証明書、取り消された公証) はしない
- ディスク全体の静的検査はしない
- 手順 1〜6 の順序、失敗の分類、印の決定は procline-core の純関数に置き、Security framework の呼び出しは OS ごとの crate が trait で渡す (procline-macos は呼び出しと生の戻り値だけを持つ)
- cdhash の出どころは、検証に成功した code の `kSecCodeInfoUnique`。Security.framework が検証の中でカーネルの cdhash と照合しているので、走っているコードの cdhash になる。カーネルに直接問う SPI (`csops`) は使わない
- hardened runtime と platform binary はカーネルの動的な status から取り、CodeDirectory の flags と platform identifier からは取らない

### 時間とキャッシュ

- crate は署名の検証の結果をキャッシュしない (cdhash をキーにしたキャッシュを持たない)。1 プロセスの検証は中央値 1.8 ms で、ネットワークを使わない。常駐するアプリがキャッシュするかはアプリが決める
- 収集に検証の時間の予算を与えられる (`CollectOptions.signature_budget: Option<Duration>`)。予算を超えた時点で、検証を始めていないプロセスは `NotChecked` にする。1 回の Security framework の呼び出しは途中で打ち切れない

### JSON (`code_signing`)

```json
{"state": "verified", "mark": "developer_id_notarized",
 "identifier": "com.example.app", "cdhash": "36e6041264ceb14d55f2178cdbe76ec1227b8565",
 "signer": {"kind": "certificate",
            "root": {"kind": "apple_issued", "team_id": "ABCDE12345",
                     "certificate_kind": {"kind": "developer_id", "notarized": true}},
            "chain": [{"summary": "Developer ID Application: Example (ABCDE12345)", "der": "MIIF…"}]},
 "runtime": {"hardened_runtime": true, "platform_binary": false, "debugged": false},
 "entitlements": {"com.apple.security.app-sandbox": true},
 "bundle_id": "com.example.app",
 "verified_from": "disk"}
{"state": "verified", "mark": "adhoc", "identifier": "tool-1234", "cdhash": "…",
 "signer": {"kind": "ad_hoc", "linker_signed": true}, "runtime": {…}, "entitlements": null, "bundle_id": null, "verified_from": "disk"}
{"state": "failed", "mark": "failed", "failure": "replaced"}
{"state": "unsigned", "mark": "unsigned"}
{"state": "not_checked", "mark": "not_checked"}
```

- 型の形をそのまま写す (state で分け、当てはまらない要素はキーごと無い)。`mark` は `CodeSigning::mark()` の値を書き出す
- これは書き出しの形で、`CodeSigning` は JSON から読めない (収集した事実の型は `Deserialize` を持たない。[DR-0014](DR-0014-chain-trust-boundary-and-caller-supplied-values.md))
- バイト列は base64url (padding なし)、enum の値は snake_case (今の決まりと同じ)
- 証明書の `summary` は、Security framework が証明書から作る subject の要約 (`SecCertificateCopySubjectSummary`) で、表示専用 (subject は署名する側が書けるので判定に使わない)。要約を作れない証明書 (subject が空のもので観測) では null (`Certificate.summary: Option<String>`)

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 証明書の種類を leaf の subject summary の文字列で判定する | 自己署名で同じ名前を名乗れる (観測)。名前は署名する側が決める値 |
| Apple 自身のコードを `anchor apple generic` と platform identifier で判定する | platform identifier も署名の情報で、`anchor apple generic` は Apple が開発者に発行した証明書も満たす。Apple 自身かは `anchor apple` で確かめられる |
| 開発用の証明書を Developer ID に倒す | 開発用を Developer ID と言うことになり、確かめたことより強く言う。開発用は区別できる (leaf の OID) |
| 開発用を `certificate 1[field.1.2.840.113635.100.6.2.1]` で判定する | Mac App Store の中間も同じ OID を持ち、Mac App Store が開発用にも当たる (観測) |
| 検証に失敗した署名にも identifier / Team ID / 証明書を持たせる | 差し替えられた時に取れるのは差し替えた先のファイルの情報で、走っているコードの情報ではない (観測)。別のバイナリの身元を、走っているプロセスの身元として見せることになる |
| 常に pid ベースで検証する | 通常の方法で通る対象では結果が同じで得るものが無い。意味の説明の無い属性の挙動が版で変わった時に、全プロセスの検証が崩れる。通常の方法が失敗した時だけにすれば、崩れるのはその対象だけ |
| カーネルの値 (`csops` の CDHASH / IDENTITY / TEAMID / STATUS) で身元を補う | SDK にヘッダの無い SPI。identifier と Team ID は署名する側が書いた値で、根の検証が無い。pid ベースで requirement まで評価できるので要らない |
| 信頼度 (`SignatureTrust`) の名前と、「警告なし」「未公証」の言葉を残す | 「警告なし」は操作の安全を言っているように読め、「署名の身元が確かめられた」と区別しない。印は身元の確かさだけを表す |
| 印を型に持たず、表示する側が事実から決める | 判定がアプリ (pam-passkey の承認ページ、cw) ごとに分かれ、ずれる。印は core の 1 か所で決め、値として渡す |
| 公証を `None` (評価しない) のままにする | Developer ID の公証は requirement で 0.1〜0.5 ms で評価できる (観測)。評価しないと、公証の有無を区別できない |
| 署名の結果を cdhash をキーにキャッシュする | 走っているプロセスの検証は中央値 1.8 ms で、ネットワークを使わない。キャッシュは、差し替えや失効の後に古い結果を返す経路を足す |
| `kSecCSDefaultFlags` で検証する | 待ちの長さがネットワークに左右される。観測した範囲では結果も変わらなかった |

## Consequences

- 表示と照合の元が同じ型 (`CodeSigning`) になり、検証に成功していない署名からは身元が取れない
- `binary` の `team_id` は、根が `Apple` か `AppleIssued` の時だけ照合元を持つ (Developer ID、Mac App Store、開発用の証明書は `AppleIssued`)。今の自己署名の Team ID (codesign の自己署名では Team ID は入らなかったが、CodeDirectory を自前で組めば入りうる。未観測) で当たる経路が閉じる
- pam-passkey の `protocol::signature` (DR-0014 の検証の手順、失敗の分類、印) と同じ判定がここに置かれ、載せ替えの時に向こうを消せる。印の値は同じ 11 個。JSON の形は違う (procline は型の形を写す)。承認ページは載せ替えの時に追従する
- 走っている `sudo` (setuid、実行ファイルを読めない) を、ユーザ権限の収集から `apple` と検証できる (pid ベース)
- 実行中に更新された app bundle と、実行ファイルが消えたプロセスは `Failed` になる。走っているコードが改ざんされたわけではない (カーネルの cdhash は起動時のままで、status は valid)
- 証明書と公証のオンラインの失効確認はしない。失効した Developer ID の証明書や取り消された公証が、端末に失効の情報が届くまで印に出ない
- 説明の無い属性 (`kSecGuestAttributeDynamicCode`) に依るのは、通常の方法が 100013 か -67034 で失敗した時だけ
- 未観測の点:
  - 開発用の leaf の OID 1.2.840.113635.100.6.1.12 の一次資料での裏取り
  - ネットワークの無い状態での `notarized` の評価
  - pid ベースの -67065 が、削除以外に何で出るか
  - 公証が取り消された Developer ID、Developer ID Installer、Apple Distribution の結果

## 関連

- [DESIGN-ja の「収集する情報」「署名の検証と信頼の印」「matcher」「API の骨格」](../DESIGN-ja.md)
- [DR-0012](DR-0012-strength-class-from-protection.md): 強さのクラスを対象の保護の状態で決める (この DR の `RuntimeState` と entitlements を使う)
- [DR-0006](DR-0006-structured-values-instead-of-depends.md): `binary` の値の形と、署名由来の field は検証が通った時だけ当たること
- [findings: collect_pid の観測](../findings/2026-11-09-collect-pid-observations.md): `anchor apple generic` の評価
- [findings: audit token と kSecGuestAttributeDynamicCode](../findings/2026-11-15-audit-token-dynamic-code.md): 接続相手を audit token で参照した時の pid ベースの検証
- [findings: 実行ファイルを消したプロセスの参照の時機](../findings/2026-11-15-deleted-executable-lookup-timing.md): 起動の直後に実行ファイルを消したプロセスの検証の失敗
- [findings: ad-hoc の bit と証明書の列](../findings/2026-11-15-adhoc-flag-and-certificate-list.md): 証明書の列が空かどうかと CodeDirectory の ad-hoc の bit の一致
- [findings: Team ID と leaf 証明書の OU](../findings/2026-11-15-team-id-and-leaf-certificate-ou.md)
- pam-passkey (別リポ kawaz/pam-passkey): DR-0014、findings `2026-11-15-process-signing-elements.md`、`2026-11-15-running-code-identity.md`
- TN3127: Inside Code Signing: Requirements (https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
