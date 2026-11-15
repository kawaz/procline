# 走っている全プロセスで、証明書の列が空かどうかと CodeDirectory の ad-hoc の bit は一致した

- Date: 2026-11-15

観測環境: macOS 26.5.2、Apple M1 Max。利用者の権限だけで (sudo なし)、1 回観測した。

## 何を確かめたか

procline の検証 (DR-0011 の手順 5) は、署名の情報に証明書が無ければ `AdHoc` にする。SecCode.h は `kSecCodeInfoCertificates` について「ad-hoc では無い。エラーの時は欠けるか一部だけになりうる」と書くので、証明書が無いことを ad-hoc の証拠にすると、取得に失敗した時と区別できない。代わりに CodeDirectory の flags の `kSecCodeSignatureAdhoc` (0x2。CSCommon.h の注記は「must be used without signer」) で判定する案がある。その前に、今の実装の検証の結果ごとに「証明書の列が空か」と「ad-hoc の bit」の組を数え、食い違うプロセスがあるかを確かめた。

## 判明した事実

`proc_listallpids` で列挙した全プロセス (1013 個) を pid で検証した。利用者の権限でも、root のプロセスを含めて検証できた。

検証に成功した 999 個の組:

| 検証したもの (`verified_from`) | 証明書の列が空 | ad-hoc の bit | 件数 |
| --- | --- | --- | --- |
| disk | いいえ | なし | 941 |
| disk | はい | あり | 56 |
| running code | はい | あり | 2 |

- 食い違う組 (証明書の列が空で bit なし、証明書があって bit あり) は 0 件だった
- 別の時刻に、同じ手順で独立に測り直した: 全プロセス 998 個、検証に成功した 984 個で、disk で証明書あり (bit なし) 930、disk で ad-hoc (証明書なし、bit あり) 52、running code で ad-hoc 2。食い違いは 0 件
- running code で検証したものは 2 個とも ad-hoc で、証明書のある署名を running code で検証したプロセスは無かった。この組合せは観測していない
- 印の内訳: `apple` 798、`developer_id_notarized` 140、`mac_app_store` 2、`development` 1、`adhoc` 58
- 検証に成功しなかった 14 個 (`failed` 13、`unsigned` 1) は、署名の情報を読む段に達していないので数えていない

## 実用的な示唆

- この環境では、証明書が無いことと ad-hoc の bit は同じことを言っていた。ad-hoc の判定を bit に変えても、今 `adhoc` や `apple` と出ているプロセスの印は変わらない
- 0 件は、取得に失敗して証明書の列が欠ける場合が無いことの証明ではない (その失敗を起こす手段を持たない)。ad-hoc の判定は証明書の列が空かどうかのままにする (DR-0011 の手順は変えない。観測では flags の ad-hoc の bit と食い違いが 0 件だったため、変えても結果は変わらない)
- 今の規則は、証明書の列を取れずに `AdHoc` になっても印は `adhoc` (赤) で、Team ID も根も持たない (`team_id()` は `None`、signing_id の pin は Team ID と組でなければ作れない)。根は requirement の評価で決まり、証明書の列は表示用なので、信頼を強く言う方向の誤りにはならない (実装を読んで確かめた)

## 検証の詳細

procline-macos の単体テストとして一時的に書き、`cargo test -p procline-macos --lib -- --ignored --nocapture` で走らせた (commit していない)。`SigningCalls` を包んで、検証が読んだ署名の情報ごとに (検証の方法、flags、証明書の列が空か) を記録し、検証の結果が `Verified` なら、最後に読んだ署名の情報 (結果に使われたもの) の組を数える。検証の結果と flags は同じ SecCode から取るので、その間にプロセスが exec しても食い違わない。

```rust
struct Recording<'a> {
    calls: Calls<'a>,
    seen: RefCell<Vec<(Lookup, Option<u32>, bool)>>,
}

impl SigningCalls for Recording<'_> {
    type Code = (Lookup, SecCode);
    fn open(&self, lookup: Lookup) -> Result<Self::Code, i32> {
        self.calls.open(lookup).map(|code| (lookup, code))
    }
    fn check(&self, (_, code): &Self::Code, requirement: Option<Requirement>) -> i32 {
        self.calls.check(code, requirement)
    }
    fn info(&self, (lookup, code): &Self::Code) -> Result<SigningInfo, i32> {
        let info = self.calls.info(code);
        if let Ok(info) = &info {
            self.seen.borrow_mut().push((*lookup, info.flags, info.certificates.is_empty()));
        }
        info
    }
}

// 全 pid について
let result = procline_core::verify::verify(&Recording { calls: Calls { guest: Guest::Pid(pid), requirements: &requirements }, seen: Default::default() });
// Verified なら seen の最後の (flags, 空か) と verified_from で数え、空か != (flags & 0x2 != 0) なら pid、実行パス、flags、印を出す
```

出力 (要約):

```
COUNT	Disk	certificates_empty=false	adhoc_bit=false	941
COUNT	Disk	certificates_empty=true	adhoc_bit=true	56
COUNT	RunningCode	certificates_empty=true	adhoc_bit=true	2
COUNT	not verified	Failed	13
COUNT	not verified	Unsigned	1
```

`MISMATCH` の行は 1 つも出なかった。
