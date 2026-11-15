---
title: 収集が bundle の Info.plist を大きさも種類も確かめずに読む
status: resolved
category: bug
created: 2026-11-15T18:25:40+09:00
origin: 他プロジェクトからの依頼 (収集だけを使うアプリの設計の確認から)
close_reason: implemented
---

# 収集が bundle の Info.plist を大きさも種類も確かめずに読む

## 概要

収集は、対象と祖先の全部の行で、実行パスの上にある最寄りの `*.app` の `Contents/Info.plist` を読み、表示用の `ProcessInfo.bundle` (bundle ID と版) を作る。この読み取りに大きさの上限が無く、ファイルの種類も確かめていなかった。

- Info.plist は、同じ uid の別プロセス (脅威モデルで守る相手) が中身も種類も決められる。自分で置いた `X.app/Contents/` の中の実行ファイルを起動すればよい
- 巨大なファイル、FIFO (書き手がいなければ open で止まる)、デバイスを置かれると、収集するプロセスが止まるか、メモリを使い切る
- `CollectOptions` に bundle を切る指定が無かった。`digest`、`signature`、`icon` は選べるのに、同じ「相手が決められるファイルを読む」処理の bundle だけ選べず、`ProcessInfo.bundle` を使わない利用者も、相手が決めたファイルの解析を省けなかった (署名で封印された bundle ID は `VerifiedSignature.bundle_id` にあり、`ProcessInfo.bundle` は表示用)

## 決めたこと

- **種類の検査**: `O_NONBLOCK | O_NOCTTY | O_NOFOLLOW` で開き、開いた fd の種類が通常のファイルの時だけ読む。パスを確かめてから開く形にしない (確かめた後にすり替えられる)
- **symlink は辿らない**: 実物の app の Info.plist に symlink は無かった (2026-11-15、`/Applications`、`/System/Applications`、`/System/Library/CoreServices` の 500 件すべてが通常のファイル)
- **ファイルの大きさの上限**: 1 MiB (`MAX_INFO_PLIST_LEN`)。観測した最大は 37,825 バイト (同じ 500 件)。読む量そのものを上限 + 1 バイトで切り、超えたら捨てる (開いた時の大きさの申告には頼らず、読んでいる間に伸びるファイルにも効く)
- **解析は event のストリームで読む**: `plist::Value` (や serde) の木を作らない。同じ子を何度も参照する binary plist は、木にすると数百バイトのファイルが数秒・数百 MB に膨らむ (深さ 22 の配列の鎖で 3.6 秒、678 MB を観測)。ストリーム (`plist::stream`、crate の unstable の feature の裏にあるので版を `~1.10` に固定) は木を作らず、再帰もしない
- **拾う値**: トップレベルの辞書の直下の `CFBundleIdentifier`、`CFBundleShortVersionString`、`CFBundleVersion` の文字列だけ。入れ子の中の同名の key は拾わない。全体を最後まで読めた時だけ値を返す
- **event の数の上限**: 65,536 (`MAX_INFO_PLIST_EVENTS`)。観測した最大は 5,948 (同じ 500 件)
- **読み取りの量の上限**: 4 MiB (`MAX_INFO_PLIST_READ`)。ストリームは共有された大きい文字列を参照のたびに読み直すので、event の数だけでは時間が抑えられない (1 MiB の UTF-16 の文字列で、16,384 event に 25 秒)。解析に渡す reader が読んだバイト数を数え、上限で失敗させる。観測した「読んだバイト数 ÷ ファイルの大きさ」は binary で最大 2.50 (中央値 1.05)、XML で最大 1.02 (中央値 1.00)
- 最悪の入力 (1 MiB の binary plist、配列の鎖 + 約 1 MiB の UTF-16 の文字列) は、release で 1 回の読み取りが約 14 ms、メモリの増分は数 MB で `None` を返す
- 種類が違う・大きすぎる・上限を超える・解析できない時は、どれも `None` (表示用の項目で、取れない時は空)。エラーの型は足さない
- **切る指定**: `CollectOptions.bundle: bool`。切ると `ProcessInfo.bundle` は `None`
- procline コマンドにはオプションを足さない (今の挙動のまま読む)

## 受け入れ条件

- [x] 通常のファイルで上限ちょうどの Info.plist は読める
- [x] 上限を 1 バイト超える Info.plist は `None`
- [x] 書き手のいない FIFO の Info.plist は止まらずに `None`
- [x] ディレクトリの Info.plist は `None`
- [x] symlink の Info.plist は、指す先が正しい plist でも `None`
- [x] binary 形式の正常な Info.plist は読める
- [x] 入れ子の辞書の中にだけ `CFBundleIdentifier` がある plist では、ID は `None`
- [x] 同じ子を何度も参照して指数的に膨らむ binary plist は、トップレベルに正しい ID があっても `None`
- [x] 小さい event だけで event の数の上限を超える plist は `None`
- [x] 共有された大きい文字列で読み取りの量の上限を超える plist は `None`
- [x] 深い入れ子の XML plist でスタックがあふれず `None`
- [x] `.app` の中から起こした実プロセスで、`bundle: true` は Info.plist の bundle ID と版を読み、`bundle: false` は `None`
- [x] DESIGN (ja/en) の「収集する情報」と「API の骨格」に、読むかを選べること、通常のファイルだけを読むこと、上限が 3 つ (ファイルの大きさ、event の数、読み取りの量) であること、トップレベルの値だけを読むことを書く
