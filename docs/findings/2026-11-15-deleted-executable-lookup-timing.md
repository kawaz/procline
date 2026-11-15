# 起動の直後に実行ファイルを消したプロセスは、pid での SecCode の取得が ESRCH (100003) で失敗する

- Date: 2026-11-15

観測環境: macOS 26.5.2 (25F84)、Apple silicon (arm64)。利用者 (uid 501) の権限だけで、procline-macos の結合テスト (`crates/procline-macos/tests/collect_pid.rs`) の中で観測した。

## 判明した事実

- テストのバイナリ (リンカの ad-hoc 署名) を一時ディレクトリにコピーし、`std::process::Command::spawn` で起動して、`spawn` が戻った直後にコピーを削除すると、`SecCodeCopyGuestWithAttributes` (`kSecGuestAttributePid`) は 100003 (Security framework の POSIX の範囲の ESRCH) を返した。5 回とも同じ。プロセスは生きていて、`kinfo_proc` は読めた
- 同じことを、コピーのテストハーネスが動き始めた (標準出力に `running 1 test` を出した) 後に行うと、100002 (ENOENT) を返した。3 回とも同じ。`spawn` の 500 ms 後に削除した場合も 100002
- [audit token での検証の観測](./2026-11-15-audit-token-dynamic-code.md) の削除 (接続の後に削除し 100002) は、後者と同じ状況

## 実用的な示唆

- DR-0011 の分類では 100002 は `Failed(Missing)`、100003 は `Failed(Other)`。起動の直後に実行ファイルが消えたプロセスは `Failed(Other)` になりうる。どちらも身元を持たない `Failed` で、`binary` の署名由来の field に当たらず、印は `failed` で同じ。違うのは表示に添える理由だけ
- 結合テストで「消えた」を確かめる時は、対象が起動を終えたことを (時間でなく) 対象の出力で待ってから消す

## 未観測

- 100003 が返る区間が何で決まるか (dyld の読み込み、`main` の開始、exec の後処理のどれと揃うか)
- 単体の実行ファイルでない対象 (app bundle) での同じ操作
