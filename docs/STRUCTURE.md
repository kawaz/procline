# リポジトリ物理構造

```
procline/
  README.md / README-ja.md
  LICENSE
  Cargo.toml                # workspace (members = crates/*、version は workspace.package.version)
  Cargo.lock
  justfile                  # task runner (lint / test / build / ci / push)
  crates/
    procline/               # 入口。core の型と、ビルドターゲットの OS の collect を再公開する (examples/ に bench)
    procline-cli/           # procline コマンド。対象と祖先を集めた列を JSON で出す (src/lib.rs に文法・--help・補完の表、src/main.rs に実行)
    procline-core/          # 収集結果の型、Strength、署名の検証の手順と信頼の印 (verify)、env の方針と伏せ字 (OS 非依存)
    procline-macos/         # macOS での接続相手と祖先の収集、Security framework の呼び出し、os.* の語彙が使う OS の観測 (boot_session_uuid、wake_time_secs)。ACL の crate に依存しない
    procline-acl/           # Vocabulary、subject / tag / rule / grant、評価、ルールの作成
    procline-acl-macos/     # macOS の os.* の語彙 (os_items)。tests/ に収集と ACL をまたぐテスト (実プロセスの保護の状態からクラスが決まる)
  docs/
    DESIGN-ja.md            # 設計の正本
    DESIGN.md               # DESIGN-ja.md の英訳
    STRUCTURE.md            # 本ファイル
    QUESTIONS.md            # 裁定・確認待ち (現在待ちのものだけ)
    decisions/              # 設計判断の記録 (DR-NNNN-*.md、索引は INDEX.md、置き換えられた DR は archive/)
    findings/               # 実機で確かめた事実 (YYYY-MM-DD-*.md)
    issue/                  # 作業の issue (YYYY-MM-DD-*.md、索引は INDEX.md、close 済みは archive/)
```

各 crate は `src/lib.rs` を持ち、テストは置き場を言語慣習に従う (単体テストは同じファイルの `#[cfg(test)]`、結合テストは crate 直下の `tests/`)。
