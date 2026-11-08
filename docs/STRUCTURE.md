# リポジトリ物理構造

```
procline/
  README.md / README-ja.md
  LICENSE
  Cargo.toml                # workspace (members = crates/*、version は workspace.package.version)
  Cargo.lock
  justfile                  # task runner (lint / test / build / ci / push)
  crates/
    procline/               # 入口。core の型と、ビルドターゲットの OS の collect を再公開する (examples/ に dump と bench)
    procline-core/          # 収集結果の型、Strength、env の方針と伏せ字、表示用の無害化 (OS 非依存)
    procline-macos/         # macOS での接続相手と祖先の収集、os.* の語彙 (os_items)
    procline-acl/           # Vocabulary、subject / tag / rule / grant、評価、ルールの作成
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
