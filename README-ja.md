# procline

> [English](./README.md) | 日本語

プロセスとその祖先 (lineage) の情報を集め、その情報に対するアクセス制御 (ACL) を定義・評価する Rust crate 群。macOS を先に実装する。

## コマンド

`procline` コマンドは、プロセスとその祖先を集めた列を JSON で出す (macOS)。

```sh
cargo install --path crates/procline-cli
procline <pid>        # オプションは procline --help、zsh の補完は source <(procline completion zsh)
```

## ドキュメント

- [DESIGN-ja.md](./docs/DESIGN-ja.md) — 設計 (収集する情報、署名の検証と信頼の印、ACL ルールの形と評価、強さのクラスと保護の状態、scope)

## ライセンス

MIT License, Yoshiaki Kawazu (@kawaz)
