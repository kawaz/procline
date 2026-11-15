# cw (cache-warden) の評価と承認画面は別のプロセスで、間を表示専用の JSON が渡る

- Date: 2026-11-15

cw のリポ (`kawaz/cache-warden`) を読んで確かめた。cw はまだ procline を使っておらず、自前の `macos-process-inspect` crate で収集している。以下のパスは cw のリポのルートからの相対。

## 判明した事実

- 照合 (kv の guard の評価) と承認画面は別のプロセス。評価は daemon (`cache-warden`) が行い、承認のダイアログは daemon が起動して常駐させる GUI の helper (`CacheWardenApprover`) が出す
  - 設計: `docs/decisions/draft-DR-0031-custom-touchid-dialog.md` の「1. アーキテクチャ」(150〜170 行。「2 プロセス構成」)、「3. helper のライフサイクル」(315〜336 行。daemon が起動時に spawn して維持)
  - 実装: helper は workspace の別の crate `crates/cache-warden-approver` (`src/main.rs`、`src/wire.rs`)。daemon 側の呼び出し口は `crates/cache-warden-cli/src/daemon/approver.rs`、guard の評価は同じディレクトリの `guard.rs`、wire への変換は `approver_wire.rs`
- 間を渡るのは、daemon → helper の承認の要求と、helper → daemon の結果。どちらも 1 行 1 つの JSON
  - 設計: 同じ draft の「4. IPC」(338〜398 行)。要求は `requester.chain` (pid、ppid、path、start_time)、`audit_token`、`responsible_bundle_id`、guard の評価の結果 (`guard_eval`) を持つ
  - 実装: `crates/cache-warden-approver/src/wire.rs`。冒頭 (1〜21 行) が「daemon は Rust、helper は別のプロセスなので、型はプロセスの境界を越えられず JSON が合流点」とし、`ProcessChainEntry` (183〜203 行) は「core の `ProcessInfo` でなく、必須の field だけの型。helper は表示専用の利用者」とする。収集の型そのものは渡していない
- helper は daemon から受け取った値を表示し、承認の結果だけを返す
  - `ApproveResponse` (`wire.rs` 289〜302 行) は `request_id`、`outcome` (`approved` / `denied` / `cancelled` / `peer_gone` / `timeout` / `biometric_failed`)、`biometric_kind` だけで、ルールや選んだ項目は返さない
  - helper は要求元が終わったかを自分で見る (draft の「7. peer exit 処理」603〜629 行。kqueue、または `macos-process-inspect` での pid の読み直し。`crates/cache-warden-approver/Cargo.toml` 37 行で依存)。判定は daemon の側で、`peer_gone` を受けた daemon が kv の取得を失敗にする
- 承認画面からルールを作る (承認を記憶する) 操作は、設計でも実装でも、まだ無い
  - `docs/decisions/draft-DR-0030-kv-peer-identity-guard.md` の 214〜221 行: 拒否の代わりに人間の承認へ上げる経路は作らず、「TOFU + remember (不一致 → TouchID → TTL 付きで許可を記憶)」の検討が始まっていて、ダイアログの DR の側で再訪する

## 実用的な示唆

- cw が procline に載せ替えると、procline の収集の結果を daemon が集め、評価も daemon で行い、承認画面は別のプロセスで表示する形になる。承認画面のプロセスは収集の結果を JSON で受け取って読む側にあたる (今は cw 自身の表示用の型で受けている)
- 承認画面からルールを作る操作を足すなら、chain を持って `resolve_subject` (プレビュー) と `Policy::grant` を呼べるのは daemon で、承認画面のプロセスは利用者が選んだもの (どの項目を pin するか) を返す形になる。procline の `SubjectBuilder` / `RuleBuilder` は収集結果を受け取らないので、この分け方と合う (推定。cw の設計にはまだ無い)

## 検証の詳細

読んだもの (cw のリポ):

| ファイル | 読んだ箇所 |
|---|---|
| `docs/decisions/draft-DR-0031-custom-touchid-dialog.md` | 1〜12 行 (状態)、148〜172 行 (アーキテクチャ)、315〜336 行 (ライフサイクル)、338〜414 行 (IPC と wire schema)、600〜629 行 (peer exit) |
| `docs/decisions/draft-DR-0030-kv-peer-identity-guard.md` | 214〜221 行 |
| `docs/issue/archive/2026-06-22-crate-macos-process-inspect.md` | 冒頭 (収集の crate の範囲) |
| `crates/cache-warden-approver/src/wire.rs` | 1〜210 行、286〜310 行 |
| `crates/cache-warden-approver/Cargo.toml` | 37 行 |
| `crates/cache-warden-cli/src/daemon/` | ファイルの一覧、`approver_wire.rs` の `to_wire_guard_eval` (141 行〜) |
| `Cargo.toml` (workspace) | members |

`docs/` の下に procline への言及は無かった (`rg -i procline docs` が 0 件)。
