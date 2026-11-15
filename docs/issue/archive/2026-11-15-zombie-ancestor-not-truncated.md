---
title: 終了して回収されていない祖先 (zombie) が、途切れの印なしで列に残る
status: resolved
category: bug
created: 2026-11-15T12:30:00+09:00
origin: 自リポ TODO (pam-passkey のセッションからの起票。署名の検証と収集のレビューの確認で見つかった)
close_reason: implemented
---

# 終了して回収されていない祖先 (zombie) が、途切れの印なしで列に残る

## 概要

祖先が収集の途中で終了し、まだ親に回収されていない (zombie) と、収集はそのプロセスを生きている祖先として扱う。列は `AncestorExited` で途切れず、その行は生前の値か空の値を持つ。DESIGN-ja「収集の整合性」の 4 (祖先は途中で終了していることがある。その場合は「ここで途切れた」と分かる形で列を終える) に沿っていない。

別のプロセスの事実は混ざらない (zombie の間は pid が使い回されない) ので、守りの穴ではない。

## 観測 (macOS 26.5.2、利用者の権限)

C の試験プログラムで、fork した子を終わらせ、`waitid(WEXITED | WNOWAIT)` で終了を待って回収しないまま読んだ:

| 読み方 | 生きている | zombie | 回収済み・存在しない pid |
| --- | --- | --- | --- |
| `sysctl(KERN_PROC_PID)` の `kinfo_proc` | 読める (`p_stat` 2 = `SRUN`) | 読める (`p_stat` 5 = `SZOMB`、起動時刻は生前と同じ) | 0 バイト |
| `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` | 読める | `ESRCH` | `ESRCH` |
| `proc_pidinfo` の未知の flavor (9999。SPI が無い環境の代わり) | `EINVAL` | `EINVAL` | `EINVAL` |
| `proc_pidpath` | 読める | `ESRCH` | `ESRCH` |

`p_stat` は `struct kinfo_proc` の offset 36 (構造体は 648 バイト。SDK のヘッダで `offsetof` を測った)。

procline の収集のテストの足場 (sh とその子のサブシェル。sh を kill して `waitid(WNOWAIT)` で待ち、回収しない) で、今の実装の振る舞いを再現した:

- 署名の検証の後に祖先が zombie になる: 結果は `Ok` で、列は 2 つのまま `truncated` は `MaxAncestors`。祖先の行は記録時の unique ID と生前の署名 (`apple`) を持つ
- 対象を記録した後、親を読む前に親が zombie になる: walk が親として受け入れる。その行の識別子は unique ID なし (`PROC_PIDUNIQIDENTIFIERINFO` が `ESRCH` で `ids: None`) で、親子の確かめは起動時刻の比較に落ちて通る

## 原因

- `Recorded::read` は `kinfo_proc` が読めれば生きているとみなし、`unique_ids` の失敗は「SPI が使えない」として `None` にする。zombie の `ESRCH` も `None` になる
- `same_individual` / `same_image` / `is_parent_of` は、片方の `ids` が `None` なら unique ID と pid version を比べず、起動時刻だけで同じとみなす。zombie の起動時刻は生前と同じなので通る
- 対象 (列の先頭) も同じ経路を通り、収集の途中で対象が zombie になると `Ok` になった (修正を外した状態のテストで、pid の経路と接続相手の経路の両方で観測)

## 直し方の案 (推奨案を採った)

### 推奨 (採用): `kinfo_proc` の `p_stat` が `SZOMB` なら、`Recorded::read` を「そのプロセスは無い」(`ESRCH`) で失敗させる

- `kinfo_proc` が zombie を `ESRCH` の失敗として返し、`Recorded::read` はそれをそのまま返す (呼び出し元は `Recorded::read` だけなので、`KinfoProc` の型は変えない)
- 既存の分岐がそのまま当てはまる:
  - walk: 親の読み込みが `ESRCH` なら `AncestorExited` で列を終える
  - 最後の確かめ直し: 祖先なら列をその手前で `AncestorExited` で終える。対象なら `NoSuchProcess` (pid で集めた時) か `IdentityChanged` (接続相手)
  - 責任プロセスの識別: 読めずに `None` になる
- カーネルが状態として返す値で判定するので、SPI が使えない環境でも効く
- テスト: 今の収集のテストの足場に「sh を終わらせて回収しない」を足す (kill して `waitid(WEXITED | WNOWAIT)` で待つ。時間待ちなし)。足場で上の 2 つの時機を作れることは確かめた。署名の後に zombie になる場合と、walk の前に zombie になる場合の 2 つで、`AncestorExited` になることを固定する。対象が zombie になる場合も足す

### 代わりの案 (不採用。SPI が使えない環境で効かない): `PROC_PIDUNIQIDENTIFIERINFO` の `ESRCH` を「無い」として扱う

- `unique_ids` の失敗のうち `ESRCH` だけを `Recorded::read` の失敗にし、それ以外 (SPI が無い時は `EINVAL` のはず) は今どおり `None`
- `kinfo_proc` の offset を新しく読まなくて済む
- ただし、SPI が使えない環境では zombie を検出できない。未知の flavor が `EINVAL` を返すことは観測したが、SPI が無い版の macOS で実際に何が返るかは観測していない

## 結果

- `kinfo_proc` (呼び出し元は `Recorded::read` だけ) が、`p_stat` が `SZOMB` の時に、既存の「無い」と同じ `no_such_process()` (`ESRCH`) を返す。`KinfoProc` の型は変えていない。`p_stat` の offset 36 (`char`) と `SZOMB` 5 は、SDK (MacOSX 26.5、arm64) のヘッダを `offsetof` でコンパイルして測った (同じプログラムで既存の `p_comm` 243、`e_ppid` 560 も一致)
- 対象が終わっている時 (zombie でも回収済みでも同じ) の返り値。どれも回収済みで消えたプロセスの時と同じ:

  | 経路 | 終わった時機 | 返り値 | 根拠 |
  | --- | --- | --- | --- |
  | pid (`collect_pid`) | 収集の開始の前 | `NoSuchProcess` | 観測 (zombie と回収済み) |
  | pid | 対象を記録した後 (収集の途中) | `NoSuchProcess` | テスト (zombie) |
  | 接続相手 (`collect_peer`) | audit token を読む前 | `Peer` (`ENOTCONN`、Socket is not connected) | 観測 (zombie と回収済み) |
  | 接続相手 | audit token を読んだ後・対象を記録する前 | `NoSuchProcess` | コードを読んだだけ (時機は作っていない) |
  | 接続相手 | 対象を記録した後 (収集の途中) | `IdentityChanged` | テスト (zombie) |
- テスト (`collect::tests`): `a_zombie_ancestor_before_the_walk_ends_the_chain`、`a_zombie_ancestor_after_the_signatures_ends_the_chain`、`a_target_that_became_a_zombie_is_gone` (pid と接続相手)。zombie は kill と `waitid(WEXITED | WNOWAIT)` で作り、時間待ちなし。修正を外すと 3 つとも落ちる (祖先は列が 2 つ残る、対象は `Ok`)。失敗しても子は残らない (Drop で回収)
- DESIGN (ja/en) の「収集の整合性」の 4 に、回収されていない終了済みのプロセスも終了として扱うことを足した

## 受け入れ条件

- [x] 収集の途中で zombie になった祖先で、列がその手前で `AncestorExited` で終わる (署名の後に zombie になる場合と、walk の前に zombie になる場合)
- [x] 収集の途中で zombie になった対象で、結果が `Ok` にならない
- [x] それぞれ、zombie を実際に作るテストで固定する
