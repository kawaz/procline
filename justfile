# procline justfile
#
# Task runner following the canonical justfile of kawaz/bump-semver: VCS-shaped gates (clean check, default branch, translation freshness, push) delegate to `bump-semver vcs` subcommands.
# The crates are not published yet, so there is no release flow. Add the canonical `bump-version` / `check-version-bumped` at the first release.
#
# Declaration order is intentional: most-used recipes first so `just --list` (and `default`) surface them prominently.

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

# default behaviour: alias for `list`
default: list

# show the recipe list
list:
    @just --list --unsorted

# ---------- atomic (lint / test / build) ----------

# cargo fmt --check + cargo clippy
[private]
lint-rust:
    cargo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings

# just --fmt (justfile self-format check)
[private]
lint-just:
    just --unstable --fmt --check

# lint-rust + lint-just
lint: lint-rust lint-just

# cargo test for the workspace (ARGS go to cargo test, e.g. `just test -p procline-acl`)
test *ARGS: lint
    cargo test --workspace "$@"

# cargo build for the workspace
build: lint
    cargo build --workspace

# lint + test + build (CI entry point)
ci: lint test build

# ---------- gates (used by `just push`; rarely invoked directly) ----------

# working copy is clean
[private]
ensure-clean:
    bump-semver vcs is clean

# fail if the current bookmark / branch is not the default
[private]
check-on-default-branch:
    bump-semver vcs is on-default-branch

# translation pair freshness (README-ja.md -> README.md, docs/DESIGN-ja.md -> docs/DESIGN.md)
[private]
check-outdated-translations: ensure-clean
    bump-semver vcs outdated 'glob:**/*-ja.md' '$1/$2.md'

# ---------- push ----------

# push the default branch to origin (default branch + ci + translation freshness)
push: check-on-default-branch ci check-outdated-translations
    bump-semver vcs push --branch "$(bump-semver vcs get default-branch)" --jj-bookmark-auto-advance

# ---------- utility ----------

# show the workspace version (Cargo.toml workspace.package.version)
version:
    @bump-semver get Cargo.toml --no-hint
