# procline

> English | [日本語](./README-ja.md)

Rust crates that collect information about a process and its ancestors (lineage), and define and evaluate access control (ACL) over that information. macOS first.

## Command

The `procline` command prints a process and its ancestors as JSON (macOS). In the strings of the JSON, the control characters that change the state of a terminal, the direction of the display or the lines (DEL, C1, the bidi controls, U+2028, U+2029) are written as `\uXXXX` (the values read as JSON stay the same).

```sh
cargo install --path crates/procline-cli
procline <pid>        # options: procline --help; zsh completion: source <(procline completion zsh)
```

## Documentation

- [DESIGN.md](./docs/DESIGN.md) — design (collected items, signature verification and the trust mark, ACL rule shape and evaluation, strength classes and the protection state, scopes). Japanese original: [DESIGN-ja.md](./docs/DESIGN-ja.md)

## License

MIT License, Yoshiaki Kawazu (@kawaz)
