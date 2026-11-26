@/home/zdx/.codex/RTK.md

# Repository Guidelines

## Structure

LTR is a Rust 2021 TCP tunnel and Web control plane, independently forked from
ekzhang/bore and now fully diverged.

- crates/ltr-protocol: frozen null-delimited JSON framing and protocol messages.
- crates/ltr-relay: authentication, TLS transport (plaintext only with explicit --no-tls),
  client, server, and relay lifecycle (including per-tunnel traffic counters).
- src/: ltr-cli command parsing, orchestration, and the embedded Web control plane.
- src/web/session.rs (API types), registry.rs (tunnel registry + TOML persistence),
  runtime.rs (per-tunnel runtime), state.rs (WebState facade).
- src/conf.rs (settings registry + three-layer resolution), src/daemon.rs
  (background re-exec), src/instances.rs (run registry for -l/-s),
  src/update.rs (GitHub Releases self-update).
- src/web/static/js/: zero-build ES-module frontend (vendored Preact + htm), design
  system "极简信号" in DESIGN.md; i18n dictionaries in i18n.mjs must stay zh/en
  key-parity.
- tests/: protocol, authentication, transport/TLS, Web API, and end-to-end
  behaviour tests.
- npm/ltr*: canonical npm/Bun launcher and 4 platform packages (macOS arm64, Linux x64 musl, Linux arm64 glibc, Windows x64).
- ci/ and .github/workflows/: cross-compilation and release automation.
- PRODUCT.md and DESIGN.md: Web product and design references.

User data on disk: `~/.config/ltr/config.toml` (persistent settings, 0600,
see src/conf.rs key registry; precedence CLI > file > `LTR_*` env > default),
`~/.config/ltr/tunnels.toml` (console tunnels, 0600, secrets included),
`~/.config/ltr/known_hosts` (TOFU fingerprints, 0600), generated TLS material and
background logs under `~/.local/share/ltr/`, and the instance registry under
`~/.local/share/ltr/run/`.

Read docs/agents/issue-tracker.md for the issue workflow before changing
spec-driven behaviour.

## Commands

- cargo run: open the local Web console (zero-argument entry).
- cargo run -- server: run an LTR relay server (TLS on by default).
- cargo run -- 8000: expose a local port through the configured relay
  (`ltr conf set to host` first, or pass `-t host`).
- cargo run -- web / -- ssh: expose the console (remote 7836) or local SSH
  (remote 2222) through a relay.

Commands background themselves after printing the startup summary (pid, log
directory under the data dir's `logs/`); pass `--front` (or set `LTR_FRONT=1`)
to keep them attached to the terminal. Background mode is Unix-only; on Windows
LTR falls back to the foreground with a notice.

Quick commands never daemonize: `ltr -l/--list`, `ltr -s/--stop [PORT]`,
`ltr conf get|set|unset`, `ltr update`. Long-running modes register themselves
under the data dir's `run/` registry so `-l` can list and `-s` can gracefully
stop them (SIGTERM, then SIGKILL).
- cargo test --workspace --all-targets: run the complete Rust suite.
- cargo fmt --all -- --check: verify formatting.
- cargo clippy --workspace --all-targets --all-features -- -D warnings: run lints.
- npm run npm:check: validate release versions and package relationships.
- npm run npm:pack:dry-run: pack all packages.

Before handoff, run formatting, the full Rust suite, Clippy, npm checks, npm
pack dry-run, Node syntax checks, and git diff --check. A step is complete only
when its command exits successfully.

## Style and interfaces

Use four-space rustfmt indentation, snake_case functions/modules, PascalCase
types, and SCREAMING_SNAKE_CASE constants. Keep async network work on Tokio.
Use anyhow::Result for fallible orchestration. Keep protocol, transport, relay,
CLI, and Web seams narrow; depend on domain behaviour rather than task or
framing internals.

Canonical CLI/environment names use ltr and LTR_*. The Bore compatibility layer
(bore binary, BORE_* variables, bore npm packages, the home alias) was removed in
0.1.0, and Bore protocol interop is no longer promised: LTR relays only guarantee
LTR clients. Do not reintroduce compatibility wrappers.

## Security invariants

- Never print, trace, serialize, or include secret values in errors. HMAC secrets,
  Web bearer tokens, and private keys must be redacted in Debug output.
- TLS is the default on both ends. A TLS-enabled server accepts only TLS; plaintext
  requires explicit `--no-tls` on both ends. There is no flag that skips certificate
  validation. TOFU fingerprint mismatch fails hard with reset instructions — never
  add a bypass.
- Tunnel clients never fall back to plaintext after a failed TLS handshake.
- Web console binds loopback by default; remote/bundle modes require loopback
  web-addr and bearer-token authentication.
- Persisted files (tunnels.toml, known_hosts) are written atomically with 0600
  permissions.

## Pull requests

Use concise Conventional Commit subjects. Describe user-visible CLI, Web,
npm/Bun, Cargo, release, and migration changes, and list verification commands.
Link the canonical LTR issue when applicable.
