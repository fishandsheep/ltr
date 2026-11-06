@/home/zdx/.codex/RTK.md

# Repository Guidelines

## Structure

LTR is a Rust 2021 TCP tunnel and Web control plane, independently forked and
rewritten from ekzhang/bore.

- crates/ltr-protocol: frozen Bore v1 JSON framing and protocol messages.
- crates/ltr-relay: authentication, plaintext/TLS transport with auto-negotiation,
  client, server, and relay lifecycle (including per-tunnel traffic counters).
- src/: ltr-cli command parsing, orchestration, and the embedded Web control plane.
- src/web/session.rs (API types), registry.rs (tunnel registry + TOML persistence),
  runtime.rs (per-tunnel runtime), state.rs (WebState facade).
- src/web/static/js/: zero-build ES-module frontend (vendored Preact + htm), design
  system "极简信号" in DESIGN.md; i18n dictionaries in i18n.mjs must stay zh/en
  key-parity.
- tests/: protocol, authentication, transport/TLS, Web API, and end-to-end
  behaviour tests.
- npm/ltr*: canonical npm/Bun launcher and 5 platform packages.
- ci/ and .github/workflows/: cross-compilation and release automation; the CI also
  runs live protocol interop tests against upstream ekzhang/bore.
- PRODUCT.md and DESIGN.md: Web product and design references.

User data on disk: `~/.config/ltr/tunnels.toml` (console tunnels, 0600, secrets
included), `~/.config/ltr/known_hosts` (TOFU fingerprints, 0600), and generated TLS
material under `~/.local/share/ltr/`.

Read docs/agents/issue-tracker.md for the issue workflow before changing
spec-driven behaviour.

## Commands

- cargo run: open the local Web console (zero-argument entry).
- cargo run -- server: run an LTR relay server (TLS on by default).
- cargo run -- local 8000 --to localhost: expose a local service.
- cargo run -- bundle --to server.example: run Web plus SSH system tunnels.
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
0.1.0; only the Bore v1 wire protocol stays compatible, guarded by CI interop
tests. Do not reintroduce compatibility wrappers.

## Security invariants

- Never print, trace, serialize, or include secret values in errors. HMAC secrets,
  Web bearer tokens, and private keys must be redacted in Debug output.
- TLS is the default on both ends; the server auto-detects TLS vs plaintext per
  connection. There is no flag that skips certificate validation. TOFU fingerprint
  mismatch fails hard with reset instructions — never add a bypass.
- Tunnel TLS negotiation falls back to plaintext only on message-framing errors;
  certificate-trust failures must never fall back.
- Web console binds loopback by default; remote/bundle modes require loopback
  web-addr and bearer-token authentication.
- Persisted files (tunnels.toml, known_hosts) are written atomically with 0600
  permissions.

## Pull requests

Use concise Conventional Commit subjects. Describe user-visible CLI, Web,
npm/Bun, Cargo, release, and migration changes, and list verification commands.
Link the canonical LTR issue when applicable.
