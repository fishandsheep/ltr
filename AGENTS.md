@/home/zdx/.codex/RTK.md

# Repository Guidelines

## Structure

LTR is a Rust 2021 TCP tunnel and Web control plane, independently forked and
rewritten from ekzhang/bore.

- crates/ltr-protocol: frozen Bore v1 JSON framing and protocol messages.
- crates/ltr-relay: authentication, plaintext/TLS transport, client, server,
  and relay lifecycle.
- src/: ltr-cli command parsing, orchestration, compatibility entry point, and
  embedded Web control plane.
- tests/: protocol, authentication, transport/TLS, Web API, and end-to-end
  behaviour tests.
- npm/ltr*: canonical npm/Bun launcher and 11 platform packages.
- npm/bore*: deprecated compatibility wrappers.
- ci/ and .github/workflows/: cross-compilation and release automation.
- PRODUCT.md and DESIGN.md: Web product and design references.

Read docs/agents/issue-tracker.md for the issue workflow before changing
spec-driven behaviour.

## Commands

- cargo run -- server: run an LTR relay server.
- cargo run -- local 8000 --to localhost: expose a local service.
- cargo run -- web: run the loopback Web console.
- cargo run -- bundle --to server.example: run Web plus SSH system tunnels.
- cargo test --workspace --all-targets: run the complete Rust suite.
- cargo fmt --all -- --check: verify formatting.
- cargo clippy --workspace --all-targets --all-features -- -D warnings: run lints.
- npm run npm:check: validate release versions and package relationships.
- npm run npm:pack:dry-run: pack all canonical and compatibility packages.

Before handoff, run formatting, the full Rust suite, Clippy, npm checks, npm
pack dry-run, Node syntax checks, and git diff --check. A step is complete only
when its command exits successfully.

## Style and interfaces

Use four-space rustfmt indentation, snake_case functions/modules, PascalCase
types, and SCREAMING_SNAKE_CASE constants. Keep async network work on Tokio.
Use anyhow::Result for fallible orchestration. Keep protocol, transport, relay,
CLI, and Web seams narrow; depend on domain behaviour rather than task or
framing internals.

Canonical CLI/environment names use ltr and LTR_*. Keep bore, bore-cli, BORE_*,
and bore home only where they implement the documented two-major version
migration window.

## Security

Never print, trace, serialize, or include secret values in errors. HMAC secrets,
Web bearer tokens, and private keys must be redacted in Debug output. Plaintext
is the compatibility default; document and test TLS, certificate validation,
bind addresses, and Web authentication when changing transport or Web code.

## Pull requests

Use concise Conventional Commit subjects. Describe user-visible CLI, Web,
npm/Bun, Cargo, release, and migration changes, and list verification commands.
Link the canonical LTR issue when applicable.
