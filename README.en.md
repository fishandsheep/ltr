# LTR

[中文版](README.md)

[![Build status](https://img.shields.io/github/actions/workflow-status/fishandsheep/ltr/ci.yml)](https://github.com/fishandsheep/ltr/actions)
[![Crates.io version](https://img.shields.io/crates/v/ltr-cli.svg)](https://crates.io/crates/ltr-cli)

LTR (Local-to-Remote) is an async-Rust TCP tunnel. It exposes local TCP services through a remote relay, encrypts transport by default, and ships with a Web console featuring a network topology and live traffic visualization.

The project is an independent fork and rewrite of [ekzhang/bore](https://github.com/ekzhang/bore). The Bore v1 plaintext protocol stays compatible (old Bore clients connect to LTR servers unchanged); everything else — the command surface, transport security, console, and distribution — was redesigned for simplicity.

## Install

```sh
npm install -g @qinshower/ltr
# or
bun add --global @qinshower/ltr
# or run without installing
npx @qinshower/ltr
# or
cargo install ltr-cli
```

Standalone binaries and SHA-256 checksums are on the [Releases](https://github.com/fishandsheep/ltr/releases) page.

## Quick start

**Open the console with zero arguments** (the most common flow):

```sh
ltr
# LTR web console listening on http://127.0.0.1:7836
```

Create, start, and stop tunnels in the browser, with a live topology per tunnel (local service → ltr client → relay → visitors) and request flow. Console tunnels persist in `~/.config/ltr/tunnels.toml` and survive restarts.

Start a relay on your server:

```sh
ltr server --secret change-me
```

Expose a local port without the console:

```sh
ltr local 8000 --to your-server.example --secret change-me
```

## Encrypted by default, TOFU trust

Since 0.1.0 encryption needs no flags:

- The **server** generates and persists a TLS certificate by default
  (`~/.local/share/ltr/`), printing its fingerprint on startup.
- The **client** uses TLS by default and records the server certificate fingerprint on
  first use (TOFU, like SSH `known_hosts`, stored at `~/.config/ltr/known_hosts`).
  A changed fingerprint fails hard with reset instructions — there is no skip option.
- One control port accepts both TLS and plaintext: legacy Bore clients keep working.

Explicit trust is still available:

```sh
# Client validates the server certificate via a CA
ltr local 8000 --to your-server.example --tls-ca ./ca.pem

# Or pin a fingerprint
ltr local 8000 --to your-server.example --tls-fingerprint <sha256>

# Server with existing certs / required client certs (mTLS)
ltr server --tls-cert ./cert.pem --tls-key ./key.pem --tls-client-ca ./ca.pem

# Explicitly disable encryption (e.g. trusted internal networks)
ltr server --no-tls
ltr local 8000 --to your-server.example --no-tls
```

## Remote console and SSH bundle

```sh
ltr bundle --to your-server.example --secret change-me
# → HTTPS console + SSH tunnel (ssh user@your-server.example -p 2222)

ltr bundle --to your-server.example --no-ssh
# → HTTPS console only
```

Remote mode terminates HTTPS locally (auto-generated self-signed certificate and a
dedicated bearer token; only file paths are printed, never secrets). After login the
token lives in `sessionStorage`, and every `/api/*` request carries it. Managed tunnel
targets stay on loopback.

## Web console

- **Signal-rail topology**: each running tunnel renders a four-node data path with
  packets flowing along the rail for request/response direction, plus live rates,
  connection counts, and cumulative bytes. Stopped tunnels collapse the topology.
- **Chinese/English**: follows the browser language, manually switchable.
- **Mobile-first**: below 640px the topology becomes a vertical rail.
- **Respects system settings**: animations degrade to static arrows under
  `prefers-reduced-motion`.
- Zero-build frontend (Preact + htm embedded as ES modules in the binary).

## Environment variables

Canonical variables use `LTR_*`: `LTR_SECRET`, `LTR_SERVER`, `LTR_LOCAL_PORT`,
`LTR_WEB_TOKEN`, `LTR_MIN_PORT`, `LTR_MAX_PORT`, `LTR_TLS_CA`,
`LTR_TLS_FINGERPRINT`, `LTR_TLS_SERVER_NAME`, `LTR_TLS_CLIENT_CERT`,
`LTR_TLS_CLIENT_KEY`, `LTR_NO_TLS`, `LTR_LOG_LEVEL`, `LTR_LOG_JSON`.
Precedence is CLI > `LTR_*`.

Logs are human-readable by default; pass `--log-level debug` or `--log-json` for
structured output. Secrets and tokens never appear in logs.

## Relationship to Bore

- **Protocol compatibility stays**: Bore v1 clients connect to LTR servers, and LTR
  clients connect to Bore servers (the latter falls back to plaintext automatically —
  no `--no-tls` needed).
- **Compatibility wrappers are gone** (0.1.0): the `bore` binary, `BORE_*` variables,
  the `bore home` alias, and the `@qinshower/bore*` npm packages are no longer
  published. Commands map one-to-one: `bore local` → `ltr local`, `bore server` →
  `ltr server`.
- Compatibility is guarded in CI by live interop tests against upstream
  [ekzhang/bore](https://github.com/ekzhang/bore).

## Development

```sh
cargo build --workspace
cargo test --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
npm run npm:check
npm run npm:pack:dry-run
```

LTR collects no telemetry or analytics. Docker images are out of distribution scope.

## License and lineage

LTR is released under the MIT license. Upstream attribution is in [NOTICE](NOTICE) and
[ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).
