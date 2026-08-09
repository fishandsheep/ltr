# LTR

[中文版](README.md)

[![Build status](https://img.shields.io/github/actions/workflow/status/fishandsheep/ltr/ci.yml)](https://github.com/fishandsheep/ltr/actions)
[![Crates.io](https://img.shields.io/crates/v/ltr-cli.svg)](https://crates.io/crates/ltr-cli)

LTR (Local-to-Remote) is a small asynchronous Rust TCP tunnel. It exposes a local TCP service through a remote relay while preserving the Bore plaintext protocol and command workflow for compatibility.

This project is an independent fork and rewrite of [ekzhang/bore](https://github.com/ekzhang/bore). LTR keeps the upstream TCP relay and HMAC challenge-response ideas while adding a Web control plane, remote Web/SSH bundle mode, first-class npm/Bun distribution, platform packages, security controls, and a new product identity.

## Install

Install globally with npm:

```sh
npm install -g @qinshower/ltr@0.0.1
```

Install globally with Bun:

```sh
bun add --global @qinshower/ltr@0.0.1
```

You can also run LTR without a global install through npx or bunx:

```sh
npx @qinshower/ltr@0.0.1 local 8000 --to your-server.example
bunx @qinshower/ltr@0.0.1 local 8000 --to your-server.example
```

Install from crates.io:

```sh
cargo install ltr-cli --version 0.0.1
```

Standalone binaries and SHA-256 checksums are available on the [Releases page](https://github.com/fishandsheep/ltr/releases).

## Quick start

Run a relay server:

```sh
ltr server --secret change-me
```

Expose local port `8000`:

```sh
ltr local 8000 --to your-server.example --secret change-me
```

The compatible control port is `7835`; remote tunnel ports default to `1024..=65535`. Use `--bind-addr` and `--bind-tunnels` when the control and public tunnel listeners need different interfaces.

## Web control plane

Local Web mode binds to loopback at `127.0.0.1:7836` and does not require login:

```sh
ltr web
# equivalent: ltr --web
```

Remote Web mode explicitly publishes the local console through a relay. It terminates HTTPS locally, generates and persists a self-signed certificate and a separate bearer token, and prints credential file paths at startup without printing secret values:

```sh
ltr web --remote --to your-server.example --port 7836 --secret change-me
```

For production certificates, provide both PEM files:

```sh
ltr web --remote --to your-server.example \
  --web-cert ./server-cert.pem --web-key ./server-key.pem
```

The browser login stores the token in `sessionStorage`; it is never placed in a URL. Every `/api/*` request requires the token. Remote Web and `ltr bundle` keep managed tunnel targets on loopback.

The combined Web-plus-SSH mode is:

```sh
ltr bundle --to your-server.example --secret change-me
```

## Authentication and transport security

HMAC authentication is optional for Bore v1 compatibility. Configure `--secret` on both ends; a server without one emits a warning and never logs secret values. Plaintext remains the default so old Bore clients and servers can interoperate.

Use tunnel TLS when payload encryption is required. Configure the server with a PEM certificate and key, and configure clients with a CA file or certificate fingerprint; LTR does not provide an insecure verification bypass:

```sh
# generate and persist a relay certificate; startup prints its fingerprint
ltr server --tls

# client, validating the generated relay certificate by fingerprint
ltr local 8000 --to your-server.example --tls --tls-fingerprint <fingerprint>

# or provide an existing certificate and key
ltr server --tls-cert ./server-cert.pem --tls-key ./server-key.pem

# client, validating the relay certificate through its CA
ltr local 8000 --to your-server.example --tls --tls-ca ./server-ca.pem
```

For mutual TLS, add `--tls-client-ca` on the server and `--tls-client-cert` plus `--tls-client-key` on the client. Web HTTPS flags (`--web-cert`, `--web-key`) protect the browser control plane separately.

Canonical environment variables use `LTR_*`, for example `LTR_SECRET`, `LTR_SERVER`, and `LTR_LOCAL_PORT`. Existing `BORE_*` variables remain accepted with a deprecation warning; precedence is CLI, `LTR_*`, then `BORE_*`.

Diagnostics use human-readable stderr logs by default. Set `--log-level debug` (or `LTR_LOG_LEVEL`) while troubleshooting, or use `--log-json` / `LTR_LOG_JSON=true` for structured collection. Secrets and Web tokens are not included in these logs.

## Bore migration

| Bore | LTR |
| --- | --- |
| `bore server` | `ltr server` |
| `bore local ...` | `ltr local ...` |
| `bore web` / `bore --web` | `ltr web` / `ltr --web` |
| `bore home ...` | `ltr bundle ...` |
| `bore-cli` | `ltr-cli` |
| `@qinshower/bore` | `@qinshower/ltr` |

The `bore` binary remains as a deprecated compatibility entry point for two LTR major versions. `bore home` is a hidden compatibility alias for `ltr bundle`; old `BORE_*` environment variables are also accepted during migration. The old npm package is a wrapper and prints the same migration warning.

## Development

```sh
cargo build --workspace
cargo test --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features
npm run npm:check
npm run npm:pack:dry-run
```

LTR does not collect telemetry or analytics. Docker images are intentionally outside this project's distribution scope.

## License and lineage

LTR is released under the MIT license. See [NOTICE](NOTICE) and [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) for upstream attribution.
