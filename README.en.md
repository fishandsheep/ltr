# LTR

[中文版](README.md)

[![Build status](https://img.shields.io/github/actions/workflow-status/fishandsheep/ltr/ci.yml)](https://github.com/fishandsheep/ltr/actions)
[![Crates.io version](https://img.shields.io/crates/v/ltr-cli.svg)](https://crates.io/crates/ltr-cli)

LTR (Local-to-Remote) is an async-Rust TCP tunnel. It exposes local TCP services through a remote relay, encrypts transport by default, and ships with a Web console featuring a network topology and live traffic visualization.

The project started as an independent fork and rewrite of [ekzhang/bore](https://github.com/ekzhang/bore) and has since fully diverged: the command surface, transport security, console, and distribution are redesigned for simplicity, and interoperability with Bore clients or servers is no longer promised (LTR relays are only guaranteed to work with LTR clients).

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

Every command runs in the background by default: it prints its startup summary and log directory, then detaches from the terminal, appending logs under the data dir's `logs/`. Pass `--front` (or set `LTR_FRONT=1`) to stay in the foreground. Background mode is not available on Windows yet; LTR falls back to the foreground with a notice.

Start a relay on your server:

```sh
ltr server --secret change-me
```

Expose a local port without the console (a bare port means 127.0.0.1):

```sh
ltr 8000 -t your-server.example --secret change-me
ltr 192.168.1.5:8000 -t your-server.example -p 9000   # explicit local address and remote port
```

## Encrypted by default, TOFU trust

Since 0.1.0 encryption needs no flags:

- The **server** generates and persists a TLS certificate by default
  (`~/.local/share/ltr/`), printing its fingerprint on startup.
- The **client** uses TLS by default and records the server certificate fingerprint on
  first use (TOFU, like SSH `known_hosts`, stored at `~/.config/ltr/known_hosts`).
  A changed fingerprint fails hard with reset instructions — there is no skip option.
- One control port accepts both TLS and plaintext, auto-detected per connection.

Explicit trust is still available:

```sh
# Client validates the server certificate via a CA
ltr 8000 -t your-server.example --tls-ca ./ca.pem

# Or pin a fingerprint
ltr 8000 -t your-server.example --tls-fingerprint <sha256>

# Server with existing certs / required client certs (mTLS)
ltr server --tls-cert ./cert.pem --tls-key ./key.pem --tls-client-ca ./ca.pem

# Explicitly disable encryption (e.g. trusted internal networks)
ltr server --no-tls
ltr 8000 -t your-server.example --no-tls
```

## Remote console and SSH

Expose each separately (running both replaces the old bundle mode):

```sh
ltr web -t your-server.example    # HTTPS console, remote port 7836 by default
ltr ssh -t your-server.example    # SSH tunnel (ssh user@your-server.example -p 2222), remote port 2222 by default
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

## Configuration and instance management

Save common defaults (such as `to`) so a bare `ltr 8000` just works:

```sh
ltr conf set to your-server.example
ltr conf get          # every setting, its value, and its source
ltr 8000              # uses the configured relay
```

The config file is `~/.config/ltr/config.toml` (0600). Precedence: **CLI > config file
> `LTR_*` environment variables > defaults**. Variables like `LTR_SECRET`,
`LTR_SERVER`, `LTR_TLS_*`, `LTR_LOG_LEVEL`, `LTR_LOG_JSON`, and `LTR_WEB_*` keep
working.

List and stop running instances:

```sh
ltr -l          # list exposed ports (SVC column shows whether the local service is listening)
ltr -s 9000     # stop by port
ltr -s          # interactive picker (a stops all, q cancels)
ltr update      # self-update from GitHub Releases (npm/cargo installs get a hint instead)
```

Logs are human-readable by default; pass `--log-level debug` or `--log-json` for
structured output. Secrets and tokens never appear in logs.

## Relationship to Bore

LTR was originally forked from [ekzhang/bore](https://github.com/ekzhang/bore) (see
ACKNOWLEDGMENTS). The `bore` binary, `BORE_*` variables, and `@qinshower/bore*` npm
packages were removed in 0.1.0; the Bore v1 protocol interop promise is now gone too —
LTR servers are only guaranteed to work with LTR clients. Bore users should migrate
both ends to ltr.

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
