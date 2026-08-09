# LTR

[英文版](README.en.md)

[![构建状态](https://img.shields.io/github/actions/workflow/status/fishandsheep/ltr/ci.yml)](https://github.com/fishandsheep/ltr/actions)
[![Crates.io 版本](https://img.shields.io/crates/v/ltr-cli.svg)](https://crates.io/crates/ltr-cli)

LTR（Local-to-Remote）是一个基于异步 Rust 的 TCP 隧道工具。它把本地 TCP 服务通过远程中继暴露出去，同时保留 Bore 明文协议和命令行工作流的兼容性。

本项目从 [ekzhang/bore](https://github.com/ekzhang/bore) 独立 fork 并重写。LTR 保留上游 TCP 中继与 HMAC challenge-response 思路，并增加 Web 控制台、远程 Web/SSH 组合模式、npm/Bun 分发、多平台包、安全控制和新的产品身份。

## 安装

使用 npm 全局安装：

```sh
npm install -g @qinshower/ltr@0.0.1
```

使用 Bun 全局安装：

```sh
bun add --global @qinshower/ltr@0.0.1
```

也可以不安装，直接使用 npx 或 bunx：

```sh
npx @qinshower/ltr@0.0.1 local 8000 --to your-server.example
bunx @qinshower/ltr@0.0.1 local 8000 --to your-server.example
```

从 crates.io 安装：

```sh
cargo install ltr-cli --version 0.0.1
```

独立二进制和 SHA-256 校验和见 [Releases](https://github.com/fishandsheep/ltr/releases)。

## 快速开始

启动中继服务端：

```sh
ltr server --secret change-me
```

暴露本地 `8000` 端口：

```sh
ltr local 8000 --to your-server.example --secret change-me
```

兼容控制端口为 `7835`；远程隧道端口默认范围为 `1024..=65535`。如果控制端口和公开隧道监听器需要绑定不同网卡，使用 `--bind-addr` 与 `--bind-tunnels`。

## Web 控制台

本地 Web 模式默认绑定回环地址 `127.0.0.1:7836`，不需要登录：

```sh
ltr web
# 等价写法：ltr --web
```

远程 Web 模式会明确通过中继公开本地控制台。它在本地终止 HTTPS，生成并持久化自签名证书及独立 Bearer Token；启动时只打印凭据文件路径，不打印秘密值：

```sh
ltr web --remote --to your-server.example --port 7836 --secret change-me
```

生产证书可同时提供两个 PEM 文件：

```sh
ltr web --remote --to your-server.example \
  --web-cert ./server-cert.pem --web-key ./server-key.pem
```

浏览器登录后会把 Token 保存到 `sessionStorage`，不会放进 URL。每个 `/api/*` 请求都需要 Token。远程 Web 与 `ltr bundle` 会把受管理的隧道目标保持在回环地址。

Web 与 SSH 组合模式：

```sh
ltr bundle --to your-server.example --secret change-me
```

## 身份验证与传输安全

HMAC 身份验证为可选功能，用于 Bore v1 兼容。两端都配置 `--secret`；未配置 Secret 的服务端会发出警告，且不会记录 Secret。为了兼容旧 Bore 客户端和服务端，明文仍是默认传输方式。

如果需要加密隧道负载，启用隧道 TLS。服务端配置 PEM 证书和私钥，客户端使用 CA 文件或证书指纹验证；LTR 不提供关闭验证的不安全绕过选项：

```sh
# 生成并持久化中继证书；启动时打印指纹
ltr server --tls

# 客户端通过指纹验证生成的中继证书
ltr local 8000 --to your-server.example --tls --tls-fingerprint <fingerprint>

# 或提供已有证书和私钥
ltr server --tls-cert ./server-cert.pem --tls-key ./server-key.pem

# 客户端通过 CA 验证中继证书
ltr local 8000 --to your-server.example --tls --tls-ca ./server-ca.pem
```

双向 TLS 需要在服务端增加 `--tls-client-ca`，在客户端增加 `--tls-client-cert` 与 `--tls-client-key`。Web HTTPS 参数（`--web-cert`、`--web-key`）独立保护浏览器控制平面。

规范环境变量使用 `LTR_*`，例如 `LTR_SECRET`、`LTR_SERVER` 和 `LTR_LOCAL_PORT`。迁移期间仍接受 `BORE_*` 环境变量，并发出弃用警告；优先级为命令行、`LTR_*`、`BORE_*`。

诊断默认写入人类可读的 stderr 日志。排查问题时设置 `--log-level debug`（或 `LTR_LOG_LEVEL`），也可以使用 `--log-json` / `LTR_LOG_JSON=true` 输出结构化日志。日志不会包含 Secret 或 Web Token。

## Bore 迁移

| Bore | LTR |
| --- | --- |
| `bore server` | `ltr server` |
| `bore local ...` | `ltr local ...` |
| `bore web` / `bore --web` | `ltr web` / `ltr --web` |
| `bore home ...` | `ltr bundle ...` |
| `bore-cli` | `ltr-cli` |
| `@qinshower/bore` | `@qinshower/ltr` |

`bore` 二进制会在两个 LTR 主版本的迁移窗口内作为弃用兼容入口保留。`bore home` 是指向 `ltr bundle` 的隐藏兼容别名；旧的 `BORE_*` 环境变量也会在迁移期间继续接受。旧 npm 包是兼容包装器，并会打印相同的迁移警告。

## 开发

```sh
cargo build --workspace
cargo test --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features
npm run npm:check
npm run npm:pack:dry-run
```

LTR 不收集遥测或分析数据。Docker 镜像不在本项目的分发范围内。

## 许可证与上游来源

LTR 使用 MIT 许可证发布。上游归属信息见 [NOTICE](NOTICE) 和 [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md)。
