# LTR

[英文版](README.en.md)

[![构建状态](https://img.shields.io/github/actions/workflow-status/fishandsheep/ltr/ci.yml)](https://github.com/fishandsheep/ltr/actions)
[![Crates.io 版本](https://img.shields.io/crates/v/ltr-cli.svg)](https://crates.io/crates/ltr-cli)

LTR（Local-to-Remote）是一个基于异步 Rust 的 TCP 隧道工具。它把本地 TCP 服务通过远程中继暴露出去，默认加密传输，并内置一个带网络拓扑与流量可视化的 Web 控制台。

本项目从 [ekzhang/bore](https://github.com/ekzhang/bore) 独立 fork 并重写，保留 Bore v1 明文协议兼容（旧 Bore 客户端可直接连接 LTR 服务端），其余部分——命令面、传输安全、控制台、分发——都为简单易用重新设计。

## 安装

```sh
npm install -g @qinshower/ltr
# 或
bun add --global @qinshower/ltr
# 或直接运行
npx @qinshower/ltr
# 或
cargo install ltr-cli
```

独立二进制和 SHA-256 校验和见 [Releases](https://github.com/fishandsheep/ltr/releases)。

## 快速开始

**零参数打开控制台**（这是最常见的使用方式）：

```sh
ltr
# LTR web console listening on http://127.0.0.1:7836
```

在浏览器里创建、启动、停止隧道，实时看到每个隧道的网络拓扑（本地服务 → ltr 客户端 → 中继 → 公网访客）与请求流向。控制台隧道配置持久化在 `~/.config/ltr/tunnels.toml`，重启不丢。

在服务器上启动中继：

```sh
ltr server --secret change-me
```

不开控制台、直接命令行暴露本地端口：

```sh
ltr local 8000 --to your-server.example --secret change-me
```

## 默认加密与 TOFU 信任

从 0.1.0 起，加密不再需要任何参数：

- **服务端**默认生成并持久化 TLS 证书（`~/.local/share/ltr/`），启动时打印指纹。
- **客户端**默认走 TLS，首次连接记录服务器证书指纹（TOFU，类似 SSH 的
  `known_hosts`，存储在 `~/.config/ltr/known_hosts`）。之后指纹变化将硬失败并提示
  如何重置——没有跳过校验的选项。
- 同一个控制端口同时接受 TLS 与明文连接：旧 Bore 客户端无需任何改动。

显式信任方式仍然可用：

```sh
# 客户端用 CA 验证服务端证书
ltr local 8000 --to your-server.example --tls-ca ./ca.pem

# 或直接钉住指纹
ltr local 8000 --to your-server.example --tls-fingerprint <sha256>

# 服务端使用已有证书 / 要求客户端证书（mTLS）
ltr server --tls-cert ./cert.pem --tls-key ./key.pem --tls-client-ca ./ca.pem

# 明确关闭加密（例如纯内网）
ltr server --no-tls
ltr local 8000 --to your-server.example --no-tls
```

## 远程控制台与 SSH 组合模式

```sh
ltr bundle --to your-server.example --secret change-me
# → HTTPS 控制台 + SSH 隧道（ssh user@your-server.example -p 2222）

ltr bundle --to your-server.example --no-ssh
# → 仅 HTTPS 控制台
```

远程模式会在本地终止 HTTPS（自动生成自签名证书与独立 Bearer Token，只打印文件
路径不打印秘密），浏览器登录后 Token 保存在 `sessionStorage`，每个 `/api/*` 请求
都需要携带。受管理的隧道目标保持在回环地址。

## Web 控制台

- **网络拓扑信号轨**：每个运行中的隧道展示四节点数据通路，光点沿轨道流动表示
  请求/响应方向，附实时速率、连接数与累计字节数；停止的隧道拓扑收起。
- **中英双语**：跟随浏览器语言，可手动切换。
- **移动端自适应**：窄屏下拓扑转为纵向信号轨，操作下沉。
- **尊重系统设置**：`prefers-reduced-motion` 时动画降级为静态方向箭头。
- 前端零构建（Preact + htm 以 ES Module 内嵌于二进制），单文件分发。

## 环境变量

规范环境变量使用 `LTR_*`：`LTR_SECRET`、`LTR_SERVER`、`LTR_LOCAL_PORT`、
`LTR_WEB_TOKEN`、`LTR_MIN_PORT`、`LTR_MAX_PORT`、`LTR_TLS_CA`、
`LTR_TLS_FINGERPRINT`、`LTR_TLS_SERVER_NAME`、`LTR_TLS_CLIENT_CERT`、
`LTR_TLS_CLIENT_KEY`、`LTR_NO_TLS`、`LTR_LOG_LEVEL`、`LTR_LOG_JSON`。
优先级为命令行 > `LTR_*`。

诊断默认人类可读；`--log-level debug` 或 `--log-json` 输出结构化日志。日志不含
Secret 与 Token。

## 与 Bore 的关系

- **协议兼容保留**：Bore v1 客户端可以连接 LTR 服务端，LTR 客户端也可以连接
  Bore 服务端（后者会自动回退明文，无需 `--no-tls`）。
- **兼容包装已移除**（0.1.0）：`bore` 二进制、`BORE_*` 环境变量、`bore home`
  别名与 `@qinshower/bore*` npm 包不再发布。仍在使用旧包的用户请迁移到
  `ltr`——命令一一对应：`bore local` → `ltr local`，`bore server` → `ltr server`。
- 兼容性由 CI 中针对上游 [ekzhang/bore](https://github.com/ekzhang/bore) 的真实
  互操作测试保障。

## 开发

```sh
cargo build --workspace
cargo test --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
npm run npm:check
npm run npm:pack:dry-run
```

LTR 不收集遥测或分析数据。Docker 镜像不在本项目的分发范围内。

## 许可证与上游来源

LTR 使用 MIT 许可证发布。上游归属信息见 [NOTICE](NOTICE) 和
[ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md)。
