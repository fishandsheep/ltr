# @qinshower/ltr

通过 npm 或 Bun 执行 LTR 预编译二进制；支持 Node.js LTS 与 Bun 1.x。

## 安装

使用 npm 全局安装：

```sh
npm install -g @qinshower/ltr@0.0.1
```

使用 Bun 全局安装：

```sh
bun add --global @qinshower/ltr@0.0.1
```

也可以直接使用 npx 或 bunx，无需全局安装：

```sh
npx @qinshower/ltr local 8000 --to your-server.example
bunx @qinshower/ltr local 8000 --to your-server.example
```

可通过 npm semver 指定版本。

```sh
npx @qinshower/ltr@0.0.1 --help
bunx @qinshower/ltr@0.0.1 --help
```

`npx` 可能会先消费 `-w` 这类前导参数。启动 Web 管理台请使用：

```sh
npx @qinshower/ltr web
npx @qinshower/ltr -- -w
```

远端公开 Web 管理台：

```sh
npx @qinshower/ltr web --remote --to your-server.com --port 7836 --secret xxx
```

`home` 组合模式：

```sh
npx @qinshower/ltr bundle --to your-server.com --secret xxx
```

远程 Web 模式会生成并持久化 HTTPS 证书与 Bearer token；启动时会打印 token。浏览器登录后 token 只保存在 session storage，不会放入 URL。

更多用法见主仓库文档：https://github.com/fishandsheep/ltr
