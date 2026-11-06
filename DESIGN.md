---
name: LTR Web Console
description: `ltr` 控制台的「极简信号」设计系统
colors:
  bg: "#fafafa"
  ink: "#0c0c0e"
  panel: "#ffffff"
  line: "#e6e6e9"
  line-strong: "#c8c8cf"
  muted: "#6f6f78"
  faint: "#a5a5ad"
  accent: "#5b3df5"
  accent-deep: "#4328d4"
  accent-soft: "#efecfe"
  ok: "#0c7a43"
  ok-soft: "#e7f4ed"
  warn: "#c23b12"
  warn-soft: "#fbebe4"
  log-bg: "#111417"
  log-ink: "#edf2f5"
typography:
  display:
    fontFamily: '"Inter", "SF Pro Text", "Noto Sans SC", system-ui, sans-serif'
    fontSize: "30px"
    fontWeight: 800
    letterSpacing: "-0.03em"
    lineHeight: 1
  headline:
    fontFamily: '"Inter", "SF Pro Text", "Noto Sans SC", system-ui, sans-serif'
    fontSize: "15px"
    fontWeight: 800
    letterSpacing: "-0.01em"
  body:
    fontFamily: '"Inter", "SF Pro Text", "Noto Sans SC", system-ui, sans-serif'
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: '"Inter", "SF Pro Text", "Noto Sans SC", system-ui, sans-serif'
    fontSize: "12px"
    fontWeight: 600
  mono:
    fontFamily: '"SFMono-Regular", "JetBrains Mono", Consolas, monospace'
    fontSize: "11.5px"
    fontWeight: 400
    lineHeight: 1.7
rounded:
  sm: "8px"
  md: "10px"
  lg: "14px"
  xl: "16px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "22px"
components:
  bignum: 大号 tabular-nums 数字指标（运行数/吞吐/连接数），状态语义着色
  tunnel-card: 白底卡片 + 状态图标(▲■◐✕) + 单行路径 + 状态 pill + 行内操作组
  signal-rail: 水平信号轨拓扑；活跃链路紫色渐变 + 双向发光包流动
  dialog: 居中浮层对话框（创建/编辑/删除确认），field-grid 两列表单
  logs-panel: 深色日志面板，等宽字体，2s 自动刷新
  lang-toggle: 顶栏 中/EN 胶囊切换
---

# Design System: LTR Web Console · 极简信号

## Creative North Star: "极简信号"

服务与终端并行的开发者，需要一眼判断隧道是否在工作、数据往哪流。这套界面像一块
信号面板：黑白高对比的底，一个电光紫强调色，大号数字指标置顶；数据通路是一条
信号轨，光点沿轨道流动就是流量本身——状态先于装饰，流动即信息。

反方向（沿用 PRODUCT.md 反参考）：不做营销站，不做玻璃拟态，不做花哨低代码面板；
此外新增一条：**不用颜色堆砌科技感**——科技感来自大数字、等宽字体、克制的发光
与信号隐喻，而非渐变彩虹。

## Key Characteristics

- 黑白高对比（`#fafafa` / `#0c0c0e`）+ 单一电光紫 `#5b3df5`（深态 `#4328d4`）。
- 语义色只三种：运行绿 `#0c7a43`、失败橘红 `#c23b12`、强调紫；各自带浅底。
- 大号 tabular-nums 数字：页面打开先看到 运行数 / 实时吞吐 / 活跃连接。
- 信号轨拓扑是核心组件：`本地服务 → ltr 客户端 → 中继 → 公网访客`，紫包入站、
  绿包出站，链路空闲则灰线；流量驱动视觉，而非静态示意图。
- 等宽字体承载一切"机器值"（地址、端口、字节、日志）。
- 移动端（<640px）：卡片纵排、拓扑转纵向泳道（包下落）、新建按钮悬浮右下角。
- `prefers-reduced-motion`：隐藏流动动画，用静态 →/← 箭头表达方向。

## Color Usage Rules

- 紫色只用于：强调数字、活跃链路、入站方向包、客户端节点描边、聚焦态。
- 绿色只用于：运行状态、出站方向包。
- 橘红只用于：失败状态与错误文案、删除按钮文字。
- 中性灰阶承担其余一切；不引入第四种彩色。

## Layout

- 单列 `max-width: 880px` 居中：顶栏 → （远程横幅）→ 大数字摘要 → 隧道卡片列表。
- 创建/编辑/删除都是浮层对话框；列表永远是页面主体。
- 卡片内层级：状态图标+名称+路径+操作 → 拓扑（仅运行/启动中）→ meta 行 → 日志。

## i18n

- 全部文案经 `t(key)` 走字典（74 键 × 中/英），跟随浏览器语言，可手动切换并记忆。
- 等宽"机器值"不翻译；句式以中文书写为基准，英文为回退源。

## Accessibility

- 文本对比度：ink/bg > 15:1，muted/bg > 4.6:1。
- 状态不只靠颜色：图标字形（▲■◐✕）+ 文字标签双通道。
- 拓扑 role="img" + aria-label 描述；日志 role="log"；错误 role="alert"。
- 所有操作可键盘完成；对话框遮罩点击关闭；reduced-motion 全局降级。
