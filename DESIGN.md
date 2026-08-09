---
name: LTR Web Console
description: `ltr --web` / `ltr web` 的本地 TCP 隧道控制面
colors:
  bg: "#f4f4f1"
  bg-accent: "#e8ecef"
  surface: "#ffffff"
  surface-muted: "#f7f8f8"
  surface-strong: "#f1f4f5"
  ink: "#172126"
  muted: "#556169"
  muted-strong: "#6a7881"
  line: "#ced6db"
  line-strong: "#aab6be"
  accent: "#0f5f78"
  accent-strong: "#0b4c60"
  accent-soft: "#d9e9ee"
  ok: "#11643e"
  ok-soft: "#d9ece2"
  warn: "#9a3f20"
  warn-soft: "#f2e0d8"
  danger: "#8c321d"
  danger-strong: "#712818"
  danger-line: "#d8b4a8"
  danger-line-strong: "#c99282"
  secondary-hover: "#e8edef"
  log-bg: "#111417"
  log-line: "#243039"
  log-ink: "#edf2f5"
  top-wash: "#e8ecef8c"
typography:
  display:
    fontFamily: '"SF Pro Text", "Segoe UI", system-ui, sans-serif'
    fontSize: "clamp(2rem, 4vw, 3.25rem)"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "-0.02em"
  headline:
    fontFamily: '"SF Pro Text", "Segoe UI", system-ui, sans-serif'
    fontSize: "1.125rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  body:
    fontFamily: '"SF Pro Text", "Segoe UI", system-ui, sans-serif'
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: '"SF Pro Text", "Segoe UI", system-ui, sans-serif'
    fontSize: "0.875rem"
    fontWeight: 600
    lineHeight: 1.4
  mono:
    fontFamily: '"SFMono-Regular", Consolas, monospace'
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.5
rounded:
  xs: "4px"
  sm: "12px"
  md: "14px"
  lg: "16px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "20px"
  xxl: "24px"
  xxxl: "32px"
components:
  hero-panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    padding: "28px"
  form-panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    padding: "{spacing.xxl}"
  tunnel-card:
    backgroundColor: "{colors.surface-muted}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "18px"
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
    rounded: "{rounded.pill}"
    padding: "10px 16px"
  button-secondary:
    backgroundColor: "{colors.surface-strong}"
    textColor: "{colors.ink}"
    rounded: "{rounded.pill}"
    padding: "10px 16px"
  button-danger:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.danger}"
    rounded: "{rounded.pill}"
    padding: "10px 16px"
  input-default:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: "12px 14px"
  logs-panel:
    backgroundColor: "{colors.log-bg}"
    textColor: "{colors.log-ink}"
    rounded: "{rounded.sm}"
    padding: "{spacing.lg}"
---

# Design System: LTR Web Console

## Overview

**Creative North Star: "安静的本地控制面"**

这个界面服务的是并行打开终端与浏览器的开发者，不是浏览品牌故事的访客。它应该像一块稳态控制面：信息先清楚，状态先可判，动作先可达，然后才谈气质。页面一打开，用户要立刻知道控制台监听在哪里、当前有多少 tunnel、哪些在运行，以及下一步最短动作是什么。

当前实现已经从早先偏暖纸、偏展示感的版本，收束成更克制的 product UI。整体语言转向系统无衬线、冷静浅中性底、窄色域强调与扁平化容器，用更少的视觉噪声换更强的长期使用稳定感。这套系统明确反对 `PRODUCT.md` 里提到的三类偏移：不要像营销站；不要太玻璃拟态；不要像花哨低代码面板。

**Key Characteristics:**
- 单一控制面语言，状态与动作权重清晰。
- 左表单右列表的大桌面工作流，小屏退化为单列。
- 颜色只承担语义与动作，不承担装饰性表演。
- 日志层与管理层明确分轨。
- 轮询刷新不应破坏用户焦点、滚动和上下文。

## Colors

当前配色是 restrained product palette：中性灰白表面 + 一组蓝绿色动作色 + 明确语义状态色。

### Primary
- **控制蓝** (`#0f5f78`)：主按钮、关键链接、聚焦边框和运行中间态的主导色。它表达“执行、前进、连接”。

### Secondary
- **深控制蓝** (`#0b4c60`)：主动作 hover 态和链接 hover 态。只作为同一路径的加深态出现。

### Tertiary
- **运行绿** (`#11643e`) / **运行浅底** (`#d9ece2`)：运行成功和稳定态。
- **告警棕红** (`#9a3f20`) / **告警浅底** (`#f2e0d8`)：错误、失败、无效输入和危险提示。
- **危险描边** (`#d8b4a8`, `#c99282`)：删除相关按钮边框与 hover 收紧色。

### Neutral
- **主背景灰白** (`#f4f4f1`)：页面基础画布。
- **顶层冷洗色** (`#e8ecef` / `#e8ecef8c`)：首屏顶部轻微冷色洗层，用极低强度建立层次。
- **纯白表面** (`#ffffff`)：hero、form、list panel 主表面。
- **弱表面** (`#f7f8f8`)：tunnel card 和空态底。
- **强表面** (`#f1f4f5`)：badge、secondary button、弱状态底。
- **正文墨色** (`#172126`)：主要文本。
- **辅助灰** (`#556169`, `#6a7881`)：说明、辅助文案、placeholder。
- **边界灰** (`#ced6db`, `#aab6be`)：默认与 hover/强化描边。
- **日志深底** (`#111417`) / **日志边界** (`#243039`) / **日志浅字** (`#edf2f5`)：原始进程输出层专用。

### Named Rules
**The Action-Only Accent Rule.** 蓝色只用于动作、链接、焦点与状态，不用于大块装饰。

**The Console Layer Rule.** 管理层保持明亮、平静、低阴影；原始日志层单独使用深底与等宽字。

## Typography

**Display Font:** `"SF Pro Text", "Segoe UI", system-ui, sans-serif`
**Body Font:** `"SF Pro Text", "Segoe UI", system-ui, sans-serif`
**Label/Mono Font:** `"SFMono-Regular", Consolas, monospace`

**Character:** 这是典型 product UI 字体策略：一个系统无衬线家族承担几乎所有界面阅读任务，只在日志层切到等宽字。目标不是“有性格的字体搭配”，而是“长期阅读下不出戏、不抢控制权”。

### Hierarchy
- **Display**（700, `clamp(2rem, 4vw, 3.25rem)`, 1, `-0.02em`）：只用于页面主标题。
- **Headline**（700, `1.125rem`, 1.2）：区块标题和主要面板标题。
- **Title**（700, `1rem`, 1.25）：tunnel card 名称。
- **Body**（400, `1rem`, 1.5）：正文、状态说明、字段值、路径信息。
- **Label**（600, `0.875rem`, 1.4）：表单标签、弱状态、辅助胶囊。
- **Mono**（400, `0.75rem`, 1.5）：日志输出。

### Named Rules
**The Read-At-Glance Rule.** 所有信息先为扫读服务，再为风格服务；任何字重、字距、字号调整都不能伤害快速判读。

## Elevation

当前系统使用低抬升、低阴影、强描边的 product layering。大容器只用一档柔和阴影 `0 8px 24px rgba(17, 24, 29, 0.06)`；内部 card 不再继续漂浮，而是靠表面灰度与描边分层。日志层完全放弃阴影，改用深底形成独立工作层。

### Shadow Vocabulary
- **Panel Lift** (`box-shadow: 0 8px 24px rgba(17, 24, 29, 0.06)`): 只用于 `.hero`。
- **Flat Containers** (`none`): `.panel` 与 `.tunnel-card` 默认不叠第二层装饰性阴影。
- **Focus Ring** (`0 0 0 3px rgba(15, 95, 120, 0.18)`): 这是主要交互高亮，不是阴影替代品，而是可访问焦点层。

### Named Rules
**The Flat-By-Default Rule.** 平常态尽量平，只有顶层面板和焦点态才有明显抬升感。

## Components

### Buttons
- **Shape:** 全部按钮使用胶囊圆角（`999px`），维持统一命令感。
- **Primary:** 控制蓝底白字，hover 加深到 `#0b4c60`。
- **Secondary:** 强表面底、深墨字、描边边界，用于刷新与中性动作。
- **Ghost:** 透明底描边，hover 进入浅蓝底。
- **Danger:** 透明底、危险描边与棕红字，不用大红实底，避免在日常控制台里过度吼叫。
- **Busy State:** 通过 `button-busy::after` 注入小型旋转指示器，而不是替换整按钮文本。

### Cards / Containers
- **Corner Style:** panel `16px`，card `14px`，input/logs `12px`，focus 链接细节 `4px`。
- **Background:** hero/panel 用纯白表面；card 用弱表面；logs 用深底。
- **Border:** 整体依赖 `#ced6db` 与 `#aab6be` 两级边界控制层次。
- **Layout:** 桌面使用左表单右列表双列；`920px` 以下退化为单列；`720px` 以下全面堆叠动作组。

### Inputs / Fields
- **Style:** 纯白输入框，`12px 14px` 内边距，`12px` 圆角，`44px` 最小高度。
- **Placeholder:** 使用 `#6a7881`，保证比典型浅灰 placeholder 更可读。
- **Focus:** 用控制蓝边框 + 柔和 focus ring。
- **Error:** `input:invalid:user-invalid` 切换到告警边框与浅错误 ring。

### Navigation
- **Style:** 无全局导航，页面即控制面。
- **Primary Landmarks:** hero 负责定位与总结；form panel 负责配置；list panel 负责运行态、元信息与日志。
- **Feedback:** `#form-message` 与 `#list-feedback` 都是 live region，用于异步反馈。

### Status Pills
- **Style:** 胶囊 + 小圆点前缀。
- **States:** `starting` 走控制蓝浅底；`running` 走绿色浅底；`failed` 走告警浅底。
- **Purpose:** 它们是扫读列表时的第一信号，不可弱化成仅文本颜色差异。

### Logs
- **Style:** 深底、浅字、等宽字、最大高度 `240px`、内部滚动。
- **Behavior:** 展开态由 `aria-expanded` 控制；内容更新应尽量保留滚动位置，不抢用户阅读上下文。

## Do's and Don'ts

### Do:
- **Do** 保持控制台像产品工具，不像品牌展示页。
- **Do** 让轮询更新保持 DOM 稳定，保住焦点、滚动和展开状态。
- **Do** 让长 tunnel 名、长时间串、长地址都能断行，不把窄屏挤坏。
- **Do** 使用统一 token 层，不要让实现先跑、文档滞后。
- **Do** 让按钮和输入在触屏上下都满足 44px 级可点区域。

### Don't:
- **Don't** 像营销站：避免夸张 hero 结构、宣传式文案、过度品牌叙事和视觉噱头。
- **Don't** 太玻璃拟态：避免依赖模糊、悬浮半透明层和装饰性光效来制造“高级感”。
- **Don't** 像花哨低代码面板：避免过多彩色模块、过度圆角、冗余状态徽章、视觉密度失控和不必要的组件花样。
- **Don't** 重新引入全量 `innerHTML` 轮询重绘。
- **Don't** 把错误态做成只有颜色区别；必须同时保留文本和状态文案。
