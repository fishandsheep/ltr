const DICTS = {
  zh: {
    'app.title': 'LTR 控制台',
    'app.new': '＋ 新建隧道',
    'app.refresh': '刷新',
    'app.running': '运行中隧道',
    'app.throughput': '实时吞吐',
    'app.connections': '活跃连接',
    'app.local': '本地模式',
    'app.remote': '远程模式',
    'app.remoteWarning': '远程访问公开在公网，请保管好 Bearer Token。',
    'app.loadFailed': '加载失败',
    'app.empty': '还没有隧道。点击右上角「新建隧道」创建第一个。',
    'auth.title': '解锁控制台',
    'auth.copy': '输入 LTR 启动远程模式时打印的 Bearer Token。',
    'auth.token': 'Web Token',
    'auth.unlock': '解锁',
    'auth.checking': '正在验证…',
    'auth.invalid': 'Token 无效，请重试。',
    'summary.unit': '个 / {total}',
    'summary.conn': 'conn',
    'status.running': '运行中',
    'status.stopped': '已停止',
    'status.starting': '启动中',
    'status.failed': '失败',
    'action.start': '启动',
    'action.retry': '重试',
    'action.stop': '停止',
    'action.logs': '日志',
    'action.edit': '编辑',
    'action.delete': '删除',
    'action.cancel': '取消',
    'action.save': '保存',
    'action.close': '关闭',
    'card.tls': 'TLS · TOFU',
    'card.plaintext': '明文',
    'card.connections': '连接 {n}',
    'card.total': '累计 ↓{in} ↑{out}',
    'card.retry': '重试',
    'card.persisted': '重启后保留',
    'map.title': '网络总览',
    'map.hint': '所有运行中的隧道 · 光点速度 = 实时速率',
    'map.collapse': '收起',
    'map.expand': '展开',
    'map.empty': '没有运行中的隧道',
    'map.host': '本机 · ltr',
    'map.relay': 'LTR 中继',
    'map.internet': '互联网',
    'map.tls': '🔒 TLS',
    'map.openTab': '在新标签页打开',
    'map.request': '紫色 = 请求 →',
    'map.response': '青色 = 响应 ←',
    'map.clickHint': '点节点 = 新标签页打开服务',
    'logs.empty': '暂无日志。启动隧道后这里会显示连接与转发事件。',
    'logs.latest': '最近 {n} 行',
    'logs.auto': '自动刷新中',
    'card.stoppedHint': '已就绪未运行——点「启动」连接服务器后对外生效。',
    'dialog.createTitle': '新建隧道',
    'dialog.editTitle': '编辑隧道',
    'dialog.subtitle': '字段与 CLI 同名；远程端口留空自动分配。',
    'dialog.name': '名称',
    'dialog.localPort': '本地端口',
    'dialog.to': '目标服务器',
    'dialog.remotePort': '远程端口',
    'dialog.remotePortPh': '自动分配',
    'dialog.localHost': '本地地址',
    'dialog.secret': 'Secret（可选）',
    'dialog.secretPh': '留空表示无认证',
    'dialog.createSubmit': '创建',
    'dialog.editSubmit': '保存修改',
    'dialog.required': '必填',
    'delete.title': '删除隧道',
    'delete.body': '确定删除「{name}」？此操作会移除保存的配置。',
    'delete.keep': '保留',
    'delete.confirm': '删除',
    'error.nameRequired': '名称、本地端口和目标服务器为必填项。',
    'error.requestFailed': '请求失败：{msg}',
  },
  en: {
    'app.title': 'LTR Console',
    'app.new': '＋ New tunnel',
    'app.refresh': 'Refresh',
    'app.running': 'Running tunnels',
    'app.throughput': 'Live throughput',
    'app.connections': 'Active connections',
    'app.local': 'Local',
    'app.remote': 'Remote',
    'app.remoteWarning': 'Remote access is public. Keep the bearer token private.',
    'app.loadFailed': 'Failed to load',
    'app.empty': 'No tunnels yet. Click “New tunnel” to create your first one.',
    'auth.title': 'Unlock console',
    'auth.copy': 'Enter the bearer token LTR printed when remote mode started.',
    'auth.token': 'Web Token',
    'auth.unlock': 'Unlock',
    'auth.checking': 'Checking…',
    'auth.invalid': 'Invalid token, try again.',
    'summary.unit': '/ {total}',
    'summary.conn': 'conn',
    'status.running': 'Running',
    'status.stopped': 'Stopped',
    'status.starting': 'Starting',
    'status.failed': 'Failed',
    'action.start': 'Start',
    'action.retry': 'Retry',
    'action.stop': 'Stop',
    'action.logs': 'Logs',
    'action.edit': 'Edit',
    'action.delete': 'Delete',
    'action.cancel': 'Cancel',
    'action.save': 'Save',
    'action.close': 'Close',
    'card.tls': 'TLS · TOFU',
    'card.plaintext': 'plaintext',
    'card.connections': '{n} conn',
    'card.total': 'Total ↓{in} ↑{out}',
    'card.retry': 'Retry',
    'card.persisted': 'kept across restarts',
    'map.title': 'Network overview',
    'map.hint': 'all running tunnels · dot speed = live rate',
    'map.collapse': 'Collapse',
    'map.expand': 'Expand',
    'map.empty': 'No running tunnels',
    'map.host': 'Host · ltr',
    'map.relay': 'LTR relay',
    'map.internet': 'Internet',
    'map.tls': '🔒 TLS',
    'map.openTab': 'open in a new tab',
    'map.request': 'violet = requests →',
    'map.response': 'teal = responses ←',
    'map.clickHint': 'click a node to open the service in a new tab',
    'logs.empty': 'No logs yet. Events appear here once the tunnel starts.',
    'logs.latest': 'Last {n} lines',
    'logs.auto': 'auto-refreshing',
    'card.stoppedHint': 'Ready but not running — press Start to connect to the relay.',
    'dialog.createTitle': 'New tunnel',
    'dialog.editTitle': 'Edit tunnel',
    'dialog.subtitle': 'Field names match the CLI. Leave remote port empty for auto assignment.',
    'dialog.name': 'Name',
    'dialog.localPort': 'Local port',
    'dialog.to': 'Target server',
    'dialog.remotePort': 'Remote port',
    'dialog.remotePortPh': 'auto',
    'dialog.localHost': 'Local host',
    'dialog.secret': 'Secret (optional)',
    'dialog.secretPh': 'empty means no auth',
    'dialog.createSubmit': 'Create',
    'dialog.editSubmit': 'Save changes',
    'dialog.required': 'required',
    'delete.title': 'Delete tunnel',
    'delete.body': 'Delete “{name}”? This permanently removes the saved configuration.',
    'delete.keep': 'Keep',
    'delete.confirm': 'Delete',
    'error.nameRequired': 'Name, local port, and target server are required.',
    'error.requestFailed': 'Request failed: {msg}',
  },
};

const STORAGE_KEY = 'ltr-lang';

function detect() {
  const saved = typeof localStorage !== 'undefined' && localStorage.getItem(STORAGE_KEY);
  if (saved === 'zh' || saved === 'en') return saved;
  const nav = (typeof navigator !== 'undefined' && navigator.language) || 'en';
  return nav.toLowerCase().startsWith('zh') ? 'zh' : 'en';
}

export let lang = detect();

const listeners = new Set();

export function onLangChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function setLang(next) {
  if (next !== 'zh' && next !== 'en') return;
  if (next === lang) return;
  lang = next;
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {}
  for (const fn of listeners) fn(lang);
}

/** Translate `key` with `{param}` interpolation; falls back to English. */
export function t(key, params) {
  let text = DICTS[lang][key] ?? DICTS.en[key] ?? key;
  if (params) {
    for (const [name, value] of Object.entries(params)) {
      text = text.split(`{${name}}`).join(String(value));
    }
  }
  return text;
}

/** Parity check used by the Node smoke test: every zh key exists in en. */
export function dictionaryKeys() {
  return { zh: Object.keys(DICTS.zh), en: Object.keys(DICTS.en) };
}
