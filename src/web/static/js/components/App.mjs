import { html } from '../lib.mjs';
import { t, lang, setLang, onLangChange } from '../i18n.mjs';
import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from '../vendor/hooks.mjs';
import { api, ApiError, setToken } from '../api.mjs';
import { formatRate } from '../lib.mjs';
import { AuthPanel } from './AuthPanel.mjs';
import { TunnelCard } from './TunnelCard.mjs';
import { NetworkMap } from './NetworkMap.mjs';
import { TunnelDialog } from './TunnelDialog.mjs';
import { ConfirmDialog } from './ConfirmDialog.mjs';

const POLL_MS = 2000;

export default function App() {
  const [currentLang, setCurrentLang] = useState(lang);
  const [session, setSession] = useState(null);
  const [tunnels, setTunnels] = useState([]);
  const [authed, setAuthed] = useState(null); // null=checking, false=locked, true=ok
  const [editing, setEditing] = useState(null); // tunnel object | 'new'
  const [deleting, setDeleting] = useState(null);
  const [logsOpen, setLogsOpen] = useState({});
  const [logsCache, setLogsCache] = useState({});
  const [loadError, setLoadError] = useState('');
  const [rates, setRates] = useState({});
  const [mapOpen, setMapOpen] = useState(
    () => localStorage.getItem('ltr-map-open') !== '0'
  );
  const ratesRef = useRef({});

  useEffect(() => onLangChange(setCurrentLang), []);

  const poll = useCallback(async () => {
    try {
      const [nextSession, nextTunnels] = await Promise.all([api.session(), api.listTunnels()]);
      const now = Date.now();
      const prev = ratesRef.current;
      const nextRates = {};
      for (const tunnel of nextTunnels) {
        const stats = tunnel.stats || { bytes_in: 0, bytes_out: 0 };
        const before = prev[tunnel.id];
        if (before && now > before.ts) {
          const dt = (now - before.ts) / 1000;
          nextRates[tunnel.id] = {
            in: Math.max(0, (stats.bytes_in - before.bytes_in) / dt),
            out: Math.max(0, (stats.bytes_out - before.bytes_out) / dt),
          };
        } else {
          nextRates[tunnel.id] = { in: 0, out: 0 };
        }
        ratesRef.current[tunnel.id] = { ts: now, bytes_in: stats.bytes_in, bytes_out: stats.bytes_out };
      }
      for (const id of Object.keys(ratesRef.current)) {
        if (!nextTunnels.some((item) => item.id === id)) delete ratesRef.current[id];
      }
      setRates(nextRates);
      setSession(nextSession);
      setTunnels(nextTunnels);
      setAuthed(true);
      setLoadError('');
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setAuthed(false);
      } else {
        setLoadError(err.message);
      }
    }
  }, []);

  useEffect(() => {
    if (authed === false) return undefined;
    poll();
    const timer = setInterval(poll, POLL_MS);
    return () => clearInterval(timer);
  }, [poll, authed]);

  const refreshLogs = useCallback(async (id) => {
    try {
      const logs = await api.tunnelLogs(id);
      setLogsCache((prev) => ({ ...prev, [id]: logs }));
    } catch {
      /* next poll retries */
    }
  }, []);

  useEffect(() => {
    const open = Object.keys(logsOpen).filter((id) => logsOpen[id]);
    if (open.length === 0) return undefined;
    const timer = setInterval(() => {
      for (const id of open) refreshLogs(id);
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [logsOpen, refreshLogs]);

  const unlock = async (token) => {
    setToken(token);
    await api.session();
    setAuthed(true);
    await poll();
  };

  const act = useCallback(
    async (fn) => {
      try {
        await fn();
        await poll();
      } catch (err) {
        setLoadError(err.message);
      }
    },
    [poll],
  );

  const submitDialog = async (payload) => {
    if (editing === 'new') await api.createTunnel(payload);
    else await api.updateTunnel(editing.id, payload);
    setEditing(null);
    await poll();
  };

  const ratesNow = rates;
  const running = tunnels.filter((item) => item.status === 'running' || item.status === 'starting');
  let totalRate = 0;
  for (const item of running) {
    const r = ratesNow[item.id];
    if (r) totalRate += r.in + r.out;
  }
  const activeConns = running.reduce(
    (sum, item) => sum + (item.stats ? item.stats.active_connections : 0),
    0,
  );

  if (authed === null) {
    return html`<div class="boot"></div>`;
  }
  if (authed === false) {
    return html`<${AuthPanel} onUnlock=${unlock} />`;
  }

  const remote = session && session.mode !== 'Local';

  return html`
    <div class="stack">
      <header class="topbar">
        <span class="logo">ltr<em>.</em></span>
        <span class="addr">${location.host}</span>
        <span class="sp"></span>
        <span class="badge ${remote ? 'badge-remote' : ''}">
          ${remote ? t('app.remote') : t('app.local')}
        </span>
        <div class="lang">
          <button class=${currentLang === 'zh' ? 'on' : ''} onClick=${() => setLang('zh')}>中</button>
          <button class=${currentLang === 'en' ? 'on' : ''} onClick=${() => setLang('en')}>EN</button>
        </div>
      </header>

      ${remote
        ? html`
            <div class="remote-banner">
              <div>
                ${session.web_remote_url
                  ? html`<a class="lnk" href=${session.web_remote_url} rel="noopener"
                      target="_blank">${session.web_remote_url}</a>`
                  : ''}
                ${session.ssh_remote_endpoint
                  ? html`<span class="lnk mono">${session.ssh_remote_endpoint}</span>`
                  : ''}
                <div class="warn-note">${t('app.remoteWarning')}</div>
              </div>
            </div>
          `
        : ''}

      <div class="summary">
        <div class="bignum">
          <span class="n ok">${running.length}<small>/ ${tunnels.length}</small></span>
          <span class="l">${t('app.running')}</span>
        </div>
        <div class="bignum">
          <span class="n acc">${formatRate(totalRate)}</span>
          <span class="l">${t('app.throughput')}</span>
        </div>
        <div class="bignum">
          <span class="n">${activeConns}</span>
          <span class="l">${t('app.connections')}</span>
        </div>
        <span class="sp"></span>
        <button class="btn btn-ink" onClick=${() => setEditing('new')}>${t('app.new')}</button>
      </div>

      ${loadError ? html`<div class="load-error" role="alert">${t('app.loadFailed')}：${loadError}</div>` : ''}

      <${NetworkMap}
        tunnels=${tunnels}
        rates=${rates}
        open=${mapOpen}
        onToggle=${() => {
          setMapOpen((prev) => {
            localStorage.setItem('ltr-map-open', prev ? '0' : '1');
            return !prev;
          });
        }}
      />

      <div class="tunnel-list">
        ${tunnels.length === 0
          ? html`<div class="empty">${t('app.empty')}</div>`
          : tunnels.map(
              (item) => html`
                <${TunnelCard}
                  key=${item.id}
                  tunnel=${item}
                  logsOpen=${!!logsOpen[item.id]}
                  logs=${logsCache[item.id]}
                  logsBusy=${logsOpen[item.id] && !logsCache[item.id]}
                  onStart=${() => act(() => api.startTunnel(item.id))}
                  onStop=${() => act(() => api.stopTunnel(item.id))}
                  onEdit=${() => setEditing(item)}
                  onDelete=${() => setDeleting(item)}
                  onToggleLogs=${() => {
                    const next = !logsOpen[item.id];
                    setLogsOpen((prev) => ({ ...prev, [item.id]: next }));
                    if (next) {
                      setLogsCache((prev) => ({ ...prev, [item.id]: undefined }));
                      refreshLogs(item.id);
                    }
                  }}
                />
              `,
            )}
      </div>

      ${editing
        ? html`<${TunnelDialog}
            editing=${editing === 'new' ? null : editing}
            onSubmit=${submitDialog}
            onClose=${() => setEditing(null)}
          />`
        : ''}
      ${deleting
        ? html`<${ConfirmDialog}
            name=${deleting.config.name}
            onClose=${() => setDeleting(null)}
            onConfirm=${async () => {
              const target = deleting;
              setDeleting(null);
              await act(() => api.deleteTunnel(target.id));
            }}
          />`
        : ''}
    </div>
  `;
}
