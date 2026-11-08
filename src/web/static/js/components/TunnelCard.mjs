import { html } from '../lib.mjs';
import { t } from '../i18n.mjs';
import { formatBytes } from '../lib.mjs';

const SIG = {
  running: '▲',
  stopped: '■',
  starting: '◐',
  failed: '✕',
};

export function TunnelCard({
  tunnel,
  logsOpen,
  logs,
  logsBusy,
  onStart,
  onStop,
  onEdit,
  onDelete,
  onToggleLogs,
}) {
  const status = tunnel.status;
  const stats = tunnel.stats || { active_connections: 0, bytes_in: 0, bytes_out: 0 };

  return html`
    <article class="card status-${status}">
      <div class="row">
        <span class="sig sig-${status}">${SIG[status] || '■'}</span>
        <div class="idblock">
          <span class="nm">${tunnel.config.name}</span>
          <span class="path">
            ${tunnel.config.local_host}:${tunnel.config.local_port}
            →
            ${tunnel.config.to}${tunnel.remote_port ? `:${tunnel.remote_port}` : ''}
          </span>
        </div>
        <span class="stpill stp-${status}">${t(`status.${status}`)}</span>
        <div class="acts">
          ${status === 'stopped' || status === 'failed'
            ? html`<button class="btn btn-ink mini"
                onClick=${onStart}>${status === 'failed' ? t('action.retry') : t('action.start')}</button>`
            : ''}
          ${status === 'running' || status === 'starting'
            ? html`<button class="btn btn-plain mini" onClick=${onStop}>${t('action.stop')}</button>`
            : ''}
          <button class="btn btn-plain mini" onClick=${onToggleLogs}>
            ${t('action.logs')}${logsOpen ? ' ▴' : ' ▾'}
          </button>
          ${!tunnel.locked
            ? html`
                <button class="btn btn-plain mini" onClick=${onEdit}>${t('action.edit')}</button>
                <button class="btn btn-warn mini" onClick=${onDelete}>${t('action.delete')}</button>
              `
            : ''}
        </div>
      </div>

      ${tunnel.error
        ? html`<div class="err">${tunnel.error}</div>`
        : ''}
      ${status === 'stopped'
        ? html`<div class="hint">${t('card.stoppedHint')}</div>`
        : ''}

      <div class="meta">
        <span>${t('card.connections', { n: stats.active_connections })}</span>
        <span>${t('card.total', {
          in: formatBytes(stats.bytes_in),
          out: formatBytes(stats.bytes_out),
        })}</span>
        ${tunnel.has_secret ? html`<span>🔒 secret</span>` : ''}
        <span>${t('card.persisted')}</span>
      </div>

      ${logsOpen
        ? html`
            <div class="logs" role="log">
              ${logsBusy
                ? html`<div class="logs-line dim">…</div>`
                : logs && logs.length
                  ? logs.map((line) => html`<div class="logs-line">${line}</div>`)
                  : html`<div class="logs-line dim">${t('logs.empty')}</div>`}
            </div>
          `
        : ''}
    </article>
  `;
}
