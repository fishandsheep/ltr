import { html } from '../lib.mjs';
import { t } from '../i18n.mjs';
import { formatRate } from '../lib.mjs';

/**
 * Signal-rail topology: local service → ltr client → relay → visitors.
 * Packets animate while traffic flows; `prefers-reduced-motion` swaps the
 * animation for static arrows (CSS). Vertical layout below 640px (CSS).
 */
export function Topology({ tunnel, rateIn, rateOut }) {
  const stats = tunnel.stats || { active_connections: 0, bytes_in: 0, bytes_out: 0 };
  const live = rateIn > 0 || rateOut > 0;
  const remoteEndpoint = tunnel.remote_port
    ? `${tunnel.config.to}:${tunnel.remote_port}`
    : t('topo.assigning');

  return html`
    <div class="topo" data-live=${live ? 'on' : 'off'} role="img"
      aria-label=${t('topo.title')}>
      <span class="topo-title">${t('topo.title')}</span>

      <div class="topo-rail">
        <div class="topo-node">
          <span class="topo-box">${tunnel.config.local_host}:${tunnel.config.local_port}</span>
          <span class="topo-cap">${t('topo.local')}</span>
        </div>
        <div class="topo-seg">
          <span class="topo-line ${live ? 'live' : ''}"></span>
          <span class="topo-seg-meta">
            <span>${t('topo.request')}</span>
            <span>${t('topo.response')}</span>
          </span>
        </div>
        <div class="topo-node">
          <span class="topo-box topo-box-client">ltr</span>
          <span class="topo-cap">${t('topo.client')} · ${t('card.tls')}</span>
        </div>
        <div class="topo-seg">
          <span class="topo-line ${live ? 'live' : ''}"><span class="packet p1"></span></span>
          <span class="topo-seg-meta">
            <span>${t('topo.in', { rate: formatRate(rateIn) })}</span>
            <span>${t('topo.out', { rate: formatRate(rateOut) })}</span>
          </span>
        </div>
        <div class="topo-node">
          <span class="topo-box">${remoteEndpoint}</span>
          <span class="topo-cap">${t('topo.relay')}</span>
        </div>
        <div class="topo-seg">
          <span class="topo-line ${live ? 'live' : ''}"><span class="packet p2"></span></span>
          <span class="topo-seg-meta">
            <span>${t('card.connections', { n: stats.active_connections })}</span>
            <span>${t('topo.idle')}</span>
          </span>
        </div>
        <div class="topo-node topo-node-end">
          <span class="topo-box topo-box-port">${t('topo.visitor')}
            ${stats.active_connections > 0
              ? t('topo.visitors', { n: stats.active_connections })
              : ''}</span>
        </div>
      </div>
    </div>
  `;
}
