import { html } from '../lib.mjs';
import { t } from '../i18n.mjs';

/**
 * Merged network overview: one map for every running tunnel.
 * local services (left column) → host ltr node → relay rack → internet
 * cloud → public port chips (right column).
 *
 * Style: minimal geometric icons (2px ink stroke, white fill), isometric
 * diamond grid backdrop, orthogonal elbow links only (no diagonals):
 * violet = requests →, teal = responses ←, arrow markers, traveling pulse
 * dots whose speed follows the live rate.
 */

const INK = 'var(--ink)';
const LANE_H = 58; // vertical distance between service rows
const MAX_ROWS = 6; // extra tunnels collapse into "+n"
const X = {
  svcRight: 152, // right edge of service nodes
  trunk: 236, // vertical merge line
  host: 318, // host ltr node center
  hostRight: 372,
  relay: 452, // relay rack center
  relayRight: 508,
  cloud: 614, // cloud center
  cloudRight: 678,
  chip: 742, // visitor chip left edge
};
const TOP = 96;

/** Map a live rate (bytes/s) to a dot travel duration (seconds). */
function dotDuration(rateBytes) {
  if (!rateBytes || rateBytes <= 0) return 4.2;
  if (rateBytes > 1_000_000) return 1.2;
  if (rateBytes > 100_000) return 1.8;
  if (rateBytes > 10_000) return 2.6;
  return 3.4;
}

const elbow = (points) =>
  points.map(([x, y], i) => `${i === 0 ? 'M' : 'L'} ${x} ${y}`).join(' ');

export function NetworkMap({ tunnels, rates, open, onToggle }) {
  const running = tunnels.filter(
    (tn) => tn.status === 'running' || tn.status === 'starting'
  );
  const shown = running.slice(0, MAX_ROWS);
  const extra = running.length - shown.length;
  const n = Math.max(shown.length, 1);
  const centerY = TOP + ((Math.max(shown.length, 1) - 1) * LANE_H) / 2;
  const height = TOP + shown.length * LANE_H + 58;
  const reqY = centerY - 10;
  const resY = centerY + 12;

  const rowY = (i) => TOP + i * LANE_H;
  const rateOf = (id) => rates[id] || { in: 0, out: 0 };

  const totalIn = running.reduce(
    (sum, tn) => sum + (rateOf(tn.id).in || 0),
    0
  );
  const totalOut = running.reduce(
    (sum, tn) => sum + (rateOf(tn.id).out || 0),
    0
  );

  return html`
    <section class="map-panel">
      <header class="map-head">
        <b>${t('map.title')}</b>
        <span class="map-hint">${running.length ? t('map.hint') : ''}</span>
        <button class="btn btn-plain mini" onClick=${onToggle}
          aria-expanded=${open ? 'true' : 'false'}>
          ${t(open ? 'map.collapse' : 'map.expand')}${open ? ' ▴' : ' ▾'}
        </button>
      </header>

      ${open && running.length === 0
        ? html`<div class="map-empty">${t('map.empty')}</div>`
        : ''}
      ${open && running.length > 0
        ? html`
            <div class="map-scroll">
              <svg
                viewBox="0 0 880 ${height}"
                fill="none"
                role="img"
                aria-label=${t('map.title')}
              >
                <defs>
                  <pattern id="map-grid" width="52" height="30" patternUnits="userSpaceOnUse">
                    <path d="M0,0 L52,30 M52,0 L0,30" stroke="var(--line)" stroke-width="1" />
                  </pattern>
                  <radialGradient id="map-vignette" gradientUnits="userSpaceOnUse" cx="440" cy="${height / 2}" r="${Math.max(430, height)}">
                    <stop offset="0" stop-color="var(--panel)" stop-opacity="0" />
                    <stop offset="0.66" stop-color="var(--panel)" stop-opacity="0.38" />
                    <stop offset="1" stop-color="var(--panel)" stop-opacity="1" />
                  </radialGradient>
                  <marker id="map-av" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="5.4" markerHeight="5.4" orient="auto-start-reverse">
                    <path d="M0,.6 L10,5 L0,9.4 Z" fill="var(--acc)" />
                  </marker>
                  <marker id="map-at" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="5.4" markerHeight="5.4" orient="auto-start-reverse">
                    <path d="M0,.6 L10,5 L0,9.4 Z" fill="var(--teal)" />
                  </marker>
                </defs>

                <rect width="880" height="${height}" fill="url(#map-grid)" />
                <rect width="880" height="${height}" fill="url(#map-vignette)" />

                <!-- ══ 服务 → 汇聚线（请求）与汇聚线 → 服务（响应） ══ -->
                <g stroke-width="2">
                  ${shown.map(
                    (tn, i) => html`
                      <path
                        key=${`rq-${tn.id}`}
                        d=${elbow([
                          [X.svcRight, rowY(i)],
                          [X.trunk, rowY(i)],
                          [X.trunk, reqY],
                          [X.hostRight - 78, reqY],
                        ])}
                        stroke="var(--acc)"
                        marker-end="url(#map-av)"
                      />
                    `
                  )}
                </g>

                <!-- ══ 本机 → 中继 → 云（请求主干）══ -->
                <g stroke-width="2.4">
                  <path id="map-trunk-req" d=${elbow([[X.hostRight, reqY], [X.cloud - 44, reqY]])} stroke="var(--acc)" marker-end="url(#map-av)" />
                  <path id="map-trunk-res" d=${elbow([[X.cloud - 44, resY], [X.hostRight, resY]])} stroke="var(--teal)" marker-end="url(#map-at)" />
                </g>

                <!-- ══ 云 → 公网端口（每隧道一条肘形扇出）══ -->
                <g stroke-width="2">
                  ${shown.map((tn, i) => {
                    if (!tn.remote_port) return null;
                    return html`
                      <path
                        key=${`fan-${tn.id}`}
                        d=${elbow([
                          [X.cloudRight, centerY],
                          [X.chip - 42, centerY],
                          [X.chip - 42, rowY(i)],
                          [X.chip - 6, rowY(i)],
                        ])}
                        stroke="var(--acc)"
                        marker-end="url(#map-av)"
                      />
                    `;
                  })}
                </g>

                <!-- ══ 光点（速度=速率）══ -->
                <g>
                  ${shown.map((tn, i) => {
                    const dur = dotDuration(rateOf(tn.id).in);
                    return html`
                      <circle key=${`dot-${tn.id}`} r="4.2" fill="var(--acc)">
                        <animateMotion dur=${`${dur}s`} repeatCount="indefinite" path=${elbow([
                          [X.svcRight, rowY(i)],
                          [X.trunk, rowY(i)],
                          [X.trunk, reqY],
                          [X.hostRight - 78, reqY],
                        ])} />
                      </circle>
                    `;
                  })}
                  <circle r="4.6" fill="var(--acc)">
                    <animateMotion dur=${`${dotDuration(totalIn)}s`} repeatCount="indefinite" path=${elbow([[X.hostRight, reqY], [X.cloud - 44, reqY]])} />
                  </circle>
                  <circle r="4.2" fill="var(--teal)">
                    <animateMotion dur=${`${dotDuration(totalOut)}s`} repeatCount="indefinite" path=${elbow([[X.cloud - 44, resY], [X.hostRight, resY]])} />
                  </circle>
                </g>

                <!-- ══ 本地服务节点 ══ -->
                ${shown.map((tn, i) => {
                  const y = rowY(i);
                  const href = `http://${tn.config.local_host}:${tn.config.local_port}`;
                  return html`
                    <g key=${`svc-${tn.id}`} class="map-node">
                      <a href=${href} target="_blank" rel="noopener noreferrer">
                        <g transform=${`translate(52, ${y - 20})`} stroke=${INK} stroke-width="2" stroke-linejoin="round" stroke-linecap="round">
                          <rect width="44" height="40" rx="7" fill="var(--panel)" />
                          <path d="M12 14h20" opacity="0.35" />
                          <path d="M12 26h20" opacity="0.35" />
                        </g>
                      </a>
                      <circle cx="86" cy="${y - 12}" r="2.8" fill="var(--ok)" class="map-led" />
                      <text x="52" y="${y + 38}" font-size="11" font-weight="700" fill=${INK}>${tn.config.name}</text>
                      <text x="52" y="${y + 51}" class="mono" font-size="9" fill="var(--muted)">:${tn.config.local_port}</text>
                    </g>
                  `;
                })}
                ${extra > 0
                  ? html`<text x="52" y="${TOP + shown.length * LANE_H + 8}" font-size="10.5" fill="var(--faint)">+${extra}</text>`
                  : ''}

                <!-- ══ 本机 ltr（极简笔记本）══ -->
                <g class="map-node">
                  <g transform=${`translate(${X.host - 54}, ${centerY - 46})`} stroke=${INK} stroke-width="2" stroke-linejoin="round" stroke-linecap="round">
                    <rect x="18" y="0" width="72" height="44" rx="7" fill="var(--panel)" />
                    <path d="M6 52 L54 61 L102 52 L96 48 L54 57 L12 48 Z" fill="var(--panel)" />
                  </g>
                  <circle cx="${X.host - 18}" cy="${centerY - 34}" r="2.8" fill="var(--ok)" class="map-led" />
                  <text x=${X.host} y="${centerY + 74}" text-anchor="middle" font-size="11.5" font-weight="800" fill=${INK}>${t('map.host')}</text>
                  <text x=${X.host} y="${centerY + 87}" text-anchor="middle" class="mono" font-size="9" fill="var(--muted)">${t('map.tls')}</text>
                </g>

                <!-- ══ 中继（极简机架）══ -->
                <g class="map-node">
                  <g transform=${`translate(${X.relay - 28}, ${centerY - 38})`} stroke=${INK} stroke-width="2" stroke-linejoin="round" stroke-linecap="round">
                    <rect width="56" height="76" rx="9" fill="var(--panel)" />
                    <path d="M14 26h28" opacity="0.35" />
                    <path d="M14 50h28" opacity="0.35" />
                  </g>
                  <circle cx="${X.relay + 18}" cy="${centerY - 24}" r="2.8" fill="var(--ok)" class="map-led" />
                  <text x=${X.relay} y="${centerY + 74}" text-anchor="middle" font-size="11.5" font-weight="800" fill=${INK}>${t('map.relay')}</text>
                  <text x=${X.relay} y="${centerY + 87}" text-anchor="middle" class="mono" font-size="9" fill="var(--muted)">${shown[0] ? shown[0].config.to : ''}</text>
                </g>

                <!-- ══ 互联网云 ══ -->
                <g class="map-node">
                  <g transform=${`translate(${X.cloud - 34}, ${centerY - 26})`} stroke=${INK} stroke-width="2" stroke-linejoin="round" stroke-linecap="round">
                    <path d="M14 40 a15 15 0 0 1 -2 -29 a19 19 0 0 1 36 -3 a14 14 0 0 1 12 14 a11 11 0 0 1 -6 18 z" fill="var(--panel)" />
                  </g>
                  <text x=${X.cloud} y="${centerY + 44}" text-anchor="middle" font-size="11.5" font-weight="800" fill=${INK}>${t('map.internet')}</text>
                </g>

                <!-- ══ 公网端口徽章（可点击）══ -->
                ${shown.map((tn, i) => {
                  if (!tn.remote_port) return null;
                  const y = rowY(i);
                  const href = `http://${tn.config.to}:${tn.remote_port}`;
                  const conns = tn.stats ? tn.stats.active_connections : 0;
                  const label = `:${tn.remote_port} ×${conns}`;
                  return html`
                    <a key=${`chip-${tn.id}`} class="map-chip" href=${href} target="_blank" rel="noopener noreferrer" title=${t('map.openTab')}>
                      <rect x=${X.chip} y=${y - 13} width="106" height="26" rx="13" fill="var(--panel)" stroke="var(--line-strong)" />
                      <text x=${X.chip + 53} y=${y + 4} text-anchor="middle" class="mono" font-size="10" font-weight="700" fill=${INK}>${label}</text>
                    </a>
                  `;
                })}

                <!-- 速率标注 -->
                <text x="${X.hostRight + 8}" y="${reqY - 8}" class="mono" font-size="9.5" fill="var(--acc-deep)">↓ ${fmtRate(totalIn)}</text>
                <text x="${X.hostRight + 8}" y="${resY + 16}" class="mono" font-size="9.5" fill="var(--teal)">↑ ${fmtRate(totalOut)}</text>
              </svg>
            </div>
            <div class="map-legend">
              <span><i style="background:var(--acc)"></i>${t('map.request')}</span>
              <span><i style="background:var(--teal)"></i>${t('map.response')}</span>
              <span>${t('map.clickHint')}</span>
            </div>
          `
        : ''}
    </section>
  `;
}

function fmtRate(bytesPerSec) {
  if (!bytesPerSec || bytesPerSec <= 0) return '0 B/s';
  if (bytesPerSec > 1_048_576) return `${(bytesPerSec / 1_048_576).toFixed(1)} MB/s`;
  if (bytesPerSec > 1024) return `${(bytesPerSec / 1024).toFixed(0)} KB/s`;
  return `${bytesPerSec.toFixed(0)} B/s`;
}
