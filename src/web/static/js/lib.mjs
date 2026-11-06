import { h } from './vendor/preact.mjs';
import htm from './vendor/htm.mjs';

/** JSX-equivalent tagged template, zero build step. */
export const html = htm.bind(h);

/** Format a byte count for compact display. */
export function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/** Format a byte-per-second rate. */
export function formatRate(bytesPerSec) {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) return '0 KB/s';
  if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)} B/s`;
  return `${(bytesPerSec / 1024).toFixed(bytesPerSec < 1024 * 10 ? 1 : 0)} KB/s`;
}
