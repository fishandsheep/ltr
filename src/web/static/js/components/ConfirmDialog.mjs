import { html } from '../lib.mjs';
import { t } from '../i18n.mjs';

export function ConfirmDialog({ name, onConfirm, onClose }) {
  return html`
    <div class="overlay" onClick=${onClose}>
      <div class="dialog dialog-sm" onClick=${(e) => e.stopPropagation()} role="alertdialog"
        aria-label=${t('delete.title')}>
        <div class="dialog-title">${t('delete.title')}</div>
        <p class="dialog-sub">${t('delete.body', { name })}</p>
        <div class="dialog-actions">
          <button class="btn btn-plain" onClick=${onClose}>${t('delete.keep')}</button>
          <button class="btn btn-danger" onClick=${onConfirm}>${t('delete.confirm')}</button>
        </div>
      </div>
    </div>
  `;
}
