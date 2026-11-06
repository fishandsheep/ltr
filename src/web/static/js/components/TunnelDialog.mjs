import { html } from '../lib.mjs';
import { t } from '../i18n.mjs';
import { useState } from '../vendor/hooks.mjs';
import { formToPayload } from '../api.mjs';

const EMPTY = {
  name: '',
  local_port: '',
  to: '',
  port: '',
  local_host: '127.0.0.1',
  secret: '',
};

export function TunnelDialog({ editing, onSubmit, onClose }) {
  const [form, setForm] = useState(() =>
    editing
      ? {
          name: editing.config.name,
          local_port: String(editing.config.local_port),
          to: editing.config.to,
          port: editing.config.port ? String(editing.config.port) : '',
          local_host: editing.config.local_host,
          secret: '',
        }
      : { ...EMPTY },
  );
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const set = (field) => (event) => {
    const value = event.target.value;
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const submit = async (event) => {
    event.preventDefault();
    if (busy) return;
    if (!form.name.trim() || !form.local_port || !form.to.trim()) {
      setError(t('error.nameRequired'));
      return;
    }
    setBusy(true);
    setError('');
    try {
      await onSubmit(formToPayload(form), form.secret ? form.secret : undefined);
    } catch (err) {
      setError(t('error.requestFailed', { msg: err.message }));
      setBusy(false);
    }
  };

  return html`
    <div class="overlay" onClick=${onClose}>
      <form class="dialog" onClick=${(e) => e.stopPropagation()} onSubmit=${submit} novalidate>
        <div class="dialog-title">
          ${editing ? t('dialog.editTitle') : t('dialog.createTitle')}
        </div>
        <div class="dialog-sub">${t('dialog.subtitle')}</div>
        <div class="field-grid">
          <label class="field">
            <span class="req">${t('dialog.name')}</span>
            <input value=${form.name} onInput=${set('name')} autocomplete="off" placeholder="dev-api" />
          </label>
          <label class="field">
            <span class="req">${t('dialog.localPort')}</span>
            <input value=${form.local_port} onInput=${set('local_port')} type="number" min="1"
              max="65535" inputmode="numeric" placeholder="3000" />
          </label>
          <label class="field field-wide">
            <span class="req">${t('dialog.to')}</span>
            <input value=${form.to} onInput=${set('to')} spellcheck="false" placeholder="srv.example" />
          </label>
          <label class="field">
            <span>${t('dialog.remotePort')}</span>
            <input value=${form.port} onInput=${set('port')} type="number" min="1" max="65535"
              inputmode="numeric" placeholder=${t('dialog.remotePortPh')} />
          </label>
          <label class="field">
            <span>${t('dialog.localHost')}</span>
            <input value=${form.local_host} onInput=${set('local_host')} spellcheck="false" />
          </label>
          <label class="field field-wide">
            <span>${t('dialog.secret')}</span>
            <input value=${form.secret} onInput=${set('secret')} type="password"
              autocomplete="off" placeholder=${t('dialog.secretPh')} />
          </label>
        </div>
        ${error ? html`<p class="dialog-error" role="alert">${error}</p>` : ''}
        <div class="dialog-actions">
          <button type="button" class="btn btn-plain" onClick=${onClose}>${t('action.cancel')}</button>
          <button type="submit" class="btn btn-ink" disabled=${busy}>
            ${editing ? t('dialog.editSubmit') : t('dialog.createSubmit')}
          </button>
        </div>
      </form>
    </div>
  `;
}
