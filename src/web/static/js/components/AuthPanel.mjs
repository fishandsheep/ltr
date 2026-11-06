import { html } from '../lib.mjs';
import { t } from '../i18n.mjs';
import { useState } from '../vendor/hooks.mjs';

export function AuthPanel({ onUnlock }) {
  const [token, setToken] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    if (busy) return;
    const trimmed = token.trim();
    if (!trimmed) return;
    setBusy(true);
    setMessage(t('auth.checking'));
    try {
      await onUnlock(trimmed);
    } catch (err) {
      setMessage(err.status === 401 ? t('auth.invalid') : err.message);
      setBusy(false);
    }
  };

  return html`
    <section class="auth-wrap">
      <form class="auth-card" onSubmit=${submit}>
        <div class="dialog-title">${t('auth.title')}</div>
        <p class="dialog-sub">${t('auth.copy')}</p>
        <label class="field">
          <span>${t('auth.token')}</span>
          <input type="password" value=${token} autocomplete="off" autofocus
            onInput=${(e) => setToken(e.target.value)} />
        </label>
        <p class="dialog-error" role="alert">${message}</p>
        <div class="dialog-actions">
          <button type="submit" class="btn btn-ink" disabled=${busy || !token.trim()}>
            ${t('auth.unlock')}
          </button>
        </div>
      </form>
    </section>
  `;
}
