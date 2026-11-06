const TOKEN_KEY = 'ltr-web-token';

export function getToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function setToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {}
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';

  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    throw new ApiError('unauthorized', 401);
  }
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new ApiError((data && data.error) || response.statusText, response.status);
  }
  return data;
}

/** Normalize one tunnel record. The API serializes Rust enums PascalCase
 * ("Stopped"); the UI speaks lowercase everywhere (i18n keys, CSS classes,
 * status comparisons). */
function normalizeTunnel(tunnel) {
  return { ...tunnel, status: String(tunnel.status ?? '').toLowerCase() };
}

export const api = {
  session: () => request('/api/session'),
  listTunnels: async () =>
    (await request('/api/tunnels')).map(normalizeTunnel),
  createTunnel: (payload) =>
    request('/api/tunnels', { method: 'POST', body: JSON.stringify(payload) }),
  updateTunnel: (id, payload) =>
    request(`/api/tunnels/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  deleteTunnel: (id) => request(`/api/tunnels/${id}`, { method: 'DELETE' }),
  startTunnel: (id) => request(`/api/tunnels/${id}/start`, { method: 'POST' }),
  stopTunnel: (id) => request(`/api/tunnels/${id}/stop`, { method: 'POST' }),
  tunnelLogs: (id) => request(`/api/tunnels/${id}/logs`),
};

/** Serialize the dialog form into an API payload. */
export function formToPayload(form) {
  return {
    name: form.name.trim(),
    local_port: Number(form.local_port),
    to: form.to.trim(),
    port: form.port ? Number(form.port) : null,
    local_host: form.local_host.trim() || '127.0.0.1',
    secret: form.secret ? form.secret : null,
  };
}
