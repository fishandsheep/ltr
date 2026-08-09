const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_REMOTE = "localhost";
const POLL_INTERVAL_MS = 2000;
const LOCALE = document.documentElement.lang || navigator.language || "en-US";
const STATUS_LABELS = {
  Starting: "Starting",
  Running: "Running",
  Stopped: "Stopped",
  Failed: "Failed",
};
const COPY = {
  autoPort: "auto",
  noSecret: "Not set",
  hasSecret: "Configured",
  noLogs: "No logs yet.",
  loadingLogs: "Loading logs…",
  loadingTunnels: "Loading tunnels…",
  listUpdated: "Tunnel list updated.",
  listRefreshed: "Tunnel list refreshed.",
  startBusy: "Starting tunnel…",
  startDone: "Tunnel started.",
  stopBusy: "Stopping tunnel…",
  stopDone: "Tunnel stopped.",
  deleteDone: "Tunnel deleted.",
  createBusy: "Saving tunnel…",
  createDone: "Tunnel created.",
  updateDone: "Tunnel updated.",
  deletePromptTitle: "Delete this tunnel?",
  deletePromptBody(name) {
    return `Delete "${name}"? This permanently removes the saved tunnel configuration.`;
  },
};
const timestampFormatter = new Intl.DateTimeFormat(LOCALE, {
  dateStyle: "medium",
  timeStyle: "short",
});

const state = {
  session: null,
  authToken: sessionStorage.getItem("ltr-web-token") || "",
  expandedLogs: new Set(),
  tunnels: [],
  pollingTimer: null,
  editingTunnelId: null,
  formBusy: false,
  refreshBusy: false,
  syncing: false,
  pendingSync: false,
  busyTunnelActions: new Map(),
};

const renderedTunnels = new Map();

const form = document.getElementById("tunnel-form");
const authPanel = document.getElementById("auth-panel");
const authForm = document.getElementById("auth-form");
const authTokenInput = document.getElementById("auth-token");
const authMessage = document.getElementById("auth-message");
const formTitle = document.getElementById("form-title");
const submitBtn = document.getElementById("submit-btn");
const cancelEditBtn = document.getElementById("cancel-edit-btn");
const list = document.getElementById("tunnel-list");
const listFeedback = document.getElementById("list-feedback");
const formMessage = document.getElementById("form-message");
const refreshBtn = document.getElementById("refresh-btn");
const consoleAddr = document.getElementById("console-addr");
const tunnelSummary = document.getElementById("tunnel-summary");
const sessionBanner = document.getElementById("session-banner");
const sessionMode = document.getElementById("session-mode");
const sessionRemoteWeb = document.getElementById("session-remote-web");
const sessionRemoteSsh = document.getElementById("session-remote-ssh");
const sessionWarnings = document.getElementById("session-warnings");
const deleteDialog = document.getElementById("delete-dialog");
const deleteDialogTitle = document.getElementById("delete-dialog-title");
const deleteDialogBody = document.getElementById("delete-dialog-body");

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!form.reportValidity() || state.formBusy) {
    return;
  }

  const payload = readFormPayload();
  setFormBusy(true);
  setFormMessage(COPY.createBusy);

  try {
    if (state.editingTunnelId) {
      await updateTunnel(state.editingTunnelId, payload);
      resetFormState();
      setFormMessage(COPY.updateDone, "success");
    } else {
      await createTunnel(payload);
      resetFormState();
      setFormMessage(COPY.createDone, "success");
    }
    await syncState({ announce: COPY.listUpdated });
  } catch (error) {
    setFormMessage(error.message, "error");
  } finally {
    setFormBusy(false);
  }
});

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = authTokenInput.value.trim();
  if (!token) {
    setAuthMessage("Enter the Web token.", "error");
    return;
  }

  state.authToken = token;
  sessionStorage.setItem("ltr-web-token", token);
  setAuthMessage("Checking token…");

  try {
    await init();
    hideAuthPanel();
  } catch (error) {
    showAuthPanel(error.message);
  }
});

cancelEditBtn.addEventListener("click", () => {
  resetFormState();
  setFormMessage("");
});

refreshBtn.addEventListener("click", () => {
  syncState({ announce: COPY.listRefreshed, source: "manual" }).catch(showListError);
});

list.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) {
    return;
  }

  const { action, tunnelId } = button.dataset;
  if (!action || !tunnelId || button.disabled) {
    return;
  }

  const actions = {
    start: () => startTunnel(tunnelId),
    stop: () => stopTunnel(tunnelId),
    edit: () => {
      beginEditTunnel(tunnelId);
      return Promise.resolve();
    },
    delete: () => deleteTunnel(tunnelId),
    logs: () => toggleLogs(tunnelId, button),
  };

  const handler = actions[action];
  if (!handler) {
    return;
  }

  Promise.resolve(handler()).catch((error) => {
    if (action === "edit") {
      setFormMessage(error.message, "error");
      return;
    }
    showListError(error);
  });
});

function readFormPayload() {
  const data = new FormData(form);
  const payload = {
    name: data.get("name")?.toString().trim() || "",
    local_port: Number(data.get("local_port")),
    to: data.get("to")?.toString().trim() || "",
    port: data.get("port") ? Number(data.get("port")) : null,
    local_host: data.get("local_host")?.toString().trim() || "",
    secret: data.get("secret")?.toString() || null,
  };

  if (!payload.port) {
    payload.port = null;
  }
  if (!payload.secret) {
    payload.secret = null;
  }
  return payload;
}

function resetFormState() {
  state.editingTunnelId = null;
  formTitle.textContent = "Create local tunnel";
  submitBtn.textContent = "Create tunnel";
  cancelEditBtn.hidden = true;
  form.reset();
  form.elements.to.value = DEFAULT_REMOTE;
  form.elements.local_host.value = DEFAULT_HOST;
  form.elements.local_host.readOnly = Boolean(state.session?.loopback_only);
}

function setFormBusy(isBusy) {
  state.formBusy = isBusy;
  submitBtn.disabled = isBusy;
  submitBtn.classList.toggle("button-busy", isBusy);
  Array.from(form.elements).forEach((element) => {
    if (element === cancelEditBtn) {
      return;
    }
    element.disabled = isBusy;
  });
}

function setRefreshBusy(isBusy) {
  state.refreshBusy = isBusy;
  refreshBtn.disabled = isBusy;
  refreshBtn.classList.toggle("button-busy", isBusy);
}

function setFormMessage(message, tone) {
  formMessage.textContent = message;
  formMessage.className = "message";
  if (tone) {
    formMessage.classList.add(`is-${tone}`);
  }
}

function setListFeedback(message, tone) {
  listFeedback.textContent = message;
  listFeedback.className = "list-feedback";
  if (tone) {
    listFeedback.classList.add(`is-${tone}`);
  }
}

function beginEditTunnel(id) {
  const tunnel = state.tunnels.find((item) => item.id === id);
  if (!tunnel) {
    return;
  }
  if (tunnel.locked) {
    setFormMessage("System tunnel is locked.", "error");
    return;
  }
  if (tunnel.status === "Starting" || tunnel.status === "Running") {
    setFormMessage("Stop the tunnel before editing it.", "error");
    return;
  }

  state.editingTunnelId = id;
  formTitle.textContent = `Edit tunnel: ${tunnel.config.name}`;
  submitBtn.textContent = "Save changes";
  cancelEditBtn.hidden = false;
  form.elements.name.value = tunnel.config.name;
  form.elements.local_port.value = tunnel.config.local_port;
  form.elements.to.value = tunnel.config.to;
  form.elements.port.value = tunnel.config.port ?? "";
  form.elements.local_host.value = tunnel.config.local_host;
  form.elements.secret.value = "";
  setFormMessage(
    tunnel.has_secret
      ? "Leave Secret empty to keep the current secret."
      : "Update the fields and save.",
  );

  form.scrollIntoView({
    behavior: prefersReducedMotion() ? "auto" : "smooth",
    block: "start",
  });
}

async function syncSession() {
  state.session = await api("/api/session");
  applySession(state.session);
  resetFormState();
}

function applySession(session) {
  consoleAddr.textContent = `Listening on ${window.location.origin}`;
  if (!session || session.mode === "Local") {
    sessionBanner.hidden = true;
    return;
  }

  sessionBanner.hidden = false;
  sessionMode.textContent =
    session.mode === "Home"
      ? "Remote home mode. Public web + SSH system tunnels stay locked."
      : "Remote web mode. Public web system tunnel stays locked.";
  sessionRemoteWeb.textContent = session.web_remote_url
    ? `Remote web: ${session.web_remote_url}`
    : "";
  sessionRemoteWeb.hidden = !session.web_remote_url;
  sessionRemoteSsh.textContent = session.ssh_remote_endpoint
    ? `Remote SSH: ${session.ssh_remote_endpoint}`
    : "";
  sessionRemoteSsh.hidden = !session.ssh_remote_endpoint;
  sessionWarnings.replaceChildren(
    ...((session.warnings || []).map((warning) => {
      const item = document.createElement("li");
      item.textContent = warning;
      return item;
    })),
  );
}

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (state.authToken) {
    headers.Authorization = `Bearer ${state.authToken}`;
  }

  const response = await fetch(path, {
    ...options,
    headers,
  });
  if (response.status === 401) {
    state.authToken = "";
    sessionStorage.removeItem("ltr-web-token");
    showAuthPanel("The Web token is missing or invalid.");
  }
  if (!response.ok) {
    let message = `Request failed: ${response.status}`;
    try {
      const data = await response.json();
      if (data.error) {
        message = data.error;
      }
    } catch (_) {
      // ignore JSON parse errors
    }
    throw new Error(message);
  }
  if (response.status === 204) {
    return null;
  }
  return response.json();
}

function showAuthPanel(message = "") {
  authPanel.hidden = false;
  authTokenInput.value = "";
  setAuthMessage(message, message ? "error" : undefined);
  authTokenInput.focus({ preventScroll: true });
}

function hideAuthPanel() {
  authPanel.hidden = true;
  setAuthMessage("");
}

function setAuthMessage(message, tone) {
  authMessage.textContent = message;
  authMessage.className = "message";
  if (tone) {
    authMessage.classList.add(`is-${tone}`);
  }
}

async function syncState({ announce = "", source = "auto" } = {}) {
  if (state.syncing) {
    state.pendingSync = true;
    return;
  }

  state.syncing = true;
  if (source === "manual") {
    setRefreshBusy(true);
  }

  try {
    state.tunnels = await api("/api/tunnels");
    renderTunnels(state.tunnels);
    updateSummary(state.tunnels);
    refreshExpandedLogs();
    restartPolling();
    if (announce) {
      setListFeedback(announce);
    }
  } finally {
    state.syncing = false;
    setRefreshBusy(false);

    if (state.pendingSync) {
      state.pendingSync = false;
      await syncState();
    }
  }
}

async function createTunnel(payload) {
  return api("/api/tunnels", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

async function updateTunnel(id, payload) {
  return api(`/api/tunnels/${id}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

async function startTunnel(id) {
  await runTunnelAction(id, "start", async () => {
    patchTunnel(id, { status: "Starting", error: null, remote_port: null });
    restartPolling();
    await api(`/api/tunnels/${id}/start`, { method: "POST" });
    await syncState({ announce: COPY.startDone });
  }, { announceStart: COPY.startBusy });
}

async function stopTunnel(id) {
  await runTunnelAction(id, "stop", async () => {
    await api(`/api/tunnels/${id}/stop`, { method: "POST" });
    await syncState({ announce: COPY.stopDone });
  }, { announceStart: COPY.stopBusy });
}

async function deleteTunnel(id) {
  const tunnel = state.tunnels.find((item) => item.id === id);
  if (!tunnel) {
    return;
  }

  const shouldDelete = await confirmDelete(tunnel);
  if (!shouldDelete) {
    return;
  }

  await runTunnelAction(id, "delete", async () => {
    await api(`/api/tunnels/${id}`, { method: "DELETE" });
    state.expandedLogs.delete(id);
    if (state.editingTunnelId === id) {
      resetFormState();
      setFormMessage("");
    }
    await syncState({ announce: COPY.deleteDone });
  });
}

async function fetchLogs(id) {
  const data = await api(`/api/tunnels/${id}/logs`);
  updateLogs(id, data.logs);
}

async function refreshExpandedLogs() {
  const expandedIds = state.tunnels
    .filter((tunnel) => state.expandedLogs.has(tunnel.id))
    .map((tunnel) => tunnel.id);

  await Promise.all(
    expandedIds.map((id) =>
      fetchLogs(id).catch((error) => {
        updateLogs(id, [`Failed to load logs: ${error.message}`]);
      }),
    ),
  );
}

function restartPolling() {
  if (state.pollingTimer) {
    clearInterval(state.pollingTimer);
    state.pollingTimer = null;
  }

  const needsPolling =
    state.expandedLogs.size > 0 ||
    state.tunnels.some((tunnel) => tunnel.status === "Starting" || tunnel.status === "Running");

  if (!needsPolling) {
    return;
  }

  state.pollingTimer = setInterval(() => {
    const hasActiveTunnels = state.tunnels.some(
      (tunnel) => tunnel.status === "Starting" || tunnel.status === "Running",
    );

    if (hasActiveTunnels) {
      syncState().catch(() => {});
      return;
    }

    if (state.expandedLogs.size > 0) {
      refreshExpandedLogs().catch(() => {});
    }
  }, POLL_INTERVAL_MS);
}

function renderTunnels(tunnels) {
  const activeElement = document.activeElement;
  const focusKey =
    activeElement instanceof HTMLElement ? activeElement.dataset.focusKey || null : null;

  if (!tunnels.length) {
    renderedTunnels.clear();
    list.replaceChildren(createEmptyState("No tunnels yet.", "Create one from the form to start forwarding traffic."));
    return;
  }

  if (list.firstElementChild?.classList.contains("empty")) {
    list.replaceChildren();
  }

  const existingIds = new Set(renderedTunnels.keys());
  tunnels.forEach((tunnel, index) => {
    let card = renderedTunnels.get(tunnel.id);
    if (!card) {
      card = createTunnelCard(tunnel.id);
      renderedTunnels.set(tunnel.id, card);
    }

    patchTunnelCard(card, tunnel);
    const currentNode = list.children[index];
    if (currentNode !== card) {
      list.insertBefore(card, currentNode || null);
    }
    existingIds.delete(tunnel.id);
  });

  existingIds.forEach((id) => {
    renderedTunnels.get(id)?.remove();
    renderedTunnels.delete(id);
  });

  if (focusKey) {
    const nextFocus = list.querySelector(`[data-focus-key="${CSS.escape(focusKey)}"]`);
    if (nextFocus instanceof HTMLElement) {
      nextFocus.focus({ preventScroll: true });
    }
  }
}

function createTunnelCard(id) {
  const article = document.createElement("article");
  article.className = "tunnel-card";
  article.dataset.tunnelId = id;

  const cardHead = document.createElement("div");
  cardHead.className = "card-head";

  const titleWrap = document.createElement("div");
  titleWrap.className = "card-title";

  const titleRow = document.createElement("div");
  titleRow.className = "card-title-row";

  const name = document.createElement("h3");
  name.className = "card-name";

  const badges = document.createElement("div");
  badges.className = "card-badges";

  const route = document.createElement("p");
  route.className = "route";

  const status = document.createElement("span");
  status.className = "status";

  titleRow.append(name, badges);
  titleWrap.append(titleRow, route);
  cardHead.append(titleWrap, status);

  const metaList = document.createElement("dl");
  metaList.className = "meta-list";

  const metaRequested = createMetaItem("Requested Port");
  const metaSecret = createMetaItem("Secret");
  const metaCreated = createMetaItem("Created");
  const metaUpdated = createMetaItem("Updated");
  metaList.append(metaRequested.item, metaSecret.item, metaCreated.item, metaUpdated.item);

  const error = document.createElement("p");
  error.className = "error-text";
  error.hidden = true;

  const cardActions = document.createElement("div");
  cardActions.className = "card-actions";

  const group = document.createElement("div");
  group.className = "card-actions-group";

  const startButton = createActionButton("Start", "start", id);
  const stopButton = createActionButton("Stop", "stop", id, "secondary");
  const editButton = createActionButton("Edit", "edit", id, "ghost");
  const deleteButton = createActionButton("Delete", "delete", id, "danger");
  group.append(startButton, stopButton, editButton, deleteButton);

  const logsButton = createActionButton("View logs", "logs", id, "ghost");
  logsButton.type = "button";
  logsButton.setAttribute("aria-controls", `logs-${id}`);
  logsButton.dataset.focusKey = `${id}:logs`;

  cardActions.append(group, logsButton);

  const logs = document.createElement("section");
  logs.className = "logs";
  logs.id = `logs-${id}`;
  logs.hidden = true;

  const logsPre = document.createElement("pre");
  logs.append(logsPre);

  article.append(cardHead, metaList, error, cardActions, logs);
  article._refs = {
    name,
    badges,
    route,
    status,
    metaRequested: metaRequested.value,
    metaSecret: metaSecret.value,
    metaCreated: metaCreated.value,
    metaUpdated: metaUpdated.value,
    error,
    startButton,
    stopButton,
    editButton,
    deleteButton,
    group,
    logsButton,
    logs,
    logsPre,
  };

  return article;
}

function createMetaItem(label) {
  const item = document.createElement("div");
  const term = document.createElement("dt");
  term.textContent = label;
  const value = document.createElement("dd");
  item.append(term, value);
  return { item, value };
}

function createActionButton(label, action, tunnelId, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.dataset.action = action;
  button.dataset.tunnelId = tunnelId;
  button.dataset.focusKey = `${tunnelId}:${action}`;
  if (className) {
    button.className = className;
  }
  return button;
}

function getStatusLabel(status) {
  return STATUS_LABELS[status] || status;
}

function formatTimestamp(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return timestampFormatter.format(date);
}

async function runTunnelAction(id, action, worker, { announceStart = "" } = {}) {
  if (state.busyTunnelActions.has(id)) {
    return;
  }

  state.busyTunnelActions.set(id, action);
  const tunnel = findTunnel(id);
  const card = renderedTunnels.get(id);
  if (card && tunnel) {
    patchTunnelCard(card, tunnel);
  }
  if (announceStart) {
    setListFeedback(announceStart);
  }

  try {
    await worker();
  } catch (error) {
    try {
      await syncState();
    } catch (_) {
      // Keep original action error.
    }
    throw error;
  } finally {
    state.busyTunnelActions.delete(id);
    const nextTunnel = findTunnel(id);
    const nextCard = renderedTunnels.get(id);
    if (nextCard && nextTunnel) {
      patchTunnelCard(nextCard, nextTunnel);
    }
  }
}

function patchTunnelCard(card, tunnel) {
  const refs = card._refs;
  const statusClass = tunnel.status.toLowerCase();
  const statusLabel = getStatusLabel(tunnel.status);
  const canStart = tunnel.status === "Stopped" || tunnel.status === "Failed";
  const canStop = !tunnel.locked && (tunnel.status === "Starting" || tunnel.status === "Running");
  const canDelete = !tunnel.locked && (tunnel.status === "Stopped" || tunnel.status === "Failed");
  const canEdit = !tunnel.locked && (tunnel.status === "Stopped" || tunnel.status === "Failed");
  const logsExpanded = state.expandedLogs.has(tunnel.id);
  const visiblePort = tunnel.remote_port ?? tunnel.config.port ?? COPY.autoPort;
  const remoteLabel = `${tunnel.config.to}:${visiblePort}`;
  const remoteUrl = tunnel.display_url || (tunnel.remote_port ? `http://${tunnel.config.to}:${tunnel.remote_port}` : null);
  const busyAction = state.busyTunnelActions.get(tunnel.id) || null;
  const isBusy = Boolean(busyAction);

  refs.name.textContent = tunnel.config.name;
  refs.badges.replaceChildren(...buildBadges(tunnel));
  refs.route.replaceChildren(
    document.createTextNode(`${tunnel.config.local_host}:${tunnel.config.local_port} → `),
    remoteUrl && /^https?:\/\//.test(remoteUrl)
      ? createRemoteLink(remoteUrl, remoteLabel)
      : document.createTextNode(remoteUrl || remoteLabel),
  );

  refs.status.className = `status ${statusClass}`;
  refs.status.textContent = statusLabel;

  refs.metaRequested.textContent = tunnel.config.port ?? COPY.autoPort;
  refs.metaSecret.textContent = tunnel.has_secret ? COPY.hasSecret : COPY.noSecret;
  refs.metaCreated.textContent = formatTimestamp(tunnel.created_at);
  refs.metaUpdated.textContent = formatTimestamp(tunnel.updated_at);

  refs.error.hidden = !tunnel.error;
  refs.error.textContent = tunnel.error || "";

  refs.group.setAttribute("aria-busy", String(isBusy));
  refs.startButton.disabled = isBusy || !canStart;
  refs.stopButton.disabled = isBusy || !canStop;
  refs.editButton.disabled = isBusy || !canEdit;
  refs.deleteButton.disabled = isBusy || !canDelete;
  refs.logsButton.disabled = isBusy;
  refs.startButton.classList.toggle("button-busy", busyAction === "start");
  refs.stopButton.classList.toggle("button-busy", busyAction === "stop");
  refs.deleteButton.classList.toggle("button-busy", busyAction === "delete");

  refs.logsButton.textContent = logsExpanded ? "Hide logs" : "View logs";
  refs.logsButton.setAttribute("aria-expanded", String(logsExpanded));
  refs.logs.hidden = !logsExpanded;

  if (logsExpanded && !refs.logsPre.textContent) {
    refs.logsPre.textContent = COPY.loadingLogs;
  }
}

function buildBadges(tunnel) {
  const badges = [];
  if (tunnel.kind === "System") {
    badges.push(createBadge("System", "system"));
    if (tunnel.config.name === "Web Console") {
      badges.push(createBadge("Web Console"));
    }
    if (tunnel.config.name === "SSH") {
      badges.push(createBadge("SSH"));
    }
  }
  if (tunnel.locked) {
    badges.push(createBadge("Locked"));
  }
  return badges;
}

function createBadge(label, className = "") {
  const badge = document.createElement("span");
  badge.className = `status-badge ${className}`.trim();
  badge.textContent = label;
  return badge;
}

function createRemoteLink(url, label) {
  const link = document.createElement("a");
  link.className = "remote-link";
  link.href = url;
  link.target = "_blank";
  link.rel = "noreferrer";
  link.textContent = label;
  return link;
}

function patchTunnel(id, patch) {
  state.tunnels = state.tunnels.map((tunnel) =>
    tunnel.id === id ? { ...tunnel, ...patch } : tunnel,
  );
  renderTunnels(state.tunnels);
  updateSummary(state.tunnels);
}

function updateLogs(id, logs) {
  const card = renderedTunnels.get(id);
  if (!card) {
    return;
  }

  const { logsPre } = card._refs;
  const nextText = (logs || []).join("\n") || COPY.noLogs;
  const wasPinnedToBottom =
    Math.abs(logsPre.scrollHeight - logsPre.clientHeight - logsPre.scrollTop) < 8;
  const previousScrollTop = logsPre.scrollTop;

  if (logsPre.textContent === nextText) {
    return;
  }

  logsPre.textContent = nextText;

  if (wasPinnedToBottom) {
    logsPre.scrollTop = logsPre.scrollHeight;
  } else {
    logsPre.scrollTop = previousScrollTop;
  }
}

async function toggleLogs(id, trigger) {
  if (state.expandedLogs.has(id)) {
    state.expandedLogs.delete(id);
    const card = renderedTunnels.get(id);
    if (card) {
      patchTunnelCard(card, findTunnel(id));
    }
    restartPolling();
    return;
  }

  state.expandedLogs.add(id);
  const card = renderedTunnels.get(id);
  if (card) {
    patchTunnelCard(card, findTunnel(id));
  }
  restartPolling();
  await fetchLogs(id);

  if (trigger instanceof HTMLElement) {
    trigger.focus({ preventScroll: true });
  }
}

async function confirmDelete(tunnel) {
  deleteDialogTitle.textContent = COPY.deletePromptTitle;
  deleteDialogBody.textContent = COPY.deletePromptBody(tunnel.config.name);

  if (typeof deleteDialog.showModal !== "function") {
    return false;
  }

  return new Promise((resolve) => {
    const handleClose = () => {
      deleteDialog.removeEventListener("close", handleClose);
      resolve(deleteDialog.returnValue === "confirm");
    };

    deleteDialog.addEventListener("close", handleClose, { once: true });
    deleteDialog.showModal();
  });
}

function findTunnel(id) {
  return state.tunnels.find((tunnel) => tunnel.id === id);
}

function updateSummary(tunnels) {
  const running = tunnels.filter((tunnel) => tunnel.status === "Running").length;
  const starting = tunnels.filter((tunnel) => tunnel.status === "Starting").length;

  if (!tunnels.length) {
    tunnelSummary.textContent = "No tunnels configured";
    return;
  }

  const parts = [`${tunnels.length} total`];
  if (running) {
    parts.push(`${running} running`);
  }
  if (starting) {
    parts.push(`${starting} starting`);
  }
  tunnelSummary.textContent = parts.join(" • ");
}

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function showListError(error) {
  setListFeedback(error.message, "error");
  if (!state.tunnels.length) {
    list.replaceChildren(createEmptyState("Unable to load tunnels.", error.message));
    updateSummary([]);
  }
}

function createEmptyState(title, body) {
  const empty = document.createElement("div");
  empty.className = "empty";
  const strong = document.createElement("strong");
  strong.textContent = title;
  const span = document.createElement("span");
  span.textContent = body;
  empty.append(strong, span);
  return empty;
}

resetFormState();
setListFeedback(COPY.loadingTunnels);
init().catch(showListError);

async function init() {
  await syncSession();
  await syncState();
}
