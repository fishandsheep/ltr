//! Shared web state: composes the tunnel registry, per-tunnel runtimes, and
//! console security into the API-facing façade.

#![allow(missing_docs)]

use std::{fmt, sync::Arc, time::Duration};

use tokio::{
    sync::{mpsc, oneshot, Mutex, RwLock},
    time::sleep,
};
use uuid::Uuid;

use crate::client::{run_local, LocalArgs};

use super::registry::{self, TunnelRegistry};
use super::runtime::{TunnelRole, TunnelRuntime};
use super::session::{conflict, internal, normalize_config, not_found, ServiceProto};

const POLL_DELAY: Duration = Duration::from_millis(50);

/// Shared web state.
#[derive(Clone)]
pub struct WebState {
    tunnels: Arc<RwLock<TunnelRegistry>>,
    session: Arc<RwLock<SessionInfo>>,
    web_token: Arc<Option<String>>,
    web_tls: Arc<Option<WebTlsConfig>>,
    limits: Arc<WebLimits>,
    store_path: Option<Arc<std::path::PathBuf>>,
    /// Set when the existing store could not be preserved; saves are refused
    /// so the unreadable file is never overwritten.
    store_blocked: Option<Arc<String>>,
    start_lock: Arc<Mutex<()>>,
    persist_lock: Arc<Mutex<()>>,
}

impl fmt::Debug for WebState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebState")
            .field("tunnels", &"[shared]")
            .field("session", &self.session)
            .field(
                "web_token",
                &self.web_token.as_ref().as_ref().map(|_| "[redacted]"),
            )
            .field(
                "web_tls",
                &self.web_tls.as_ref().as_ref().map(|_| "[redacted]"),
            )
            .field("limits", &self.limits)
            .finish()
    }
}

impl Default for WebState {
    fn default() -> Self {
        Self::new(SessionInfo::local())
    }
}

impl WebState {
    pub fn new(session: SessionInfo) -> Self {
        Self::with_web_token(session, None)
    }

    pub fn with_web_token(session: SessionInfo, web_token: Option<String>) -> Self {
        Self::with_security(session, web_token, None)
    }

    pub fn with_security(
        session: SessionInfo,
        web_token: Option<String>,
        web_tls: Option<WebTlsConfig>,
    ) -> Self {
        Self::with_limits(session, web_token, web_tls, WebLimits::default())
    }

    pub fn with_limits(
        session: SessionInfo,
        web_token: Option<String>,
        web_tls: Option<WebTlsConfig>,
        limits: WebLimits,
    ) -> Self {
        Self::with_limits_and_store(session, web_token, web_tls, limits, None)
    }

    /// Build state that persists user tunnels to `store_path`.
    pub fn with_limits_and_store(
        session: SessionInfo,
        web_token: Option<String>,
        web_tls: Option<WebTlsConfig>,
        limits: WebLimits,
        store_path: Option<std::path::PathBuf>,
    ) -> Self {
        let limits = limits.normalized();
        let mut registry = TunnelRegistry::default();
        let mut store_blocked = None;
        if let Some(path) = store_path.clone() {
            let loopback_only = session.loopback_only;
            let mut skipped = 0usize;
            match registry::load_persisted(&path) {
                Ok(persisted) => {
                    for (id, config, created_at) in persisted {
                        let Ok(config) = registry::validate_persisted(&config, loopback_only)
                        else {
                            skipped += 1;
                            continue;
                        };
                        if registry.identities.contains_key(&config.identity_key()) {
                            skipped += 1;
                            continue;
                        }
                        let runtime = registry::runtime_from_persisted(
                            id.clone(),
                            config.clone(),
                            created_at,
                            limits.max_log_lines,
                        );
                        registry.insert(id, &config, runtime);
                    }
                }
                Err(err) => {
                    eprintln!(
                        "Warning: could not read tunnels from {}: {err}",
                        path.display()
                    );
                    skipped = 1;
                }
            }
            if skipped > 0 {
                match registry::backup_store(&path) {
                    Ok(backup) => eprintln!(
                        "Warning: {skipped} persisted tunnel entr{} ignored; the original file was backed up to {}",
                        if skipped == 1 { "y" } else { "ies" },
                        backup.display()
                    ),
                    Err(err) => {
                        eprintln!(
                            "Warning: could not back up {}: {err}; tunnel persistence is disabled for this session to protect the file",
                            path.display()
                        );
                        store_blocked = Some(Arc::new(format!(
                            "tunnel store {} could not be backed up; refusing to overwrite it",
                            path.display()
                        )));
                    }
                }
            }
        }

        Self {
            tunnels: Arc::new(RwLock::new(registry)),
            session: Arc::new(RwLock::new(session)),
            web_token: Arc::new(web_token),
            web_tls: Arc::new(web_tls),
            limits: Arc::new(limits),
            store_path: store_path.map(Arc::new),
            store_blocked,
            start_lock: Arc::new(Mutex::new(())),
            persist_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn web_auth_enabled(&self) -> bool {
        self.web_token.as_ref().is_some()
    }

    pub fn web_token_matches(&self, token: &str) -> bool {
        use subtle::ConstantTimeEq;

        self.web_token
            .as_ref()
            .as_deref()
            .is_some_and(|expected| bool::from(expected.as_bytes().ct_eq(token.as_bytes())))
    }

    pub fn web_tls(&self) -> Option<WebTlsConfig> {
        self.web_tls.as_ref().clone()
    }

    pub fn limits(&self) -> WebLimits {
        *self.limits
    }

    pub async fn session(&self) -> SessionInfo {
        self.session.read().await.clone()
    }

    /// Writes the given persisted set to the store. Refuses to write while the
    /// store is blocked; the caller must hold `persist_lock`. Callers change
    /// memory only after this succeeds, so a failed save leaves state untouched.
    fn save_records(&self, records: &[(String, TunnelConfig, String)]) -> Result<(), StateError> {
        let Some(path) = self.store_path.as_ref() else {
            return Ok(());
        };
        if let Some(reason) = self.store_blocked.as_ref() {
            return Err(internal(reason.to_string()));
        }
        registry::save_persisted(path, records).map_err(|err| {
            internal(format!(
                "could not save tunnels to {}: {err}",
                path.display()
            ))
        })
    }

    pub async fn list_tunnels(&self) -> Vec<TunnelInfo> {
        let entries = {
            let tunnels = self.tunnels.read().await;
            tunnels.entries.values().cloned().collect::<Vec<_>>()
        };

        let mut views = Vec::with_capacity(entries.len());
        for entry in entries {
            let runtime = entry.lock().await;
            views.push(runtime.view());
        }
        views.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        views
    }

    pub async fn create_tunnel(&self, config: TunnelConfig) -> Result<String, StateError> {
        self.create_tunnel_with_meta(config, TunnelRole::User, false, None)
            .await
    }

    pub async fn create_system_tunnel(&self, spec: SystemTunnelSpec) -> Result<String, StateError> {
        self.create_tunnel_with_meta(spec.config, spec.role.into(), true, spec.display_url)
            .await
    }

    /// Ensures a system tunnel definition exists. A stopped tunnel with the
    /// same identity (for example one created earlier through the console) is
    /// adopted instead of failing the identity conflict; a running one is a
    /// hard error because another instance already owns it.
    pub async fn ensure_system_tunnel(&self, spec: SystemTunnelSpec) -> Result<String, StateError> {
        let _start_guard = self.start_lock.lock().await;
        let session = self.session().await;
        let config = normalize_config(spec.config.clone(), session.loopback_only)?;
        let config_key = config.identity_key();

        let existing_id = {
            let tunnels = self.tunnels.read().await;
            tunnels.identities.get(&config_key).cloned()
        };
        if let Some(existing_id) = existing_id {
            let Ok(entry) = self.entry(&existing_id).await else {
                return self.create_system_tunnel(spec).await;
            };
            let mut runtime = entry.lock().await;
            if matches!(
                runtime.status,
                TunnelStatus::Starting | TunnelStatus::Running
            ) {
                return Err(conflict(
                    "an identical tunnel is already running in another instance; stop it first with `ltr -s`",
                ));
            }
            // Take over the runtime metadata (kind, role, lock, display URL);
            // none of it is persisted, so the user's tunnel definition on disk
            // stays untouched after this process exits.
            runtime.kind = super::session::TunnelKind::System;
            runtime.role = spec.role.into();
            runtime.locked = true;
            if spec.display_url.is_some() {
                runtime.display_url = spec.display_url.clone();
            }
            runtime.touch();
            runtime.push_log("adopted by a system tunnel".to_string());
            // No save: nothing persisted changed, and a failing save must not
            // leave the tunnel half-adopted.
            drop(runtime);
            return Ok(existing_id);
        }

        self.create_system_tunnel(spec).await
    }

    pub async fn update_tunnel(&self, id: &str, config: TunnelConfig) -> Result<(), StateError> {
        let _start_guard = self.start_lock.lock().await;
        let _persist_guard = self.persist_lock.lock().await;
        let session = self.session().await;
        let config = normalize_config(config, session.loopback_only)?;
        let entry = self.entry(id).await?;
        let config_key = config.identity_key();

        loop {
            let old_key = {
                let runtime = entry.lock().await;
                if runtime.locked {
                    return Err(conflict("system tunnel is locked"));
                }
                if matches!(
                    runtime.status,
                    TunnelStatus::Starting | TunnelStatus::Running
                ) {
                    return Err(conflict("cannot edit a running tunnel"));
                }
                runtime.config.identity_key()
            };

            let mut tunnels = self.tunnels.write().await;
            if tunnels
                .identities
                .get(&config_key)
                .is_some_and(|existing_id| existing_id != id)
            {
                return Err(conflict("an identical tunnel already exists"));
            }

            let Ok(mut runtime) = entry.try_lock() else {
                drop(tunnels);
                tokio::task::yield_now().await;
                continue;
            };
            if runtime.locked {
                return Err(conflict("system tunnel is locked"));
            }
            if matches!(
                runtime.status,
                TunnelStatus::Starting | TunnelStatus::Running
            ) {
                return Err(conflict("cannot edit a running tunnel"));
            }
            if runtime.config.identity_key() != old_key {
                drop(runtime);
                drop(tunnels);
                tokio::task::yield_now().await;
                continue;
            }

            let secret = config
                .secret
                .clone()
                .or_else(|| runtime.config.secret.clone());
            let updated = TunnelConfig {
                secret,
                ..config.clone()
            };
            // Save first: a failed save must leave the tunnel as it was.
            let mut records = persisted_records(&tunnels, Some(id)).await;
            if runtime.persisted_user {
                records.push((id.to_string(), updated.clone(), runtime.created_at.clone()));
            }
            self.save_records(&records)?;

            runtime.config = updated;
            runtime.remote_port = None;
            runtime.error = None;
            runtime.touch();
            runtime.push_log("tunnel config updated".to_string());
            tunnels.identities.remove(&old_key);
            tunnels.identities.insert(config_key, id.to_string());
            return Ok(());
        }
    }

    pub async fn start_tunnel(&self, id: &str) -> Result<(), StateError> {
        // Serialize start transitions: conflict detection and reservation must
        // not interleave with another API request starting the same identity.
        let _start_guard = self.start_lock.lock().await;
        let (entry, others) = {
            let tunnels = self.tunnels.read().await;
            let entry = tunnels
                .entries
                .get(id)
                .cloned()
                .ok_or_else(|| not_found("tunnel not found"))?;
            let others = tunnels.entries.values().cloned().collect::<Vec<_>>();
            (entry, others)
        };

        // Inspect other active identities without holding the registry lock.
        // Then reserve Starting while holding the registry write lock using
        // try_lock, so updates/deletes cannot race the check and persistence
        // cannot deadlock against a registry lock held across an await.
        let local_args = loop {
            let config_key = {
                let runtime = entry.lock().await;
                if matches!(
                    runtime.status,
                    TunnelStatus::Starting | TunnelStatus::Running
                ) {
                    return Err(conflict("tunnel is already running"));
                }
                runtime.config.identity_key()
            };

            let tunnels = self.tunnels.write().await;
            if !tunnels
                .entries
                .get(id)
                .is_some_and(|registered| Arc::ptr_eq(registered, &entry))
            {
                return Err(not_found("tunnel not found"));
            }
            let mut retry = false;
            for other in &others {
                if Arc::ptr_eq(other, &entry) {
                    continue;
                }
                match other.try_lock() {
                    Ok(runtime)
                        if matches!(
                            runtime.status,
                            TunnelStatus::Starting | TunnelStatus::Running
                        ) && runtime.config.identity_key() == config_key =>
                    {
                        return Err(conflict("an identical tunnel is already running"));
                    }
                    Ok(_) => {}
                    Err(_) => {
                        retry = true;
                        break;
                    }
                }
            }
            if retry {
                drop(tunnels);
                tokio::task::yield_now().await;
                continue;
            }
            let Ok(mut runtime) = entry.try_lock() else {
                drop(tunnels);
                tokio::task::yield_now().await;
                continue;
            };
            if matches!(
                runtime.status,
                TunnelStatus::Starting | TunnelStatus::Running
            ) {
                return Err(conflict("tunnel is already running"));
            }
            if runtime.config.identity_key() != config_key {
                drop(runtime);
                drop(tunnels);
                tokio::task::yield_now().await;
                continue;
            }
            runtime.status = TunnelStatus::Starting;
            runtime.remote_port = None;
            runtime.error = None;
            runtime.service_proto = None;
            runtime.touch();
            let tunnel_name = runtime.config.name.clone();
            runtime.push_log(format!("starting tunnel {tunnel_name}"));
            break LocalArgs::from(runtime.config.clone());
        };

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let entry_for_events = Arc::clone(&entry);
        let state_for_events = self.clone();
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let remote_update = {
                    let mut runtime = entry_for_events.lock().await;
                    runtime.apply_event(event)
                };
                if let Some((role, to, remote_port)) = remote_update {
                    update_session_remote(&state_for_events, role, &to, remote_port).await;
                }
            }
        });

        let mut local_args = local_args;
        {
            let mut runtime = entry.lock().await;
            runtime.shutdown_tx = Some(shutdown_tx);
            local_args.max_connections = self.limits.max_active_connections;
        }

        let handle = tokio::spawn(async move {
            let _ = run_local(
                local_args,
                async move {
                    let _ = shutdown_rx.await;
                },
                Some(event_tx),
            )
            .await;
        });

        let mut runtime = entry.lock().await;
        runtime.handle = Some(handle);
        Ok(())
    }

    pub async fn stop_tunnel(&self, id: &str) -> Result<(), StateError> {
        let _start_guard = self.start_lock.lock().await;
        let entry = self.entry(id).await?;
        if entry.lock().await.locked {
            return Err(conflict("system tunnel is locked"));
        }
        Self::stop_entry(&entry).await;
        Ok(())
    }

    /// Stop a tunnel regardless of lock state. Takes `start_lock` so it cannot
    /// interleave with a start that has reserved the tunnel but not yet
    /// attached its shutdown handle.
    pub async fn stop_tunnel_force(&self, id: &str) -> Result<(), StateError> {
        let _start_guard = self.start_lock.lock().await;
        let entry = self.entry(id).await?;
        Self::stop_entry(&entry).await;
        Ok(())
    }

    /// Detects the protocol of a running tunnel's local service (on request).
    pub async fn detect_service(&self, id: &str) -> Result<ServiceProto, StateError> {
        let entry = self.entry(id).await?;
        super::probe::detect_tunnel_service(&entry).await
    }

    async fn stop_entry(entry: &Arc<Mutex<TunnelRuntime>>) {
        let (shutdown_tx, handle) = {
            let mut runtime = entry.lock().await;
            (runtime.shutdown_tx.take(), runtime.handle.take())
        };
        if let Some(shutdown_tx) = shutdown_tx {
            let _ = shutdown_tx.send(());
        }
        if let Some(handle) = handle {
            let _ = handle.await;
        }

        let mut runtime = entry.lock().await;
        if matches!(
            runtime.status,
            TunnelStatus::Starting | TunnelStatus::Running
        ) {
            runtime.status = TunnelStatus::Stopped;
            runtime.touch();
            runtime.push_log("tunnel stopped".to_string());
        }
    }

    pub async fn delete_tunnel(&self, id: &str) -> Result<(), StateError> {
        let _start_guard = self.start_lock.lock().await;
        let _persist_guard = self.persist_lock.lock().await;
        let entry = self.entry(id).await?;
        {
            let runtime = entry.lock().await;
            if runtime.locked {
                return Err(conflict("system tunnel is locked"));
            }
            if matches!(
                runtime.status,
                TunnelStatus::Starting | TunnelStatus::Running
            ) {
                return Err(conflict("cannot delete a running tunnel"));
            }
        }
        let identity_key = {
            let runtime = entry.lock().await;
            runtime.config.identity_key()
        };
        let mut tunnels = self.tunnels.write().await;
        // Save without this tunnel first; memory only drops it once the file is written.
        let records = persisted_records(&tunnels, Some(id)).await;
        self.save_records(&records)?;
        tunnels.remove(id, &identity_key);
        Ok(())
    }

    pub async fn logs(&self, id: &str) -> Result<Vec<String>, StateError> {
        let entry = self.entry(id).await?;
        let runtime = entry.lock().await;
        Ok(runtime.logs.iter().cloned().collect())
    }

    pub async fn get_tunnel(&self, id: &str) -> Result<TunnelInfo, StateError> {
        let entry = self.entry(id).await?;
        let runtime = entry.lock().await;
        Ok(runtime.view())
    }

    pub async fn wait_for_running(&self, id: &str) -> Result<TunnelInfo, StateError> {
        loop {
            let tunnel = self.get_tunnel(id).await?;
            match tunnel.status {
                TunnelStatus::Running => return Ok(tunnel),
                TunnelStatus::Failed => {
                    return Err(conflict(
                        tunnel
                            .error
                            .unwrap_or_else(|| "tunnel failed before startup".to_string()),
                    ));
                }
                TunnelStatus::Stopped => {
                    return Err(conflict("tunnel stopped before startup completed"));
                }
                TunnelStatus::Starting => sleep(POLL_DELAY).await,
            }
        }
    }

    pub async fn monitor_locked_tunnels(&self, ids: &[String]) -> Result<(), StateError> {
        loop {
            for id in ids {
                let tunnel = self.get_tunnel(id).await?;
                match tunnel.status {
                    TunnelStatus::Failed => {
                        return Err(conflict(tunnel.error.unwrap_or_else(|| {
                            format!("system tunnel {} failed", tunnel.config.name)
                        })));
                    }
                    TunnelStatus::Stopped => {
                        return Err(conflict(format!(
                            "system tunnel {} stopped unexpectedly",
                            tunnel.config.name
                        )));
                    }
                    TunnelStatus::Starting | TunnelStatus::Running => {}
                }
            }
            sleep(POLL_DELAY).await;
        }
    }

    pub async fn shutdown_all(&self) {
        let _start_guard = self.start_lock.lock().await;
        let entries = {
            let tunnels = self.tunnels.read().await;
            tunnels.entries.values().cloned().collect::<Vec<_>>()
        };
        for entry in entries {
            Self::stop_entry(&entry).await;
        }
    }

    async fn create_tunnel_with_meta(
        &self,
        config: TunnelConfig,
        role: TunnelRole,
        locked: bool,
        display_url: Option<String>,
    ) -> Result<String, StateError> {
        let session = self.session().await;
        let config = normalize_config(config, session.loopback_only)?;

        let config_key = config.identity_key();
        // Save before commit: holding persist_lock keeps a concurrent save from
        // writing this tunnel before it is accepted, and a failed save leaves
        // memory unchanged.
        let _persist_guard = self.persist_lock.lock().await;
        let mut tunnels = self.tunnels.write().await;
        if tunnels.identities.contains_key(&config_key) {
            return Err(conflict("an identical tunnel already exists"));
        }
        if tunnels.entries.len() >= self.limits.max_tunnels {
            return Err(conflict(format!(
                "tunnel limit reached (maximum {})",
                self.limits.max_tunnels
            )));
        }

        let now = super::session::now_rfc3339();
        let id = Uuid::new_v4().to_string();
        if role == TunnelRole::User {
            let mut records = persisted_records(&tunnels, None).await;
            records.push((id.clone(), config.clone(), now.clone()));
            self.save_records(&records)?;
        }
        let runtime = TunnelRuntime {
            id: id.clone(),
            config: config.clone(),
            status: TunnelStatus::Stopped,
            remote_port: None,
            error: None,
            kind: if role == TunnelRole::User {
                super::session::TunnelKind::User
            } else {
                super::session::TunnelKind::System
            },
            role,
            persisted_user: role == TunnelRole::User,
            locked,
            display_url,
            created_at: now.clone(),
            updated_at: now,
            shutdown_tx: None,
            handle: None,
            logs: std::collections::VecDeque::new(),
            max_log_lines: self.limits.max_log_lines,
            stats: Default::default(),
            service_proto: None,
        };
        tunnels.insert(id.clone(), &config, runtime);
        Ok(id)
    }

    pub(crate) async fn entry(&self, id: &str) -> Result<Arc<Mutex<TunnelRuntime>>, StateError> {
        self.tunnels
            .read()
            .await
            .entries
            .get(id)
            .cloned()
            .ok_or_else(|| not_found("tunnel not found"))
    }
}

async fn update_session_remote(state: &WebState, role: TunnelRole, to: &str, remote_port: u16) {
    let mut session = state.session.write().await;
    match role {
        TunnelRole::WebConsole => {
            session.web_remote_url = Some(format!("https://{to}:{remote_port}"));
        }
        TunnelRole::Ssh => {
            session.ssh_remote_endpoint = Some(format!("{to}:{remote_port}"));
        }
        TunnelRole::User => {}
    }
}

// ---------------------------------------------------------------------------
// Re-exports: the public web-state surface is importable from this module.
// ---------------------------------------------------------------------------

pub use super::registry::default_tunnels_path;
pub use super::session::{
    is_loopback_host, PublicTunnelConfig, SessionInfo, SessionMode, StateError, SystemTunnelRole,
    SystemTunnelSpec, TunnelConfig, TunnelInfo, TunnelKind, TunnelStatus, WebLimits,
    DEFAULT_MAX_LOG_LINES, DEFAULT_MAX_TUNNELS,
};

/// TLS material for the web console listener.
#[derive(Clone)]
pub struct WebTlsConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl fmt::Debug for WebTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebTlsConfig")
            .field("cert_pem", &"[redacted]")
            .field("key_pem", &"[redacted]")
            .finish()
    }
}

/// Persisted records of every user tunnel except `skip`. Callers add the
/// record they are about to commit, so the file is written before memory changes.
async fn persisted_records(
    tunnels: &TunnelRegistry,
    skip: Option<&str>,
) -> Vec<(String, TunnelConfig, String)> {
    let mut records = Vec::new();
    for (id, entry) in &tunnels.entries {
        if skip == Some(id.as_str()) {
            continue;
        }
        let runtime = entry.lock().await;
        if runtime.persisted_user {
            records.push((
                runtime.id.clone(),
                runtime.config.clone(),
                runtime.created_at.clone(),
            ));
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::{
        is_loopback_host, SessionInfo, SessionMode, SystemTunnelRole, TunnelConfig, TunnelKind,
        TunnelStatus, WebState, DEFAULT_MAX_LOG_LINES,
    };

    fn config(name: &str) -> TunnelConfig {
        TunnelConfig {
            name: name.to_string(),
            local_port: 3000,
            to: "example.com".to_string(),
            port: Some(9000),
            local_host: "127.0.0.1".to_string(),
            secret: None,
        }
    }

    #[tokio::test]
    async fn create_tunnel() {
        let state = WebState::default();
        let id = state
            .create_tunnel(config("dev"))
            .await
            .expect("create should work");
        let tunnels = state.list_tunnels().await;
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].id, id);
        assert_eq!(tunnels[0].status, TunnelStatus::Stopped);
        assert_eq!(tunnels[0].kind, TunnelKind::User);
    }

    #[tokio::test]
    async fn remote_mode_rejects_non_loopback_local_host() {
        let state = WebState::new(SessionInfo {
            mode: SessionMode::RemoteWeb,
            warnings: vec![],
            loopback_only: true,
            web_remote_url: None,
            ssh_remote_endpoint: None,
        });
        let err = state
            .create_tunnel(TunnelConfig {
                local_host: "192.168.1.10".to_string(),
                ..config("dev")
            })
            .await
            .expect_err("create should fail");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn system_tunnel_is_locked() {
        let state = WebState::default();
        let id = state
            .create_system_tunnel(super::SystemTunnelSpec {
                role: SystemTunnelRole::WebConsole,
                config: config("Web Console"),
                display_url: Some("https://example.com:7836".to_string()),
            })
            .await
            .expect("create should work");
        let tunnel = state.get_tunnel(&id).await.expect("tunnel should exist");
        assert!(tunnel.locked);
        assert_eq!(tunnel.kind, TunnelKind::System);
        assert_eq!(
            state
                .update_tunnel(&id, config("other"))
                .await
                .expect_err("update should fail")
                .status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            state
                .stop_tunnel(&id)
                .await
                .expect_err("stop should fail")
                .status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            state
                .delete_tunnel(&id)
                .await
                .expect_err("delete should fail")
                .status,
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn delete_tunnel() {
        let state = WebState::default();
        let id = state
            .create_tunnel(config("dev"))
            .await
            .expect("create should work");
        state.delete_tunnel(&id).await.expect("delete should work");
        assert!(state.list_tunnels().await.is_empty());
    }

    #[tokio::test]
    async fn delete_running_tunnel_returns_error() {
        let state = WebState::default();
        let id = state
            .create_tunnel(config("dev"))
            .await
            .expect("create should work");
        {
            let entry = state.entry(&id).await.expect("entry should exist");
            let mut runtime = entry.lock().await;
            runtime.status = TunnelStatus::Running;
        }
        let err = state
            .delete_tunnel(&id)
            .await
            .expect_err("delete should fail");
        assert_eq!(err.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn web_token_comparison_matches_only_exact_tokens() {
        let state = WebState::with_web_token(SessionInfo::local(), Some("token".to_string()));
        assert!(state.web_token_matches("token"));
        assert!(!state.web_token_matches("tokem"));
        assert!(!state.web_token_matches("token-longer"));
    }

    #[tokio::test]
    async fn starting_running_tunnel_returns_error() {
        let state = WebState::default();
        let id = state
            .create_tunnel(config("dev"))
            .await
            .expect("create should work");
        {
            let entry = state.entry(&id).await.expect("entry should exist");
            let mut runtime = entry.lock().await;
            runtime.status = TunnelStatus::Running;
        }
        let err = state
            .start_tunnel(&id)
            .await
            .expect_err("start should fail");
        assert_eq!(err.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn concurrent_start_requests_reserve_one_transition() {
        let state = WebState::default();
        let id = state
            .create_tunnel(config("dev"))
            .await
            .expect("create should work");

        let first_state = state.clone();
        let first_id = id.clone();
        let first = tokio::spawn(async move { first_state.start_tunnel(&first_id).await });
        let second_state = state.clone();
        let second_id = id.clone();
        let second = tokio::spawn(async move { second_state.start_tunnel(&second_id).await });
        let outcomes = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|result| result.is_err()).count(), 1);
        state.stop_tunnel_force(&id).await.unwrap();
    }

    #[tokio::test]
    async fn update_running_tunnel_returns_error() {
        let state = WebState::default();
        let id = state
            .create_tunnel(config("dev"))
            .await
            .expect("create should work");
        {
            let entry = state.entry(&id).await.expect("entry should exist");
            let mut runtime = entry.lock().await;
            runtime.status = TunnelStatus::Running;
        }
        let err = state
            .update_tunnel(&id, config("dev"))
            .await
            .expect_err("update should fail");
        assert_eq!(err.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn get_logs_returns_newest_lines_only() {
        let state = WebState::default();
        let id = state
            .create_tunnel(config("dev"))
            .await
            .expect("create should work");
        let entry = state.entry(&id).await.expect("entry should exist");
        {
            let mut runtime = entry.lock().await;
            for index in 0..(DEFAULT_MAX_LOG_LINES + 20) {
                runtime.push_log(format!("line-{index}"));
            }
        }

        let logs = state.logs(&id).await.expect("logs should exist");
        assert_eq!(logs.len(), DEFAULT_MAX_LOG_LINES);
        assert_eq!(logs.first().expect("first log"), "line-20");
        assert_eq!(logs.last().expect("last log"), "line-519");
    }

    #[tokio::test]
    async fn create_publishes_nothing_while_a_save_holds_persist_lock() {
        let state = WebState::default();
        let guard = state.persist_lock.lock().await;
        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            state.create_tunnel(config("pending")),
        )
        .await;
        assert!(blocked.is_err(), "create must wait for persist_lock");
        assert!(state.list_tunnels().await.is_empty());
        drop(guard);
        state
            .create_tunnel(config("pending"))
            .await
            .expect("create proceeds once the lock is free");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_create_save_leaves_no_tunnel_in_memory() {
        let dir = std::env::temp_dir().join(format!("ltr-create-nosave-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let store = dir.join("tunnels.toml");
        let state = WebState::with_limits_and_store(
            SessionInfo::local(),
            None,
            None,
            super::WebLimits::default(),
            Some(store),
        );
        {
            let _readonly = ReadOnlyDir::new(&dir);
            state
                .create_tunnel(config("unsaved"))
                .await
                .expect_err("save into a read-only store must fail");
            assert!(state.list_tunnels().await.is_empty());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn adoption_does_not_depend_on_a_successful_save() {
        let dir = std::env::temp_dir().join(format!("ltr-adopt-nosave-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let store = dir.join("tunnels.toml");
        let state = WebState::with_limits_and_store(
            SessionInfo::local(),
            None,
            None,
            super::WebLimits::default(),
            Some(store.clone()),
        );
        let user_id = state
            .create_tunnel(config("adopt-me"))
            .await
            .expect("user tunnel should be created");
        {
            let _readonly = ReadOnlyDir::new(&dir);
            let adopted = state
                .ensure_system_tunnel(super::SystemTunnelSpec {
                    role: SystemTunnelRole::WebConsole,
                    config: config("Web Console"),
                    display_url: None,
                })
                .await
                .expect("adoption must not require a successful save");
            assert_eq!(adopted, user_id);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn adopted_user_tunnel_remains_persisted() {
        let store = std::env::temp_dir().join(format!(
            "ltr-adopted-tunnel-test-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let state = WebState::with_limits_and_store(
            SessionInfo::local(),
            None,
            None,
            super::WebLimits::default(),
            Some(store.clone()),
        );
        let user_id = state
            .create_tunnel(config("persisted"))
            .await
            .expect("user tunnel should be created");
        state
            .ensure_system_tunnel(super::SystemTunnelSpec {
                role: SystemTunnelRole::WebConsole,
                config: config("Web Console"),
                display_url: None,
            })
            .await
            .expect("stopped user tunnel should be adopted");
        state
            .update_tunnel(
                &user_id,
                TunnelConfig {
                    name: "renamed".into(),
                    ..config("persisted")
                },
            )
            .await
            .expect_err("adopted system tunnel is locked to user edits");

        let persisted = std::fs::read_to_string(&store).expect("user tunnel remains on disk");
        assert!(persisted.contains(&user_id));
        let reloaded = WebState::with_limits_and_store(
            SessionInfo::local(),
            None,
            None,
            super::WebLimits::default(),
            Some(store.clone()),
        );
        assert_eq!(reloaded.list_tunnels().await.len(), 1);
        let _ = std::fs::remove_file(store);
    }

    #[tokio::test]
    async fn user_tunnels_survive_restart_via_store() {
        let store =
            std::env::temp_dir().join(format!("ltr-tunnels-test-{}.toml", uuid::Uuid::new_v4()));
        let session = SessionInfo::local();
        let limits = super::WebLimits::default();
        let first = WebState::with_limits_and_store(
            session.clone(),
            None,
            None,
            limits,
            Some(store.clone()),
        );
        let id = first
            .create_tunnel(TunnelConfig {
                secret: Some("hush".to_string()),
                ..config("persisted")
            })
            .await
            .expect("create should work");
        let _ = first
            .create_system_tunnel(super::SystemTunnelSpec {
                role: SystemTunnelRole::WebConsole,
                config: config("Web Console"),
                display_url: None,
            })
            .await;

        let second =
            WebState::with_limits_and_store(session, None, None, limits, Some(store.clone()));
        let tunnels = second.list_tunnels().await;
        assert_eq!(tunnels.len(), 1, "system tunnels are not persisted");
        assert_eq!(tunnels[0].id, id);
        assert_eq!(tunnels[0].config.name, "persisted");
        assert!(tunnels[0].has_secret, "secret round-trips on disk");
        assert_eq!(tunnels[0].status, TunnelStatus::Stopped);
        let _ = std::fs::remove_file(&store);
    }

    #[tokio::test]
    async fn detect_service_requires_a_running_tunnel() {
        let state = WebState::new(SessionInfo::local());
        let id = state.create_tunnel(config("dev")).await.expect("create");
        let err = state
            .detect_service(&id)
            .await
            .expect_err("stopped tunnel must not be probed");
        assert_eq!(err.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn detect_service_records_protocol_on_explicit_request() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
            }
        });

        let state = WebState::new(SessionInfo::local());
        let id = state
            .create_tunnel(TunnelConfig {
                local_port: port,
                ..config("web")
            })
            .await
            .expect("create");
        let entry = state.entry(&id).await.expect("entry");
        entry.lock().await.status = TunnelStatus::Running;

        let proto = state.detect_service(&id).await.expect("probe");
        assert_eq!(proto, super::ServiceProto::Http);
        assert_eq!(
            entry.lock().await.service_proto,
            Some(super::ServiceProto::Http)
        );
    }

    fn temp_store(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ltr-{label}-{}.toml", uuid::Uuid::new_v4()))
    }

    /// Makes a directory read-only and restores it on drop, so a failing
    /// assertion cannot leave an undeletable temp directory behind.
    #[cfg(unix)]
    struct ReadOnlyDir(std::path::PathBuf);

    #[cfg(unix)]
    impl ReadOnlyDir {
        fn new(dir: &std::path::Path) -> Self {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).unwrap();
            Self(dir.to_path_buf())
        }
    }

    #[cfg(unix)]
    impl Drop for ReadOnlyDir {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }

    fn backups_of(store: &std::path::Path) -> Vec<std::path::PathBuf> {
        let dir = store.parent().expect("temp dir");
        let prefix = format!("{}.bak-", store.file_name().unwrap().to_string_lossy());
        std::fs::read_dir(dir)
            .expect("read temp dir")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
            })
            .collect()
    }

    #[tokio::test]
    async fn unreadable_store_is_backed_up_before_being_overwritten() {
        let store = temp_store("corrupt-store");
        let garbage = "this is [not valid toml";
        std::fs::write(&store, garbage).unwrap();

        let state = WebState::with_limits_and_store(
            SessionInfo::local(),
            None,
            None,
            super::WebLimits::default(),
            Some(store.clone()),
        );
        state
            .create_tunnel(config("fresh"))
            .await
            .expect("create should still work");

        let backups = backups_of(&store);
        assert_eq!(backups.len(), 1, "original file must be kept once");
        assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), garbage);
        let _ = std::fs::remove_file(&store);
        let _ = std::fs::remove_file(&backups[0]);
    }

    #[tokio::test]
    async fn invalid_persisted_entries_are_backed_up_and_skipped() {
        let store = temp_store("invalid-entry-store");
        let mut loopback_ok = config("ok");
        loopback_ok.local_host = "127.0.0.1".into();
        let mut remote = config("remote");
        remote.local_host = "192.168.1.10".into();
        let writer = WebState::with_limits_and_store(
            SessionInfo::local(),
            None,
            None,
            super::WebLimits::default(),
            Some(store.clone()),
        );
        writer.create_tunnel(loopback_ok).await.unwrap();
        writer.create_tunnel(remote).await.unwrap();

        // Remote mode only accepts loopback targets, so the second entry is
        // rejected on load and the original file must be preserved.
        let remote_session = SessionInfo {
            loopback_only: true,
            ..SessionInfo::local()
        };
        let reloaded = WebState::with_limits_and_store(
            remote_session,
            None,
            None,
            super::WebLimits::default(),
            Some(store.clone()),
        );
        let tunnels = reloaded.list_tunnels().await;
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].config.name, "ok");
        assert_eq!(backups_of(&store).len(), 1);
        let _ = std::fs::remove_file(&store);
        for backup in backups_of(&store) {
            let _ = std::fs::remove_file(backup);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn saves_are_refused_when_a_corrupt_store_cannot_be_backed_up() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_store("blocked-dir");
        std::fs::create_dir(&dir).unwrap();
        let store = dir.join("tunnels.toml");
        std::fs::write(&store, "not = [valid").unwrap();
        // Readable but not writable: the backup copy cannot be created.
        let _readonly = ReadOnlyDir::new(&dir);
        let state = WebState::with_limits_and_store(
            SessionInfo::local(),
            None,
            None,
            super::WebLimits::default(),
            Some(store.clone()),
        );
        let err = state
            .create_tunnel(config("blocked"))
            .await
            .expect_err("save must be refused");
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(std::fs::read_to_string(&store).unwrap(), "not = [valid");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_file(&store);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_save_is_reported_and_rolled_back() {
        // A read-only directory loads fine but cannot accept the atomic rewrite.
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_store("readonly-dir");
        std::fs::create_dir(&dir).unwrap();
        let store_path = dir.join("tunnels.toml");
        std::fs::write(&store_path, "").unwrap();
        let _readonly = ReadOnlyDir::new(&dir);
        let state = WebState::with_limits_and_store(
            SessionInfo::local(),
            None,
            None,
            super::WebLimits::default(),
            Some(store_path.clone()),
        );
        let err = state
            .create_tunnel(config("unsaved"))
            .await
            .expect_err("save failure must surface");
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(state.list_tunnels().await.is_empty(), "rolled back");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_file(&store_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_update_or_delete_save_leaves_the_tunnel_unchanged() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_store("readonly-edit");
        std::fs::create_dir(&dir).unwrap();
        let store_path = dir.join("tunnels.toml");
        std::fs::write(&store_path, "").unwrap();
        let state = WebState::with_limits_and_store(
            SessionInfo::local(),
            None,
            None,
            super::WebLimits::default(),
            Some(store_path.clone()),
        );
        let id = state.create_tunnel(config("kept")).await.expect("create");
        let _readonly = ReadOnlyDir::new(&dir);

        let err = state
            .update_tunnel(
                &id,
                TunnelConfig {
                    local_port: 4000,
                    ..config("kept")
                },
            )
            .await
            .expect_err("update save failure must surface");
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        let listed = state.list_tunnels().await;
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].config.local_port, 3000,
            "edit must not stick in memory"
        );

        let err = state
            .delete_tunnel(&id)
            .await
            .expect_err("delete save failure must surface");
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            state.list_tunnels().await.len(),
            1,
            "tunnel must still exist"
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        state
            .delete_tunnel(&id)
            .await
            .expect("delete once writable");
        assert!(state.list_tunnels().await.is_empty());
        let _ = std::fs::remove_file(&store_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[tokio::test]
    async fn force_stop_never_leaves_a_stopped_tunnel_with_a_live_handle() {
        // Refused connections make each start fail fast, so start and force
        // stop race on the reservation window many times.
        for _ in 0..25 {
            let state = WebState::default();
            let mut refused = config("race");
            refused.to = "127.0.0.1".into();
            refused.port = Some(9);
            refused.local_port = 1;
            let id = state.create_tunnel(refused).await.unwrap();
            let (started, stopped) =
                tokio::join!(state.start_tunnel(&id), state.stop_tunnel_force(&id));
            let _ = started;
            stopped.expect("force stop should succeed");
            let runtime = state.entry(&id).await.unwrap();
            let runtime = runtime.lock().await;
            assert!(
                !(runtime.status == TunnelStatus::Stopped && runtime.handle.is_some()),
                "stopped tunnel must not own a running handle"
            );
        }
    }

    #[test]
    fn loopback_host_parser_accepts_known_values() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("192.168.1.10"));
    }
}
