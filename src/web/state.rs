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
use super::session::{conflict, normalize_config, not_found};

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
        if let Some(path) = &store_path {
            for (id, config, created_at) in registry::load_persisted(path) {
                let Ok(config) = registry::validate_persisted(&config) else {
                    continue;
                };
                let runtime = registry::runtime_from_persisted(
                    id.clone(),
                    config.clone(),
                    created_at,
                    limits.max_log_lines,
                );
                registry.insert(id, &config, runtime);
            }
        }

        Self {
            tunnels: Arc::new(RwLock::new(registry)),
            session: Arc::new(RwLock::new(session)),
            web_token: Arc::new(web_token),
            web_tls: Arc::new(web_tls),
            limits: Arc::new(limits),
            store_path: store_path.map(Arc::new),
        }
    }

    pub fn web_auth_enabled(&self) -> bool {
        self.web_token.as_ref().is_some()
    }

    pub fn web_token_matches(&self, token: &str) -> bool {
        self.web_token.as_ref().as_deref() == Some(token)
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

    /// Persist user tunnels if a store path is configured.
    async fn persist(&self) {
        let Some(path) = self.store_path.as_ref() else {
            return;
        };
        let tunnels = self.tunnels.read().await;
        let mut snapshot = Vec::new();
        for entry in tunnels.entries.values() {
            let runtime = entry.lock().await;
            if runtime.role != TunnelRole::User {
                continue;
            }
            snapshot.push((
                runtime.id.clone(),
                runtime.config.clone(),
                runtime.created_at.clone(),
            ));
        }
        drop(tunnels);
        if let Err(err) = registry::save_persisted(path, &snapshot) {
            eprintln!(
                "Warning: could not persist tunnels to {}: {err}",
                path.display()
            );
        }
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

    pub async fn update_tunnel(&self, id: &str, config: TunnelConfig) -> Result<(), StateError> {
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
                continue;
            }

            let secret = config
                .secret
                .clone()
                .or_else(|| runtime.config.secret.clone());
            runtime.config = TunnelConfig {
                secret,
                ..config.clone()
            };
            runtime.remote_port = None;
            runtime.error = None;
            runtime.touch();
            runtime.push_log("tunnel config updated".to_string());
            tunnels.identities.remove(&old_key);
            tunnels.identities.insert(config_key, id.to_string());
            drop(runtime);
            drop(tunnels);
            self.persist().await;
            return Ok(());
        }
    }

    pub async fn start_tunnel(&self, id: &str) -> Result<(), StateError> {
        let entries = {
            let tunnels = self.tunnels.read().await;
            let entry = tunnels
                .entries
                .get(id)
                .cloned()
                .ok_or_else(|| not_found("tunnel not found"))?;
            let others = tunnels.entries.values().cloned().collect::<Vec<_>>();
            (entry, others)
        };

        let (entry, others) = entries;
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

        for other in others {
            let runtime = other.lock().await;
            if runtime.id != id
                && matches!(
                    runtime.status,
                    TunnelStatus::Starting | TunnelStatus::Running
                )
                && runtime.config.identity_key() == config_key
            {
                return Err(conflict("an identical tunnel is already running"));
            }
        }

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

        let local_args = {
            let mut runtime = entry.lock().await;
            runtime.status = TunnelStatus::Starting;
            runtime.remote_port = None;
            runtime.error = None;
            runtime.touch();
            let tunnel_name = runtime.config.name.clone();
            runtime.push_log(format!("starting tunnel {tunnel_name}"));
            runtime.shutdown_tx = Some(shutdown_tx);
            let mut local_args = LocalArgs::from(runtime.config.clone());
            local_args.max_connections = self.limits.max_active_connections;
            local_args
        };

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
        let entry = self.entry(id).await?;
        let (shutdown_tx, handle) = {
            let mut runtime = entry.lock().await;
            if runtime.locked {
                return Err(conflict("system tunnel is locked"));
            }
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
        Ok(())
    }

    pub async fn stop_tunnel_force(&self, id: &str) -> Result<(), StateError> {
        let entry = self.entry(id).await?;
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
        Ok(())
    }

    pub async fn delete_tunnel(&self, id: &str) -> Result<(), StateError> {
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
        tunnels.remove(id, &identity_key);
        drop(tunnels);
        self.persist().await;
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
        let ids = {
            let tunnels = self.tunnels.read().await;
            tunnels.entries.keys().cloned().collect::<Vec<_>>()
        };

        for id in ids {
            let _ = self.stop_tunnel_force(&id).await;
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
            locked,
            display_url,
            created_at: now.clone(),
            updated_at: now,
            shutdown_tx: None,
            handle: None,
            logs: std::collections::VecDeque::new(),
            max_log_lines: self.limits.max_log_lines,
            stats: Default::default(),
        };
        tunnels.insert(id.clone(), &config, runtime);
        drop(tunnels);
        if role == TunnelRole::User {
            self.persist().await;
        }
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
            to: "bore.pub".to_string(),
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
                display_url: Some("https://bore.pub:7836".to_string()),
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

    #[test]
    fn loopback_host_parser_accepts_known_values() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("192.168.1.10"));
    }
}
