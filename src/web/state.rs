#![allow(missing_docs)]

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::IpAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::{
    sync::{mpsc, oneshot, Mutex, RwLock},
    task::JoinHandle,
    time::sleep,
};
use uuid::Uuid;

use crate::client::{run_local, LocalArgs, TunnelEvent, DEFAULT_MAX_ACTIVE_CONNECTIONS};

const POLL_DELAY: Duration = Duration::from_millis(50);
type IdentityKey = (String, u16, String, Option<u16>);

#[derive(Default)]
struct TunnelRegistry {
    entries: HashMap<String, Arc<Mutex<TunnelRuntime>>>,
    identities: HashMap<IdentityKey, String>,
}

/// Default maximum number of tunnel definitions held by the Web control plane.
pub const DEFAULT_MAX_TUNNELS: usize = 64;

/// Default maximum number of retained log lines per tunnel.
pub const DEFAULT_MAX_LOG_LINES: usize = 500;

/// Resource limits for the in-memory Web control plane.
#[derive(Debug, Clone, Copy)]
pub struct WebLimits {
    pub max_tunnels: usize,
    pub max_active_connections: usize,
    pub max_log_lines: usize,
}

impl Default for WebLimits {
    fn default() -> Self {
        Self {
            max_tunnels: DEFAULT_MAX_TUNNELS,
            max_active_connections: DEFAULT_MAX_ACTIVE_CONNECTIONS,
            max_log_lines: DEFAULT_MAX_LOG_LINES,
        }
    }
}

impl WebLimits {
    fn normalized(self) -> Self {
        Self {
            max_tunnels: self.max_tunnels.max(1),
            max_active_connections: self.max_active_connections.max(1),
            max_log_lines: self.max_log_lines.max(1),
        }
    }
}

/// Tunnel configuration accepted by the web API.
#[derive(Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub name: String,
    pub local_port: u16,
    pub to: String,
    pub port: Option<u16>,
    pub local_host: String,
    pub secret: Option<String>,
}

impl fmt::Debug for TunnelConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelConfig")
            .field("name", &self.name)
            .field("local_port", &self.local_port)
            .field("to", &self.to)
            .field("port", &self.port)
            .field("local_host", &self.local_host)
            .field("secret", &self.secret.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Public tunnel configuration returned by the web API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTunnelConfig {
    pub name: String,
    pub local_port: u16,
    pub to: String,
    pub port: Option<u16>,
    pub local_host: String,
}

/// Tunnel lifecycle state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TunnelStatus {
    Stopped,
    Starting,
    Running,
    Failed,
}

/// Public tunnel class.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TunnelKind {
    User,
    System,
}

/// Web console runtime mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionMode {
    Local,
    RemoteWeb,
    Home,
}

/// Session metadata returned by the web API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub mode: SessionMode,
    pub warnings: Vec<String>,
    pub loopback_only: bool,
    pub web_remote_url: Option<String>,
    pub ssh_remote_endpoint: Option<String>,
}

impl SessionInfo {
    pub fn local() -> Self {
        Self {
            mode: SessionMode::Local,
            warnings: Vec::new(),
            loopback_only: false,
            web_remote_url: None,
            ssh_remote_endpoint: None,
        }
    }
}

/// Tunnel information returned by the web API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
    pub id: String,
    pub config: PublicTunnelConfig,
    pub status: TunnelStatus,
    pub remote_port: Option<u16>,
    pub error: Option<String>,
    pub has_secret: bool,
    pub kind: TunnelKind,
    pub locked: bool,
    pub display_url: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Static spec for system tunnels.
#[derive(Debug, Clone)]
pub struct SystemTunnelSpec {
    pub role: SystemTunnelRole,
    pub config: TunnelConfig,
    pub display_url: Option<String>,
}

/// Predefined system tunnel roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemTunnelRole {
    WebConsole,
    Ssh,
}

/// Shared web state.
#[derive(Clone)]
pub struct WebState {
    tunnels: Arc<RwLock<TunnelRegistry>>,
    session: Arc<RwLock<SessionInfo>>,
    web_token: Arc<Option<String>>,
    web_tls: Arc<Option<WebTlsConfig>>,
    limits: Arc<WebLimits>,
}

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

/// Structured state-layer error for HTTP mapping.
#[derive(Debug, Clone)]
pub struct StateError {
    pub status: StatusCode,
    pub message: String,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for StateError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelRole {
    User,
    WebConsole,
    Ssh,
}

#[derive(Debug)]
struct TunnelRuntime {
    id: String,
    config: TunnelConfig,
    status: TunnelStatus,
    remote_port: Option<u16>,
    error: Option<String>,
    kind: TunnelKind,
    role: TunnelRole,
    locked: bool,
    display_url: Option<String>,
    created_at: String,
    updated_at: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
    logs: VecDeque<String>,
    max_log_lines: usize,
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
        Self {
            tunnels: Arc::new(RwLock::new(TunnelRegistry::default())),
            session: Arc::new(RwLock::new(session)),
            web_token: Arc::new(web_token),
            web_tls: Arc::new(web_tls),
            limits: Arc::new(limits.normalized()),
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
            runtime.push_log(format!("starting tunnel {}", tunnel_name));
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
        tunnels.entries.remove(id);
        tunnels.identities.remove(&identity_key);
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

        let now = now_rfc3339();
        let id = Uuid::new_v4().to_string();
        let runtime = TunnelRuntime {
            id: id.clone(),
            config,
            status: TunnelStatus::Stopped,
            remote_port: None,
            error: None,
            kind: if role == TunnelRole::User {
                TunnelKind::User
            } else {
                TunnelKind::System
            },
            role,
            locked,
            display_url,
            created_at: now.clone(),
            updated_at: now,
            shutdown_tx: None,
            handle: None,
            logs: VecDeque::new(),
            max_log_lines: self.limits.max_log_lines,
        };
        tunnels.identities.insert(config_key, id.clone());
        tunnels
            .entries
            .insert(id.clone(), Arc::new(Mutex::new(runtime)));
        Ok(id)
    }

    async fn entry(&self, id: &str) -> Result<Arc<Mutex<TunnelRuntime>>, StateError> {
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

impl TunnelRuntime {
    fn view(&self) -> TunnelInfo {
        TunnelInfo {
            id: self.id.clone(),
            config: self.config.public(),
            status: self.status,
            remote_port: self.remote_port,
            error: self.error.clone(),
            has_secret: self.config.secret.is_some(),
            kind: self.kind,
            locked: self.locked,
            display_url: self.display_url.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }

    fn apply_event(&mut self, event: TunnelEvent) -> Option<(TunnelRole, String, u16)> {
        match event {
            TunnelEvent::Log(message) => {
                self.push_log(message);
                None
            }
            TunnelEvent::Started { remote_port } => {
                self.status = TunnelStatus::Running;
                self.remote_port = remote_port;
                self.error = None;
                self.touch();
                if let Some(remote_port) = remote_port {
                    self.push_log(format!("remote port assigned: {remote_port}"));
                }
                remote_port.and_then(|remote_port| {
                    (self.role != TunnelRole::User)
                        .then(|| (self.role, self.config.to.clone(), remote_port))
                })
            }
            TunnelEvent::Stopped => {
                self.status = TunnelStatus::Stopped;
                self.shutdown_tx = None;
                self.touch();
                self.push_log("tunnel stopped".to_string());
                None
            }
            TunnelEvent::Failed(message) => {
                self.status = TunnelStatus::Failed;
                self.remote_port = None;
                self.error = Some(message.clone());
                self.shutdown_tx = None;
                self.touch();
                self.push_log(format!("error: {message}"));
                None
            }
        }
    }

    fn push_log(&mut self, message: String) {
        self.logs.push_back(message);
        while self.logs.len() > self.max_log_lines {
            self.logs.pop_front();
        }
        self.updated_at = now_rfc3339();
    }

    fn touch(&mut self) {
        self.updated_at = now_rfc3339();
    }
}

impl TunnelConfig {
    fn public(&self) -> PublicTunnelConfig {
        PublicTunnelConfig {
            name: self.name.clone(),
            local_port: self.local_port,
            to: self.to.clone(),
            port: self.port,
            local_host: self.local_host.clone(),
        }
    }

    fn identity_key(&self) -> (String, u16, String, Option<u16>) {
        (
            self.local_host.clone(),
            self.local_port,
            self.to.clone(),
            self.port,
        )
    }
}

impl From<TunnelConfig> for LocalArgs {
    fn from(value: TunnelConfig) -> Self {
        Self {
            local_port: value.local_port,
            local_host: value.local_host,
            to: value.to,
            port: value.port.unwrap_or(0),
            secret: value.secret,
            tls: false,
            tls_ca: None,
            tls_fingerprint: None,
            tls_server_name: None,
            tls_client_cert: None,
            tls_client_key: None,
            max_connections: DEFAULT_MAX_ACTIVE_CONNECTIONS,
        }
    }
}

impl From<SystemTunnelRole> for TunnelRole {
    fn from(value: SystemTunnelRole) -> Self {
        match value {
            SystemTunnelRole::WebConsole => TunnelRole::WebConsole,
            SystemTunnelRole::Ssh => TunnelRole::Ssh,
        }
    }
}

fn normalize_config(
    mut config: TunnelConfig,
    loopback_only: bool,
) -> Result<TunnelConfig, StateError> {
    config.name = config.name.trim().to_string();
    config.to = config.to.trim().to_string();
    config.local_host = config.local_host.trim().to_string();
    config.secret = config
        .secret
        .as_ref()
        .map(|secret| secret.trim().to_string())
        .filter(|secret| !secret.is_empty());

    if config.name.is_empty() {
        return Err(bad_request("name cannot be empty"));
    }
    if config.local_port == 0 {
        return Err(bad_request("local_port must be a valid port"));
    }
    if config.to.is_empty() {
        return Err(bad_request("to cannot be empty"));
    }
    if config.local_host.is_empty() {
        return Err(bad_request("local_host cannot be empty"));
    }
    if loopback_only && !is_loopback_host(&config.local_host) {
        return Err(bad_request(
            "remote web mode only allows loopback local_host targets",
        ));
    }
    if matches!(config.port, Some(0)) {
        return Err(bad_request("port must be a valid port"));
    }

    Ok(config)
}

pub fn is_loopback_host(host: &str) -> bool {
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return true;
    }

    IpAddr::from_str(host)
        .map(|addr| addr.is_loopback())
        .unwrap_or(false)
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn bad_request(message: impl Into<String>) -> StateError {
    StateError {
        status: StatusCode::BAD_REQUEST,
        message: message.into(),
    }
}

fn not_found(message: impl Into<String>) -> StateError {
    StateError {
        status: StatusCode::NOT_FOUND,
        message: message.into(),
    }
}

fn conflict(message: impl Into<String>) -> StateError {
    StateError {
        status: StatusCode::CONFLICT,
        message: message.into(),
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

    #[test]
    fn loopback_host_parser_accepts_known_values() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("192.168.1.10"));
    }
}
