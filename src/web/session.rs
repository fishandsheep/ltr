//! Web console data types shared across the state layer and the HTTP API.

#![allow(missing_docs)]

use std::{fmt, net::IpAddr, str::FromStr};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::client::{TunnelStatsSnapshot, DEFAULT_MAX_ACTIVE_CONNECTIONS};

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
    pub(crate) fn normalized(self) -> Self {
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

impl TunnelConfig {
    pub(crate) fn public(&self) -> PublicTunnelConfig {
        PublicTunnelConfig {
            name: self.name.clone(),
            local_port: self.local_port,
            to: self.to.clone(),
            port: self.port,
            local_host: self.local_host.clone(),
        }
    }

    /// Stable identity of a tunnel definition, ignoring name and secret.
    pub(crate) fn identity_key(&self) -> (String, u16, String, Option<u16>) {
        (
            self.local_host.clone(),
            self.local_port,
            self.to.clone(),
            self.port,
        )
    }

    /// Serialize for persistence; the secret is stored on disk (0600) but is
    /// redacted from every other surface.
    pub(crate) fn persisted(&self) -> PersistedTunnelConfig {
        PersistedTunnelConfig {
            name: self.name.clone(),
            local_port: self.local_port,
            to: self.to.clone(),
            port: self.port,
            local_host: self.local_host.clone(),
            secret: self.secret.clone(),
        }
    }
}

/// On-disk shape of a tunnel definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedTunnelConfig {
    pub name: String,
    pub local_port: u16,
    pub to: String,
    pub port: Option<u16>,
    pub local_host: String,
    pub secret: Option<String>,
}

impl From<PersistedTunnelConfig> for TunnelConfig {
    fn from(value: PersistedTunnelConfig) -> Self {
        Self {
            name: value.name,
            local_port: value.local_port,
            to: value.to,
            port: value.port,
            local_host: value.local_host,
            secret: value.secret,
        }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_proto: Option<ServiceProto>,
    pub stats: TunnelStatsSnapshot,
}

/// Protocol a tunneled local service was fingerprinted as speaking.
///
/// Detected best-effort by the console after a tunnel starts; used by the
/// web UI to display the protocol and only link what a browser can open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProto {
    Http,
    Https,
    Ssh,
    Tcp,
}

impl std::fmt::Display for ServiceProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ServiceProto::Http => "http",
            ServiceProto::Https => "https",
            ServiceProto::Ssh => "ssh",
            ServiceProto::Tcp => "tcp",
        })
    }
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

pub(crate) fn bad_request(message: impl Into<String>) -> StateError {
    StateError {
        status: StatusCode::BAD_REQUEST,
        message: message.into(),
    }
}

pub(crate) fn not_found(message: impl Into<String>) -> StateError {
    StateError {
        status: StatusCode::NOT_FOUND,
        message: message.into(),
    }
}

pub(crate) fn conflict(message: impl Into<String>) -> StateError {
    StateError {
        status: StatusCode::CONFLICT,
        message: message.into(),
    }
}

pub(crate) fn normalize_config(
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

/// True when the host resolves to a loopback address literal.
pub fn is_loopback_host(host: &str) -> bool {
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return true;
    }

    IpAddr::from_str(host)
        .map(|addr| addr.is_loopback())
        .unwrap_or(false)
}

pub(crate) fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
