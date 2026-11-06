//! Per-tunnel runtime: status, events, logs, and run-argument conversion.

#![allow(missing_docs)]

use std::collections::VecDeque;

use tokio::{sync::oneshot, task::JoinHandle};

use crate::client::{LocalArgs, TunnelEvent, TunnelStatsSnapshot, DEFAULT_MAX_ACTIVE_CONNECTIONS};

use super::session::{
    now_rfc3339, SystemTunnelRole, TunnelConfig, TunnelInfo, TunnelKind, TunnelStatus,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TunnelRole {
    User,
    WebConsole,
    Ssh,
}

impl From<SystemTunnelRole> for TunnelRole {
    fn from(value: SystemTunnelRole) -> Self {
        match value {
            SystemTunnelRole::WebConsole => TunnelRole::WebConsole,
            SystemTunnelRole::Ssh => TunnelRole::Ssh,
        }
    }
}

#[derive(Debug)]
pub(crate) struct TunnelRuntime {
    pub(crate) id: String,
    pub(crate) config: TunnelConfig,
    pub(crate) status: TunnelStatus,
    pub(crate) remote_port: Option<u16>,
    pub(crate) error: Option<String>,
    pub(crate) kind: TunnelKind,
    pub(crate) role: TunnelRole,
    pub(crate) locked: bool,
    pub(crate) display_url: Option<String>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) shutdown_tx: Option<oneshot::Sender<()>>,
    pub(crate) handle: Option<JoinHandle<()>>,
    pub(crate) logs: VecDeque<String>,
    pub(crate) max_log_lines: usize,
    pub(crate) stats: TunnelStatsSnapshot,
}

impl TunnelRuntime {
    pub(crate) fn view(&self) -> TunnelInfo {
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
            stats: self.stats,
        }
    }

    pub(crate) fn apply_event(&mut self, event: TunnelEvent) -> Option<(TunnelRole, String, u16)> {
        match event {
            TunnelEvent::Log(message) => {
                self.push_log(message);
                None
            }
            TunnelEvent::Stats(stats) => {
                self.stats = stats;
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

    pub(crate) fn push_log(&mut self, message: String) {
        self.logs.push_back(message);
        while self.logs.len() > self.max_log_lines {
            self.logs.pop_front();
        }
        self.updated_at = now_rfc3339();
    }

    pub(crate) fn touch(&mut self) {
        self.updated_at = now_rfc3339();
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
            no_tls: false,
            tls_ca: None,
            tls_fingerprint: None,
            tls_server_name: None,
            tls_client_cert: None,
            tls_client_key: None,
            max_connections: DEFAULT_MAX_ACTIVE_CONNECTIONS,
        }
    }
}
