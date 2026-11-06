//! In-memory tunnel registry with TOML persistence.

#![allow(missing_docs)]

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::{
    runtime::{TunnelRole, TunnelRuntime},
    session::{
        normalize_config, now_rfc3339, PersistedTunnelConfig, TunnelConfig, TunnelKind,
        TunnelStatus,
    },
};

pub(crate) type IdentityKey = (String, u16, String, Option<u16>);

#[derive(Default)]
pub(crate) struct TunnelRegistry {
    pub(crate) entries: HashMap<String, Arc<Mutex<TunnelRuntime>>>,
    pub(crate) identities: HashMap<IdentityKey, String>,
}

impl TunnelRegistry {
    /// Insert a runtime under its id and identity key.
    pub(crate) fn insert(
        &mut self,
        id: String,
        config: &TunnelConfig,
        runtime: TunnelRuntime,
    ) -> Arc<Mutex<TunnelRuntime>> {
        self.identities.insert(config.identity_key(), id.clone());
        let entry = Arc::new(Mutex::new(runtime));
        self.entries.insert(id, Arc::clone(&entry));
        entry
    }

    /// Remove a tunnel by id, returning whether the identity key matched.
    pub(crate) fn remove(&mut self, id: &str, identity_key: &IdentityKey) -> bool {
        self.entries.remove(id);
        self.identities.remove(identity_key).is_some()
    }
}

/// On-disk document for the persisted tunnel set.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedTunnels {
    #[serde(default)]
    tunnels: Vec<PersistedEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedEntry {
    id: String,
    created_at: String,
    #[serde(flatten)]
    config: PersistedTunnelConfig,
}

/// Resolve the default tunnels config path in the user config directory.
pub fn default_tunnels_path() -> PathBuf {
    config_dir().join("tunnels.toml")
}

fn config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("APPDATA"));

    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join("Library/Application Support")
            .into_os_string()
    });

    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_CONFIG_HOME").or_else(|| {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config").into_os_string())
    });

    base.map(|base| PathBuf::from(base).join("ltr"))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Load persisted user tunnels; system tunnels and invalid entries are
/// skipped. Missing or unreadable files yield an empty set.
pub(crate) fn load_persisted(path: &Path) -> Vec<(String, TunnelConfig, String)> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(parsed) = toml::from_str::<PersistedTunnels>(&contents) else {
        return Vec::new();
    };
    parsed
        .tunnels
        .into_iter()
        .map(|entry| {
            let created_at = if entry.created_at.is_empty() {
                now_rfc3339()
            } else {
                entry.created_at
            };
            (entry.id, TunnelConfig::from(entry.config), created_at)
        })
        .collect()
}

/// Atomically persist user tunnels (tmp file + rename, 0600 permissions).
/// Secrets are stored on disk in the same trust model as SSH keys; they stay
/// redacted in every other surface.
pub(crate) fn save_persisted(
    path: &Path,
    tunnels: &[(String, TunnelConfig, String)],
) -> std::io::Result<()> {
    let doc = PersistedTunnels {
        tunnels: tunnels
            .iter()
            .map(|(id, config, created_at)| PersistedEntry {
                id: id.clone(),
                created_at: created_at.clone(),
                config: config.persisted(),
            })
            .collect(),
    };
    let contents =
        toml::to_string_pretty(&doc).map_err(|err| std::io::Error::other(err.to_string()))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension("toml.tmp");
    write_private(&tmp, contents.as_bytes())?;
    std::fs::rename(&tmp, path)
}

fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, contents)
}

/// Rehydrate a persisted user tunnel as a fresh runtime.
pub(crate) fn runtime_from_persisted(
    id: String,
    config: TunnelConfig,
    created_at: String,
    max_log_lines: usize,
) -> TunnelRuntime {
    TunnelRuntime {
        id,
        config,
        status: TunnelStatus::Stopped,
        remote_port: None,
        error: None,
        kind: TunnelKind::User,
        role: TunnelRole::User,
        locked: false,
        display_url: None,
        created_at: created_at.clone(),
        updated_at: created_at,
        shutdown_tx: None,
        handle: None,
        logs: std::collections::VecDeque::new(),
        max_log_lines,
        stats: Default::default(),
    }
}

/// Validate a persisted config before it enters the registry, using the same
/// rules as the web API (persistence never weakens them).
pub(crate) fn validate_persisted(
    config: &TunnelConfig,
) -> Result<TunnelConfig, super::session::StateError> {
    normalize_config(config.clone(), false)
}
