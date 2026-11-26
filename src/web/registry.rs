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

    /// Remove a tunnel by id. The identity key is released only when this id owns it.
    pub(crate) fn remove(&mut self, id: &str, identity_key: &IdentityKey) {
        self.entries.remove(id);
        if self
            .identities
            .get(identity_key)
            .is_some_and(|owner| owner.as_str() == id)
        {
            self.identities.remove(identity_key);
        }
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

pub(crate) fn config_dir() -> PathBuf {
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

/// Load persisted user tunnels. A missing file yields an empty set; any other
/// read or parse failure is returned so the caller never overwrites a file it
/// could not understand.
pub(crate) fn load_persisted(path: &Path) -> std::io::Result<Vec<(String, TunnelConfig, String)>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let parsed = toml::from_str::<PersistedTunnels>(&contents)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
    Ok(parsed
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
        .collect())
}

/// Copy an unreadable or partially-invalid tunnels file aside before LTR
/// rewrites it, so no user definition is lost silently. Returns the backup path.
pub(crate) fn backup_store(path: &Path) -> std::io::Result<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or_default();
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    // The UUID keeps backups unique even when two land in the same millisecond.
    name.push(format!(".bak-{stamp}-{}", uuid::Uuid::new_v4()));
    let backup = path.with_file_name(name);
    std::fs::copy(path, &backup)?;
    Ok(backup)
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

    crate::atomic_file::write_atomic(path, contents.as_bytes(), Some(0o600))
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
        persisted_user: true,
        locked: false,
        display_url: None,
        created_at: created_at.clone(),
        updated_at: created_at,
        shutdown_tx: None,
        handle: None,
        logs: std::collections::VecDeque::new(),
        max_log_lines,
        stats: Default::default(),
        service_proto: None,
    }
}

/// Validate a persisted config before it enters the registry, using the same
/// rules as the web API for the current session mode (persistence never
/// weakens them).
pub(crate) fn validate_persisted(
    config: &TunnelConfig,
    loopback_only: bool,
) -> Result<TunnelConfig, super::session::StateError> {
    normalize_config(config.clone(), loopback_only)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> IdentityKey {
        (
            "127.0.0.1".to_string(),
            3000,
            "example.com".to_string(),
            Some(9000),
        )
    }

    #[test]
    fn remove_releases_identity_only_for_its_owner() {
        let mut registry = TunnelRegistry::default();
        registry.identities.insert(key(), "owner".to_string());

        // A stale id must not release a key that a different tunnel owns.
        registry.remove("stale", &key());
        assert_eq!(
            registry.identities.get(&key()).map(String::as_str),
            Some("owner")
        );

        registry.remove("owner", &key());
        assert!(!registry.identities.contains_key(&key()));
    }
}
