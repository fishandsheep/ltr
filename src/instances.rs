//! Registry of running LTR instances, backing `ltr -l/--list` and
//! `ltr -s/--stop`.
//!
//! Every long-running mode (tunnel, ssh, web, console, server) writes a small
//! JSON record under `<data dir>/run/<pid>.json` once it is up, and removes it
//! on shutdown. Listing filters out records whose process is gone and deletes
//! those stale files.

// The few `unsafe` blocks below call `kill(2)` on numeric pids; the crate
// denies `unsafe_code` everywhere else.
#![allow(unsafe_code)]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::web::credentials::data_dir;

/// One running instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    /// OS process id of the instance.
    pub pid: u32,
    /// Instance kind: tunnel, ssh, web, console, or server.
    pub kind: String,
    /// Local endpoint it serves or forwards, as host:port.
    pub local: String,
    /// Remote endpoint exposed through the relay, when assigned.
    pub remote: Option<String>,
    /// Remote relay server, when used.
    pub to: Option<String>,
    /// Unix seconds when the instance started.
    pub started_at: u64,
}

/// Returns the directory holding instance records.
pub fn run_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("run"))
}

impl Record {
    /// Writes the record atomically with 0600 permissions.
    pub fn write(&self) -> Result<()> {
        let dir = run_dir()?;
        fs::create_dir_all(&dir)
            .with_context(|| format!("could not create run directory {}", dir.display()))?;
        let path = dir.join(format!("{}.json", self.pid));
        let tmp = dir.join(format!("{}.json.tmp", self.pid));
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("could not create {}", tmp.display()))?;
            let body = serde_json::to_string_pretty(self)?;
            file.write_all(body.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            let body = serde_json::to_string_pretty(self)?;
            std::fs::write(&tmp, body.as_bytes())
                .with_context(|| format!("could not create {}", tmp.display()))?;
        }
        fs::rename(&tmp, &path).with_context(|| format!("could not replace {}", path.display()))?;
        Ok(())
    }

    /// Removes the record for a pid, if present.
    pub fn remove(pid: u32) {
        let _ = fs::remove_file(
            run_dir()
                .ok()
                .map(|dir| dir.join(format!("{pid}.json")))
                .unwrap_or_default(),
        );
    }

    /// Creates a record stamped with the current time.
    pub fn new(kind: &str, local: String, remote: Option<String>, to: Option<String>) -> Self {
        Self {
            pid: std::process::id(),
            kind: kind.to_string(),
            local,
            remote,
            to,
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }
}

/// Returns true when a process with this pid exists.
pub fn alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `kill` with signal 0 only probes for the process.
        let sent = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if sent == 0 {
            return true;
        }
        // EPERM means the process exists but belongs to someone else.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Loads live instance records, deleting stale files for dead pids. Records
/// are ordered by start time.
pub fn load_live() -> Result<Vec<Record>> {
    let dir = run_dir()?;
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("could not read {}", dir.display())),
    };
    let mut records = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        match serde_json::from_str::<Record>(&raw) {
            Ok(record) if alive(record.pid) => records.push(record),
            _ => {
                let _ = fs::remove_file(&path);
            }
        }
    }
    records.sort_by_key(|record| (record.started_at, record.pid));
    Ok(records)
}

/// Sends a graceful terminate signal to a process.
pub fn send_terminate(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: sends SIGTERM to a numeric pid.
        let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if sent != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("could not terminate pid {pid}"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string()])
            .status()
            .with_context(|| format!("could not terminate pid {pid}"))?;
        Ok(())
    }
}

/// Sends a force-kill signal to a process.
pub fn send_kill(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: sends SIGKILL to a numeric pid.
        let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if sent != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("could not kill pid {pid}"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .status()
            .with_context(|| format!("could not kill pid {pid}"))?;
        Ok(())
    }
}

/// Waits until a process exits or the deadline passes; returns whether it is
/// gone.
pub fn wait_gone(pid: u32, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    !alive(pid)
}

#[cfg(test)]
mod tests {
    use std::{env, fs, sync::Mutex, time::SystemTime};

    use super::{alive, load_live, run_dir, Record};

    /// Serializes tests that repoint the data directory via the environment.
    static DATA_DIR_GUARD: Mutex<()> = Mutex::new(());

    fn with_temp_data_dir<F: FnOnce(&std::path::Path)>(f: F) {
        let _guard = DATA_DIR_GUARD
            .lock()
            .expect("data dir lock should not be poisoned");
        let old = env::var_os("XDG_DATA_HOME");
        let root = std::env::temp_dir().join(format!(
            "ltr-instances-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        env::set_var("XDG_DATA_HOME", &root);
        f(&root);
        match old {
            Some(value) => env::set_var("XDG_DATA_HOME", value),
            None => env::remove_var("XDG_DATA_HOME"),
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn record_round_trip_and_stale_cleanup() {
        with_temp_data_dir(|_root| {
            let live = Record::new(
                "tunnel",
                "127.0.0.1:8000".into(),
                Some("h:9000".into()),
                Some("h".into()),
            );
            live.write().unwrap();
            // Own pid is alive.
            assert!(alive(live.pid));

            // A record for a pid that cannot exist is filtered and deleted.
            let dead_pid = 4_000_000;
            let dead = Record {
                pid: dead_pid,
                ..live.clone()
            };
            dead.write().unwrap();
            let records = load_live().unwrap();
            assert_eq!(records, vec![live.clone()]);
            assert!(!run_dir().unwrap().join(format!("{dead_pid}.json")).exists());

            Record::remove(live.pid);
            assert!(load_live().unwrap().is_empty());
        });
    }
}
