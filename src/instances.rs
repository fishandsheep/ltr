//! Registry of running LTR instances, backing `ltr -l/--list` and
//! `ltr -s/--stop`.
//!
//! Every long-running mode (tunnel, ssh, web, console, server) writes a small
//! JSON record under `<data dir>/run/<pid>.json` once it is up, and removes it
//! on shutdown. Listing filters out records whose process is gone and deletes
//! those stale files.

// The few `unsafe` blocks below call process-liveness and pidfd syscalls; the
// crate denies `unsafe_code` everywhere else.
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
    /// Linux process start-time ticks, when available, to detect PID reuse.
    #[serde(default)]
    pub process_start: Option<u64>,
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
        let body = serde_json::to_vec_pretty(self)?;
        crate::atomic_file::write_atomic(&path, &body, Some(0o600))
            .with_context(|| format!("could not save instance record {}", path.display()))
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
            process_start: process_start(std::process::id()),
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

/// Reads Linux process start ticks (field 22 in `/proc/<pid>/stat`).
fn process_start(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit_once(')')?
            .1
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Returns true when a process with this pid exists and matches its recorded
/// start time when both are available.
pub fn alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Some(pid) = valid_pid(pid) else {
            return false;
        };
        // SAFETY: `kill` with signal 0 only probes for the process.
        let sent = unsafe { libc::kill(pid, 0) };
        if sent == 0 {
            return true;
        }
        // EPERM means the process exists but belongs to someone else.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        std::process::Command::new("tasklist")
            .args(["/FO", "CSV", "/NH", "/FI", &format!("PID eq {pid}")])
            .output()
            .is_ok_and(|output| {
                if !output.status.success() {
                    return false;
                }
                String::from_utf8_lossy(&output.stdout).lines().any(|line| {
                    line.split(',')
                        .nth(1)
                        .is_some_and(|field| field.trim_matches('"').trim() == pid.to_string())
                })
            })
    }
}

#[cfg(unix)]
fn valid_pid(pid: u32) -> Option<libc::pid_t> {
    libc::pid_t::try_from(pid).ok().filter(|pid| *pid > 0)
}

/// Returns true when a record still identifies the process using its PID.
pub fn matches_record(record: &Record) -> bool {
    if !alive(record.pid) {
        return false;
    }
    match (record.process_start, process_start(record.pid)) {
        (Some(expected), Some(actual)) => expected == actual,
        // Keep legacy records visible, but Linux signaling refuses them because
        // they cannot be safely distinguished from a reused PID.
        (None, _) => true,
        (Some(_), None) => false,
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
            Ok(record) if matches_record(&record) => records.push(record),
            _ => {
                let _ = fs::remove_file(&path);
            }
        }
    }
    records.sort_by_key(|record| (record.started_at, record.pid));
    Ok(records)
}

/// Sends SIGTERM only if the process still matches the saved record.
pub fn terminate_record(record: &Record) -> Result<()> {
    signal_record(record, terminate_signal(), send_terminate)
}

/// Sends SIGKILL only if the process still matches the saved record.
pub fn kill_record(record: &Record) -> Result<()> {
    signal_record(record, kill_signal(), send_kill)
}

/// Removes a run record only if it still belongs to the stopped process.
pub fn remove_record(record: &Record) {
    let Ok(dir) = run_dir() else { return };
    let path = dir.join(format!("{}.json", record.pid));
    let Ok(contents) = fs::read_to_string(&path) else {
        return;
    };
    if serde_json::from_str::<Record>(&contents).is_ok_and(|current| current == *record) {
        let _ = fs::remove_file(path);
    }
}

#[cfg(unix)]
const fn terminate_signal() -> std::ffi::c_int {
    libc::SIGTERM
}

#[cfg(unix)]
const fn kill_signal() -> std::ffi::c_int {
    libc::SIGKILL
}

#[cfg(not(unix))]
const fn terminate_signal() -> std::ffi::c_int {
    15
}

#[cfg(not(unix))]
const fn kill_signal() -> std::ffi::c_int {
    9
}

#[cfg(target_os = "linux")]
fn signal_record(
    record: &Record,
    signal: std::ffi::c_int,
    _fallback: fn(u32) -> Result<()>,
) -> Result<()> {
    use std::os::fd::FromRawFd;

    let expected = record
        .process_start
        .ok_or_else(|| anyhow::anyhow!("instance pid {} has no process identity", record.pid))?;
    let pid = valid_pid(record.pid)
        .ok_or_else(|| anyhow::anyhow!("invalid process id {}", record.pid))?;
    // Hold a pidfd so the signal cannot target a process that reuses this PID.
    // SAFETY: pidfd_open returns a new fd on success, owned below.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not open process handle for pid {}", record.pid));
    }
    // SAFETY: successful pidfd_open returns a unique owned file descriptor.
    let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as std::os::fd::RawFd) };
    if process_start(record.pid) != Some(expected) {
        anyhow::bail!("instance pid {} no longer matches its record", record.pid);
    }
    if !matches_record(record) {
        anyhow::bail!("instance pid {} no longer matches its record", record.pid);
    }
    // SAFETY: pidfd pins the process; passing null siginfo and flags=0 is valid.
    let sent = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            std::os::fd::AsRawFd::as_raw_fd(&pidfd),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not signal instance pid {}", record.pid));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn signal_record(
    record: &Record,
    _signal: std::ffi::c_int,
    fallback: fn(u32) -> Result<()>,
) -> Result<()> {
    if matches_record(record) {
        fallback(record.pid)
    } else {
        anyhow::bail!("instance pid {} no longer matches its record", record.pid)
    }
}

/// Sends a graceful terminate signal to a process.
pub fn send_terminate(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let pid = valid_pid(pid).ok_or_else(|| anyhow::anyhow!("invalid process id {pid}"))?;
        // SAFETY: sends SIGTERM to a validated positive pid.
        let sent = unsafe { libc::kill(pid, libc::SIGTERM) };
        if sent != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("could not terminate pid {pid}"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let status = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string()])
            .status()
            .with_context(|| format!("could not terminate pid {pid}"))?;
        if !status.success() {
            anyhow::bail!("taskkill failed to terminate pid {pid} (exit status {status})");
        }
        Ok(())
    }
}

/// Sends a force-kill signal to a process.
pub fn send_kill(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let pid = valid_pid(pid).ok_or_else(|| anyhow::anyhow!("invalid process id {pid}"))?;
        // SAFETY: sends SIGKILL to a validated positive pid.
        let sent = unsafe { libc::kill(pid, libc::SIGKILL) };
        if sent != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("could not kill pid {pid}"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let status = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .status()
            .with_context(|| format!("could not kill pid {pid}"))?;
        if !status.success() {
            anyhow::bail!("taskkill failed to kill pid {pid} (exit status {status})");
        }
        Ok(())
    }
}

/// Waits until a process exits or the deadline passes; returns whether it is
/// gone.
pub fn wait_gone(record: &Record, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if !matches_record(record) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    !matches_record(record)
}

/// Serializes tests that repoint the data directory via the environment;
/// shared with the cli test module so XDG_DATA_HOME mutation never races.
#[cfg(test)]
pub(crate) static DATA_DIR_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use std::{env, fs, time::SystemTime};

    use super::{alive, load_live, run_dir, Record};

    fn with_temp_data_dir<F: FnOnce(&std::path::Path)>(f: F) {
        let _guard = super::DATA_DIR_GUARD
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
                process_start: None,
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

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_record_without_process_identity_is_listed_but_not_signaled() {
        with_temp_data_dir(|_| {
            let live = Record {
                process_start: None,
                ..Record::new("tunnel", "127.0.0.1:8000".into(), None, None)
            };
            live.write().unwrap();
            assert_eq!(load_live().unwrap(), vec![live.clone()]);
            assert!(super::terminate_record(&live).is_err());
            Record::remove(live.pid);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mismatched_process_start_is_not_a_live_instance() {
        with_temp_data_dir(|_| {
            let live = Record::new("tunnel", "127.0.0.1:8000".into(), None, None);
            let stale = Record {
                process_start: Some(live.process_start.unwrap_or_default().wrapping_add(1)),
                ..live
            };
            assert!(!super::matches_record(&stale));
            assert!(super::terminate_record(&stale).is_err());
        });
    }
}
