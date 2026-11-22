//! Background (daemon) execution for the LTR CLI.
//!
//! By default every LTR command detaches from the terminal: the process
//! re-executes itself in a new session, pipes its startup output back so the
//! terminal still shows it, and then keeps running with its logs appended to a
//! per-command log file. Passing `--front` (or setting `LTR_FRONT`) keeps the
//! classic foreground behaviour instead.
//!
//! The parent side of the handshake lives in [`spawn_and_wait`]; the child side
//! in [`finish`]. On platforms without Unix session support background mode is
//! never entered and [`finish`] is a no-op.

// The two `unsafe` blocks below are the only unsafe code in this crate (the
// crate denies `unsafe_code` everywhere else): they call `setsid(2)` in the
// freshly forked child before exec and `dup2(2)`/`chdir(2)` on plain file
// descriptors at the ready point.
#![allow(unsafe_code)]

use std::{
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    thread,
};

use anyhow::{Context, Result};
use tracing_subscriber::fmt::MakeWriter;

use crate::cli::Command;

/// Environment variable marking the re-executed background child process.
pub(crate) const CHILD_ENV: &str = "LTR_DAEMON_CHILD";

/// Environment variable carrying the background child's log file path.
pub(crate) const LOG_ENV: &str = "LTR_DAEMON_LOG";

/// Line the child prints once it reaches its ready point. The parent stops
/// echoing and exits as soon as it sees it, so it never reaches the terminal.
const READY_MARKER: &str = "__LTR_DAEMON_READY__";

/// Returns true when running as the re-executed background child process.
pub fn is_child() -> bool {
    env::var_os(CHILD_ENV).as_deref() == Some(std::ffi::OsStr::new("1"))
}

/// Returns the log file a command appends to while in the background.
pub fn log_path(command: &str) -> Result<PathBuf> {
    let dir = crate::web::credentials::data_dir()?
        .join("logs")
        .join(format!("{command}.log"));
    Ok(dir)
}

/// Returns the log file path inherited from the parent process.
pub fn child_log_path() -> Result<PathBuf> {
    env::var_os(LOG_ENV)
        .map(PathBuf::from)
        .with_context(|| format!("background child is missing {LOG_ENV}"))
}

/// Maps a parsed command to its background log file name.
pub fn command_log_name(command: &Option<Command>) -> &'static str {
    match command {
        None => "web",
        Some(Command::Local(_)) => "local",
        Some(Command::Bundle(_)) => "bundle",
        Some(Command::Server(_)) => "server",
    }
}

/// Appending file writer used by the background child for tracing logs.
#[derive(Clone)]
pub struct LogFileWriter {
    file: Arc<Mutex<fs::File>>,
}

impl LogFileWriter {
    /// Opens (creating if needed) a log file in append mode.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("could not create log directory {}", parent.display()))?;
        }
        let mut options = fs::OpenOptions::new();
        options.append(true).create(true).read(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .with_context(|| format!("could not open log file {}", path.display()))?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }
}

/// Cloned handle through which one log line is written.
pub struct LogFileGuard(Arc<Mutex<fs::File>>);

impl std::io::Write for LogFileGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("log file lock should not be poisoned")
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .expect("log file lock should not be poisoned")
            .flush()
    }
}

impl<'a> MakeWriter<'a> for LogFileWriter {
    type Writer = LogFileGuard;

    fn make_writer(&'a self) -> Self::Writer {
        LogFileGuard(Arc::clone(&self.file))
    }
}

/// Watches a ready signal and prints the background summary when it fires.
///
/// The spawned task is a no-op unless the process is the background child.
pub fn spawn_finish(ready: tokio::sync::oneshot::Receiver<Vec<String>>) {
    tokio::spawn(async move {
        if let Ok(extra_lines) = ready.await {
            finish(&extra_lines);
        }
    });
}

/// Prints the background summary and detaches the child from the terminal.
///
/// No-op in foreground mode. `extra_lines` are printed first so each command
/// can surface its mode-specific endpoint information.
pub fn finish(extra_lines: &[String]) {
    if !is_child() {
        return;
    }
    for line in extra_lines {
        println!("{line}");
    }
    let pid = std::process::id();
    if let Some(path) = env::var_os(LOG_ENV) {
        println!("LTR running in background (pid {pid})");
        println!("Logs: {}", PathBuf::from(path).display());
        println!("Stop: kill {pid}");
    }
    println!("{READY_MARKER}");
    let _ = std::io::stdout().flush();
    #[cfg(unix)]
    detach_stdio();
}

/// Replaces stdin/stdout/stderr with `/dev/null` and releases the old cwd so
/// the detached child no longer holds on to the user's terminal.
#[cfg(unix)]
fn detach_stdio() {
    // SAFETY: `open`, `dup2`, and `chdir` operate on plain file descriptors
    // and C strings owned by this call; none of them touch Rust-managed state.
    unsafe {
        let devnull = c"/dev/null".to_bytes().as_ptr().cast();
        let fd = libc::open(devnull, libc::O_RDWR);
        if fd >= 0 {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            if fd > 2 {
                libc::close(fd);
            }
        }
        let root = c"/".to_bytes().as_ptr().cast();
        libc::chdir(root);
    }
}

/// Signal sent from the pipe reader thread to the waiting parent.
#[cfg(unix)]
enum ChildSignal {
    /// The child printed the ready marker.
    Ready,
}

/// Re-executes the current binary as a detached background child and waits
/// until it reports readiness, then exits the parent with status 0.
///
/// The child's startup output is echoed to this terminal; if the child exits
/// before reporting readiness its exit status is propagated. Interrupting the
/// wait (Ctrl-C) kills the child.
#[cfg(unix)]
pub async fn spawn_and_wait(command: &Option<Command>) -> ! {
    let name = command_log_name(command);
    let log_path = match log_path(name).and_then(|path| LogFileWriter::open(&path).map(|_| path)) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("LTR could not prepare the background log file: {err:#}");
            std::process::exit(1);
        }
    };

    let exe = match env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            eprintln!("LTR could not locate its own executable: {err:#}");
            std::process::exit(1);
        }
    };

    use std::os::unix::process::CommandExt;

    let mut cmd = std::process::Command::new(exe);
    cmd.args(env::args_os().skip(1))
        .env(CHILD_ENV, "1")
        .env(LOG_ENV, &log_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the closure only calls `setsid(2)` in the freshly forked child
    // before exec, where it is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!("LTR could not start the background process: {err:#}");
            std::process::exit(1);
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (signal_tx, signal_rx) = std::sync::mpsc::channel::<ChildSignal>();
    if let Some(stdout) = stdout {
        let signal_tx = signal_tx.clone();
        thread::spawn(move || echo_pipe(stdout, std::io::stdout(), Some(signal_tx)));
    }
    if let Some(stderr) = stderr {
        thread::spawn(move || echo_pipe(stderr, std::io::stderr(), None));
    }
    drop(signal_tx);

    let decision =
        tokio::task::spawn_blocking(move || matches!(signal_rx.recv(), Ok(ChildSignal::Ready)));

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            let _ = child.kill();
            let _ = child.wait();
            std::process::exit(130);
        }
        ready = decision => {
            if ready.is_ok_and(|ready| ready) {
                std::process::exit(0);
            }
            let code = child
                .wait()
                .ok()
                .and_then(|status| status.code())
                .unwrap_or(1);
            std::process::exit(code);
        }
    }
}

/// Echoes one pipe to a writer, stopping (and signalling readiness) at the
/// marker line.
#[cfg(unix)]
fn echo_pipe<R, W>(input: R, mut target: W, signal: Option<std::sync::mpsc::Sender<ChildSignal>>)
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let mut reader = BufReader::new(input);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if line.trim_ascii() == READY_MARKER.as_bytes() {
            if let Some(signal) = signal {
                let _ = signal.send(ChildSignal::Ready);
            }
            return;
        }
        let _ = target.write_all(&line);
        let _ = target.flush();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{command_log_name, log_path, READY_MARKER};
    use crate::cli::Args;
    use clap::Parser;

    #[test]
    fn marker_is_private_and_stable() {
        assert_eq!(READY_MARKER, "__LTR_DAEMON_READY__");
    }

    #[test]
    fn command_log_name_covers_all_modes() {
        assert_eq!(command_log_name(&None), "web");
        for (argv, expected) in [
            (vec!["ltr", "local", "8000", "--to", "h"], "local"),
            (vec!["ltr", "bundle", "--to", "h"], "bundle"),
            (vec!["ltr", "server"], "server"),
        ] {
            let args = Args::try_parse_from(argv).expect("parse should succeed");
            assert_eq!(command_log_name(&args.command), expected);
        }
    }

    #[test]
    fn log_path_lands_in_logs_directory() {
        let path = log_path("server").expect("log path should resolve");
        assert!(path.ends_with("logs/server.log"));
    }
}
