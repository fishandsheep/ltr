//! End-to-end tests for `--front` and default background execution, driving
//! the compiled `ltr` binary directly.

#![cfg(unix)]

use std::{
    io::{BufRead, BufReader},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

/// Spawns the ltr binary with isolated XDG/HOME state and piped output.
fn spawn_ltr(args: &[&str], root: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ltr"))
        .args(args)
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("HOME", root)
        .env_remove("LTR_FRONT")
        .env_remove("LTR_DAEMON_CHILD")
        .env_remove("LTR_DAEMON_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ltr binary should spawn")
}

/// Reads stdout lines through a channel so expectations can time out instead
/// of hanging the test suite.
fn line_reader(child: &mut Child) -> mpsc::Receiver<String> {
    let stdout = child.stdout.take().expect("stdout should be piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    rx
}

fn recv_line(rx: &mpsc::Receiver<String>) -> String {
    rx.recv_timeout(Duration::from_secs(15))
        .expect("stdout line should arrive within timeout")
}

fn wait_for_connect(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("nothing listened on {addr}");
}

fn wait_for_refused(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{addr} should have stopped listening");
}

/// Parses the web console port out of the listening line.
fn web_port_from(line: &str) -> String {
    let port = line
        .rsplit(':')
        .next()
        .expect("listening line should carry the port");
    format!("127.0.0.1:{port}")
}

#[test]
fn front_mode_stays_in_foreground() {
    let root = std::env::temp_dir().join(format!(
        "ltr-front-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let mut child = spawn_ltr(&["--front", "--web-addr", "127.0.0.1:0"], &root);
    let rx = line_reader(&mut child);

    let line = recv_line(&rx);
    assert!(line.starts_with("LTR web console listening on http://"));
    let addr = web_port_from(&line);
    wait_for_connect(&addr);

    // No daemon summary in front mode, and the process keeps running.
    assert!(rx.try_recv().is_err());
    assert!(child.try_wait().unwrap().is_none());

    child.kill().unwrap();
    child.wait().unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn default_mode_backgrounds_after_summary() {
    let root = std::env::temp_dir().join(format!(
        "ltr-daemon-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let mut child = spawn_ltr(&["--web-addr", "127.0.0.1:0"], &root);
    let rx = line_reader(&mut child);

    let line = recv_line(&rx);
    assert!(line.starts_with("LTR web console listening on http://"));
    let addr = web_port_from(&line);

    let summary = recv_line(&rx);
    let pid: u32 = summary
        .strip_prefix("LTR running in background (pid ")
        .and_then(|rest| rest.strip_suffix(')'))
        .and_then(|pid| pid.parse().ok())
        .expect("summary should report the background pid");

    let logs = recv_line(&rx);
    let log_path = std::path::PathBuf::from(
        logs.strip_prefix("Logs: ")
            .expect("summary should report the log path"),
    );
    assert!(log_path.ends_with("logs/web.log"));

    let stop = recv_line(&rx);
    assert_eq!(stop, format!("Stop: kill {pid}"));

    // The marker never leaks to the terminal and the parent exits cleanly.
    assert!(rx.recv_timeout(Duration::from_secs(10)).is_err());
    let status = child.wait().unwrap();
    assert!(status.success());

    // The background child keeps serving and writes its logs to the file.
    wait_for_connect(&addr);
    assert!(log_path.exists());

    Command::new("kill")
        .arg(pid.to_string())
        .status()
        .expect("kill should run");
    wait_for_refused(&addr);
    let _ = std::fs::remove_dir_all(&root);
}
