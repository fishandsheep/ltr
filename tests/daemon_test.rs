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

/// Reads piped lines (stdout or stderr) through a channel so expectations can
/// time out instead of hanging the test suite.
fn line_reader<T: std::io::Read + Send + 'static>(pipe: Option<T>) -> mpsc::Receiver<String> {
    let Some(pipe) = pipe else {
        return mpsc::channel().1;
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(pipe);
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
    let rx = line_reader(child.stdout.take());

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
    let rx = line_reader(child.stdout.take());

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
    assert_eq!(stop, "Stop: ltr -s");

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

/// Runs the ltr binary to completion, returning combined output and exit code.
fn run_ltr_to_completion(args: &[&str], root: &std::path::Path) -> (String, Option<i32>) {
    let mut child = spawn_ltr(args, root);
    let rx = line_reader(child.stdout.take());
    let err_rx = line_reader(child.stderr.take());
    let mut out = String::new();
    while let Ok(line) = rx.recv_timeout(Duration::from_secs(15)) {
        out.push_str(&line);
        out.push('\n');
    }
    while let Ok(line) = err_rx.try_recv() {
        out.push_str(&line);
        out.push('\n');
    }
    let status = child.wait().unwrap();
    (out, status.code())
}

#[test]
fn list_and_stop_background_console() {
    let root = std::env::temp_dir().join(format!(
        "ltr-manage-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let mut child = spawn_ltr(&["--web-addr", "127.0.0.1:0"], &root);
    let rx = line_reader(child.stdout.take());
    let line = recv_line(&rx);
    assert!(line.starts_with("LTR web console listening on http://"));
    let port: u16 = line.rsplit(':').next().unwrap().parse().unwrap();
    let _ = recv_line(&rx); // running in background (pid ..)
    let _ = child.wait().unwrap();

    // -l lists the console instance.
    let (out, code) = run_ltr_to_completion(&["-l"], &root);
    assert_eq!(code, Some(0));
    assert!(out.contains("console"), "list output: {out}");
    assert!(
        out.contains(&format!("127.0.0.1:{port}")),
        "list output: {out}"
    );

    // -s stops it gracefully; the port goes away and the list empties.
    let (out, code) = run_ltr_to_completion(&["-s", &port.to_string()], &root);
    assert_eq!(code, Some(0), "stop output: {out}");
    assert!(out.contains("Stopped console"), "stop output: {out}");
    wait_for_refused(&format!("127.0.0.1:{port}"));

    let (out, code) = run_ltr_to_completion(&["-l"], &root);
    assert_eq!(code, Some(0));
    assert!(
        out.contains("No running LTR instances."),
        "list output: {out}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn stop_unknown_port_lists_instances() {
    let root = std::env::temp_dir().join(format!(
        "ltr-manage-none-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (out, code) = run_ltr_to_completion(&["-s", "59999"], &root);
    assert_eq!(code, Some(1));
    assert!(
        out.contains("no running instance exposes port 59999"),
        "stop output: {out}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn pipe_to_head_exits_cleanly() {
    let root = std::env::temp_dir().join(format!(
        "ltr-pipe-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ltr"))
        .args(["conf", "get"])
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("HOME", &root)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(out.status.success(), "conf get should succeed");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn server_survives_stopped_client() {
    let root = std::env::temp_dir().join(format!(
        "ltr-sigpipe-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (out, code) = run_ltr_to_completion(&["conf", "set", "to", "localhost"], &root);
    assert_eq!(code, Some(0), "conf set output: {out}");

    // Start the relay in the background.
    let mut server = spawn_ltr(&["server", "--no-tls"], &root);
    let rx = line_reader(server.stdout.take());
    let _ = recv_line(&rx); // LTR server listening on 0.0.0.0:7835
    let server_pid: u32 = recv_line(&rx)
        .strip_prefix("LTR running in background (pid ")
        .and_then(|rest| rest.strip_suffix(')'))
        .and_then(|pid| pid.parse().ok())
        .expect("server pid");
    let _ = server.wait().unwrap();

    // Expose a port, then stop it by port; the server must survive.
    let mut tunnel = spawn_ltr(&["8000", "--no-tls"], &root);
    let rx = line_reader(tunnel.stdout.take());
    let line = recv_line(&rx);
    let remote_port: u16 = line.rsplit(':').next().unwrap().parse().unwrap();
    let _ = tunnel.wait().unwrap();

    let (out, code) = run_ltr_to_completion(&["-s", &remote_port.to_string()], &root);
    assert_eq!(code, Some(0), "stop output: {out}");

    let (out, code) = run_ltr_to_completion(&["-l"], &root);
    assert_eq!(code, Some(0));
    assert!(
        out.contains(&format!("{server_pid}")),
        "server pid {server_pid} should still be listed, got: {out}"
    );

    let _ = run_ltr_to_completion(&["-s", "7835"], &root);
    let _ = std::fs::remove_dir_all(&root);
}
