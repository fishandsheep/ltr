use anyhow::Result;
use ltr_cli::cli::{init_logging, init_logging_into, parse_args, run};
use ltr_cli::daemon;

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();
    if !args.front && !daemon::is_child() {
        #[cfg(unix)]
        daemon::spawn_and_wait(&args.command).await;
        #[cfg(not(unix))]
        eprintln!("Note: background execution is not supported on Windows yet; continuing in the foreground.");
    }
    if daemon::is_child() {
        let log_path = daemon::child_log_path()?;
        let writer = daemon::LogFileWriter::open(&log_path)?;
        init_logging_into(&args, Some(writer));
    } else {
        init_logging(&args);
    }
    run(args).await
}
