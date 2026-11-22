use anyhow::Result;
use ltr_cli::cli::{self, parse_args, run};
use ltr_cli::conf::FileConfig;
use ltr_cli::daemon;

#[tokio::main]
async fn main() -> Result<()> {
    // NOTE: SIGPIPE stays ignored (the Rust default). Restoring its default
    // disposition would kill long-running modes whenever a peer socket closes
    // mid-write; quick commands tolerate EPIPE in `outln!` instead.
    let args = parse_args();
    let file = FileConfig::load()?;
    let eff = cli::Eff::resolve(&args, &file);

    if !args.is_quick() && !eff.front && !daemon::is_child() {
        #[cfg(unix)]
        daemon::spawn_and_wait(&args).await;
        #[cfg(not(unix))]
        eprintln!("Note: background execution is not supported on Windows yet; continuing in the foreground.");
    }

    if daemon::is_child() {
        let log_path = daemon::child_log_path()?;
        let writer = daemon::LogFileWriter::open(&log_path)?;
        cli::init_logging_into(&eff.log_level, eff.log_json, Some(writer));
    } else {
        cli::init_logging(&eff.log_level, eff.log_json);
    }
    run(args, eff).await
}
