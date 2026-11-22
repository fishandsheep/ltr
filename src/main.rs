use anyhow::Result;
use ltr_cli::cli::{self, parse_args, run};
use ltr_cli::conf::FileConfig;
use ltr_cli::daemon;

#[tokio::main]
async fn main() -> Result<()> {
    // Behave like a classic Unix tool when stdout is piped into `head`: die
    // silently on SIGPIPE instead of panicking on a broken pipe write.
    #[cfg(unix)]
    // SAFETY: restores the default signal disposition before any threads exist.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

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
