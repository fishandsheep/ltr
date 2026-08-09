use anyhow::Result;
use ltr_cli::cli::{init_logging, parse_args, run};

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("Warning: bore-cli is deprecated; install ltr-cli and use ltr instead.");
    let args = parse_args();
    init_logging(&args);
    run(args).await
}
