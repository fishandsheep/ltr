use anyhow::Result;
use ltr_cli::cli::{init_logging, parse_args, run};

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();
    init_logging(&args);
    run(args).await
}
