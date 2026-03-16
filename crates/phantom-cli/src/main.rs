use anyhow::Result;
use clap::Parser;
use phantom_cli::{run_cli, Cli};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    run_cli(cli)
}
