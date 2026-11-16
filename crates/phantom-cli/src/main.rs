use anyhow::Result;
use clap::Parser;
use phantom_cli::{run_cli, Cli};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Warnings (such as strings deliberately left unencrypted) show by default.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        })
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    run_cli(cli)
}
