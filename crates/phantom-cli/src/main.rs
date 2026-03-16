use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;

#[derive(Parser)]
#[command(name = "phantom", about = "Open-source code protector")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Protect a binary: lift → transform → emit
    Protect {
        /// Input binary path
        #[arg(short, long)]
        input: PathBuf,

        /// Output binary path
        #[arg(short, long)]
        output: PathBuf,

        /// Comma-separated list of passes to apply
        #[arg(short, long, value_delimiter = ',')]
        passes: Vec<String>,
    },
    /// Display binary metadata
    Info {
        /// Input binary path
        input: PathBuf,
    },
    /// Dump PhIR (intermediate representation)
    Inspect {
        /// Input binary path
        input: PathBuf,

        /// Filter to a specific function
        #[arg(short, long)]
        function: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Protect {
            input,
            output,
            passes,
        } => commands::protect::run(input, output, passes),
        Commands::Info { input } => commands::info::run(input),
        Commands::Inspect {
            input,
            function,
            json,
        } => commands::inspect::run(input, function.as_deref(), *json),
    }
}
