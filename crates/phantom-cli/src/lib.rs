pub mod cli;
pub mod commands;
pub mod profiles;

pub use cli::Cli;

use anyhow::Result;

/// Dispatch the parsed CLI to the selected command.
pub fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        cli::Commands::Protect(args) => commands::protect::run(&args),
        cli::Commands::Info(args) => commands::info::run(&args.input),
        cli::Commands::Inspect(args) => {
            commands::inspect::run(&args.input, args.function.as_deref(), args.json)
        }
        cli::Commands::Profiles(args) => commands::profiles::run(args.profile_file.as_deref()),
    }
}
