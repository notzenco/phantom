use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "phantom", about = "Open-source code protector")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Protect a binary: lift → transform → emit
    Protect(ProtectArgs),
    /// Display binary metadata
    Info(InfoArgs),
    /// Dump PhIR (intermediate representation)
    Inspect(InspectArgs),
    /// List available protection profiles
    Profiles(ProfilesArgs),
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct ProtectArgs {
    /// Input binary path
    #[arg(short, long)]
    pub input: PathBuf,

    /// Output binary path
    #[arg(short, long)]
    pub output: PathBuf,

    /// Comma-separated list of passes to apply
    #[arg(short, long, value_delimiter = ',')]
    pub passes: Vec<String>,

    /// Named protection profile to apply
    #[arg(long)]
    pub profile: Option<String>,

    /// TOML file providing additional profile definitions
    #[arg(long, requires = "profile")]
    pub profile_file: Option<PathBuf>,
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct InfoArgs {
    /// Input binary path
    pub input: PathBuf,
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct InspectArgs {
    /// Input binary path
    pub input: PathBuf,

    /// Filter to a specific function
    #[arg(short, long)]
    pub function: Option<String>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct ProfilesArgs {
    /// TOML file providing additional profile definitions
    #[arg(long)]
    pub profile_file: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_profiles_subcommand() {
        let cli = Cli::try_parse_from(["phantom", "profiles", "--profile-file", "phantom.toml"])
            .expect("parse profiles");

        match cli.command {
            Commands::Profiles(args) => {
                assert_eq!(args.profile_file, Some(PathBuf::from("phantom.toml")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn protect_profile_file_requires_profile() {
        let err = Cli::try_parse_from([
            "phantom",
            "protect",
            "-i",
            "input",
            "-o",
            "output",
            "--profile-file",
            "phantom.toml",
        ])
        .expect_err("profile file without profile should fail");

        let rendered = err.to_string();
        assert!(rendered.contains("--profile"));
        assert!(rendered.contains("--profile-file"));
    }

    #[test]
    fn parse_protect_profile_and_passes() {
        let cli = Cli::try_parse_from([
            "phantom",
            "protect",
            "-i",
            "input",
            "-o",
            "output",
            "--profile",
            "strings",
            "--profile-file",
            "phantom.toml",
            "-p",
            "string_encryption,other",
        ])
        .expect("parse protect");

        match cli.command {
            Commands::Protect(args) => {
                assert_eq!(args.profile.as_deref(), Some("strings"));
                assert_eq!(args.profile_file, Some(PathBuf::from("phantom.toml")));
                assert_eq!(args.passes, vec!["string_encryption", "other"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
