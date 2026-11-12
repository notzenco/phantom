#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

pub const BIN: &str = env!("CARGO_BIN_EXE_phantom-cli");

/// Python 3 launcher name; Windows installs ship `python`, not `python3`.
pub const PYTHON: &str = if cfg!(windows) { "python" } else { "python3" };

/// A fixture target this host can build and execute, as reported by
/// `build_fixtures.py --list`.
#[derive(Debug, Clone, Deserialize)]
pub struct Target {
    pub mode: String,
    pub suffix: String,
    pub runner: Vec<String>,
    pub bin_dir: PathBuf,
}

impl Target {
    /// Command that executes `binary` on this host (directly or via e.g. Wine).
    pub fn command(&self, binary: &Path) -> Command {
        match self.runner.split_first() {
            Some((program, rest)) => {
                let mut command = Command::new(program);
                command.args(rest).arg(binary);
                command
            }
            None => Command::new(binary),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DemoCase {
    pub name: String,
    pub args: Vec<String>,
    pub expect_stdout: String,
    pub expect_stderr: String,
    pub expect_exit: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Demo {
    pub name: String,
    pub source: String,
    pub string_probes: Vec<String>,
    #[serde(rename = "case")]
    pub cases: Vec<DemoCase>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    demo: Vec<Demo>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve repo root")
}

fn fixtures_root() -> PathBuf {
    repo_root().join("tests/fixtures")
}

fn manifest_path() -> PathBuf {
    fixtures_root().join("manifest.toml")
}

fn build_script_path() -> PathBuf {
    fixtures_root().join("build_fixtures.py")
}

static BUILD_STATUS: OnceLock<Result<(), String>> = OnceLock::new();
static MANIFEST: OnceLock<Vec<Demo>> = OnceLock::new();
static TARGETS: OnceLock<Vec<Target>> = OnceLock::new();

fn ensure_fixtures_built() {
    let status = BUILD_STATUS.get_or_init(|| {
        let output = Command::new(PYTHON)
            .arg(build_script_path())
            .args(["--mode", "all", "--quiet"])
            .current_dir(repo_root())
            .output()
            .map_err(|err| format!("spawn fixture builder: {err}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "fixture builder failed with {}:\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    });

    if let Err(err) = status {
        panic!("{err}");
    }
}

pub fn demos() -> &'static [Demo] {
    ensure_fixtures_built();
    MANIFEST
        .get_or_init(|| {
            let text = std::fs::read_to_string(manifest_path()).expect("read fixture manifest");
            toml::from_str::<Manifest>(&text)
                .expect("parse fixture manifest")
                .demo
        })
        .as_slice()
}

/// Targets this host can build and run. Set `PHANTOM_REQUIRE_TARGETS` (comma
/// separated) to fail instead of silently skipping a target CI must cover.
pub fn targets() -> &'static [Target] {
    TARGETS
        .get_or_init(|| {
            let output = Command::new(PYTHON)
                .arg(build_script_path())
                .arg("--list")
                .output()
                .expect("run fixture target listing");
            assert!(
                output.status.success(),
                "fixture target listing failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let targets: Vec<Target> =
                serde_json::from_slice(&output.stdout).expect("parse fixture target listing");
            if let Ok(required) = std::env::var("PHANTOM_REQUIRE_TARGETS") {
                for mode in required.split(',').map(str::trim).filter(|m| !m.is_empty()) {
                    assert!(
                        targets.iter().any(|t| t.mode == mode),
                        "required fixture target '{mode}' is not available on this host"
                    );
                }
            }
            if targets.is_empty() {
                eprintln!("no fixture targets can run on this host; skipping matrix");
            }
            targets
        })
        .as_slice()
}

pub fn fixture_binary(demo: &Demo, target: &Target) -> PathBuf {
    let source_path = fixtures_root().join(&demo.source);
    assert!(
        source_path.exists(),
        "fixture source should exist: {}",
        source_path.display()
    );
    target
        .bin_dir
        .join(format!("{}{}", demo.name, target.suffix))
}

pub fn temp_path(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("phantom-{name}-{unique}"))
}

/// Windows C runtimes write CRLF in text mode; the manifest records LF.
fn normalized(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n")
}

pub fn assert_case_output(case: &DemoCase, output: &Output, context: &str) {
    assert_eq!(
        output.status.code(),
        Some(case.expect_exit),
        "{context}: unexpected exit status, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        normalized(&output.stdout),
        case.expect_stdout,
        "{context}: unexpected stdout"
    );
    assert_eq!(
        normalized(&output.stderr),
        case.expect_stderr,
        "{context}: unexpected stderr"
    );
}

pub fn protect_binary(input: &Path, output: &Path, profile: Option<&str>) -> Output {
    let mut command = Command::new(BIN);
    command.args([
        "protect",
        "-i",
        input.to_str().expect("utf8 input path"),
        "-o",
        output.to_str().expect("utf8 output path"),
    ]);
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    command.output().expect("run protect command")
}

pub fn probe_hits(bytes: &[u8], probes: &[String]) -> Vec<String> {
    probes
        .iter()
        .filter(|probe| {
            bytes
                .windows(probe.len())
                .any(|window| window == probe.as_bytes())
        })
        .cloned()
        .collect()
}
