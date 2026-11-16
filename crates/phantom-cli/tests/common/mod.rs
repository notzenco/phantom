#![allow(dead_code)]

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// Environment the runner needs (e.g. silencing Wine diagnostics on stderr).
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub bin_dir: PathBuf,
}

impl Target {
    /// Command that executes `binary` on this host (directly or via e.g. Wine).
    pub fn command(&self, binary: &Path) -> Command {
        let mut command = match self.runner.split_first() {
            Some((program, rest)) => {
                let mut command = Command::new(program);
                command.args(rest).arg(binary);
                command
            }
            None => Command::new(binary),
        };
        command.envs(&self.env);
        command
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

// Not `canonicalize`: on Windows it yields a `\\?\` verbatim path that MinGW gcc
// cannot open.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the repo root")
        .to_path_buf()
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
                eprintln!("SKIPPED: no fixture targets can run on this host");
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

/// Why `output` does not match `case`, if it does not.
pub fn case_output_mismatch(case: &DemoCase, output: &Output, context: &str) -> Option<String> {
    let mut problems = Vec::new();
    if output.status.code() != Some(case.expect_exit) {
        problems.push(format!(
            "exit {:?}, expected {}",
            output.status, case.expect_exit
        ));
    }
    let stdout = normalized(&output.stdout);
    if stdout != case.expect_stdout {
        problems.push(format!(
            "stdout {stdout:?}, expected {:?}",
            case.expect_stdout
        ));
    }
    let stderr = normalized(&output.stderr);
    if stderr != case.expect_stderr {
        problems.push(format!(
            "stderr {stderr:?}, expected {:?}",
            case.expect_stderr
        ));
    }
    (!problems.is_empty()).then(|| format!("{context}: {}", problems.join("; ")))
}

/// Fail with every collected problem at once, or say plainly that nothing ran,
/// so an empty matrix reads as a skip rather than a pass.
pub fn report_matrix(name: &str, runs: usize, failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{name} matrix: {} failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    if runs == 0 {
        eprintln!("SKIPPED: {name} matrix ran no cases (no fixture targets on this host)");
    } else {
        eprintln!("{name} matrix: {runs} case run(s) passed");
    }
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

/// How long one fixture run may take before it counts as hung. Wine start-up on
/// a cold prefix is the slowest case.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(120);

/// Run `command` to completion, killing it if it outlives [`RUN_TIMEOUT`] so a
/// protected binary that hangs fails its test instead of stalling the job.
pub fn run_with_timeout(command: &mut Command) -> Output {
    try_run_with_timeout(command).unwrap_or_else(|err| panic!("{err}"))
}

pub fn try_run_with_timeout(command: &mut Command) -> Result<Output, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("spawn {command:?}: {err}"))?;
    // Drain both pipes concurrently so a chatty child cannot block on a full pipe.
    let drain = |mut pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
    };
    let stdout = drain(Box::new(child.stdout.take().expect("piped stdout")));
    let stderr = drain(Box::new(child.stderr.take().expect("piped stderr")));

    let deadline = Instant::now() + RUN_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|err| format!("wait: {err}"))? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{command:?} timed out after {RUN_TIMEOUT:?}"));
        }
        thread::sleep(Duration::from_millis(20));
    };
    Ok(Output {
        status,
        stdout: stdout.join().expect("stdout reader"),
        stderr: stderr.join().expect("stderr reader"),
    })
}
