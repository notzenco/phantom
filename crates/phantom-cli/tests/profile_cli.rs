//! Integration tests for CLI profile flows and the fixture harness scripts.

mod common;

use std::path::Path;
use std::process::Command;

use common::{temp_path, BIN};

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve repo root")
}

#[test]
fn protect_dynamic_pie_profile_hides_strings_and_runs() {
    let source = temp_path("dynamic-pie").with_extension("c");
    let input = temp_path("dynamic-pie");
    let output = temp_path("dynamic-pie-protected");

    std::fs::write(
        &source,
        "#include <stdio.h>\nint main(void) { puts(\"dyn hello\"); return 0; }\n",
    )
    .expect("write source");

    let compile = Command::new("cc")
        .args([
            "-fPIE",
            "-pie",
            "-O2",
            "-o",
            input.to_str().expect("utf8 input path"),
            source.to_str().expect("utf8 source path"),
        ])
        .output()
        .expect("compile dynamic pie fixture");
    assert!(
        compile.status.success(),
        "compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let protect = Command::new(BIN)
        .args([
            "protect",
            "-i",
            input.to_str().expect("utf8 input path"),
            "-o",
            output.to_str().expect("utf8 output path"),
            "--profile",
            "strings",
        ])
        .output()
        .expect("run phantom-cli protect");
    assert!(
        protect.status.success(),
        "protect failed: {}",
        String::from_utf8_lossy(&protect.stderr)
    );

    let protected = std::fs::read(&output).expect("read protected binary");
    assert!(
        !protected.windows(9).any(|window| window == b"dyn hello"),
        "protected binary should not contain plaintext dynamic string"
    );

    let run = Command::new(&output)
        .output()
        .expect("execute protected dynamic binary");
    assert!(
        run.status.success(),
        "protected dynamic binary failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&run.stdout), "dyn hello\n");

    let _ = std::fs::remove_file(source);
    let _ = std::fs::remove_file(input);
    let _ = std::fs::remove_file(output);
}

#[test]
fn profiles_command_lists_builtin_and_file_profiles() {
    let profile_file = temp_path("profiles").with_extension("toml");
    std::fs::write(
        &profile_file,
        "[profiles]\ncustom = [\"string_encryption\"]\n",
    )
    .expect("write profile file");

    let result = Command::new(BIN)
        .args([
            "profiles",
            "--profile-file",
            profile_file.to_str().expect("utf8 profile path"),
        ])
        .output()
        .expect("run phantom-cli profiles");

    assert!(
        result.status.success(),
        "profiles should succeed, stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains("strings [built-in]: string_encryption"));
    assert!(stdout.contains("custom [file "));
    assert!(stdout.contains("string_encryption"));

    let _ = std::fs::remove_file(profile_file);
}

#[test]
fn obfuscation_matrix_script_emits_json_report() {
    let report = temp_path("obfuscation-matrix").with_extension("json");
    let script = repo_root().join("tests/fixtures/run_obfuscation_matrix.py");

    let result = Command::new("python3")
        .arg(script)
        .args([
            "--mode",
            "dynamic",
            "--json-out",
            report.to_str().expect("utf8 report path"),
        ])
        .current_dir(repo_root())
        .output()
        .expect("run obfuscation matrix script");

    assert!(
        result.status.success(),
        "matrix script failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(report.exists(), "report should exist: {}", report.display());

    let json = std::fs::read_to_string(&report).expect("read report");
    assert!(json.contains("\"status\": \"passed\""));
    assert!(json.contains("\"demo\": \"banner_messages\""));
    assert!(json.contains("\"stage\": \"protected_run\""));

    let _ = std::fs::remove_file(report);
}
