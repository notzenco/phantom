//! CLI behaviour that needs no fixture toolchain: flags and error reporting.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::{temp_path, BIN};

fn phantom(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("run phantom-cli")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Write `bytes` to a temp file and return its path.
fn input_file(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = temp_path(name);
    std::fs::write(&path, bytes).expect("write input");
    path
}

/// A clean failure: exit code 1 (an error), not 101 (a panic) or a signal.
fn assert_clean_error(output: &Output) {
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(output));
    assert!(!stderr(output).contains("panicked"), "{}", stderr(output));
}

fn protect(input: &Path, extra: &[&str]) -> Output {
    let output = temp_path("cli-usage-out");
    let mut args = vec![
        "protect",
        "-i",
        input.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let result = phantom(&args);
    let _ = std::fs::remove_file(output);
    result
}

#[test]
fn prints_version() {
    let output = phantom(&["--version"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "{stdout}");
}

#[test]
fn missing_input_names_the_path() {
    let missing = temp_path("does-not-exist");
    for args in [
        vec!["info", missing.to_str().unwrap()],
        vec!["inspect", missing.to_str().unwrap()],
    ] {
        let output = phantom(&args);
        assert_clean_error(&output);
        assert!(
            stderr(&output).contains(missing.to_str().unwrap()),
            "{}",
            stderr(&output)
        );
    }
    let output = protect(&missing, &[]);
    assert_clean_error(&output);
    assert!(stderr(&output).contains(missing.to_str().unwrap()));
}

#[test]
fn unsupported_formats_are_named() {
    let cases: [(&str, &[u8], &str); 4] = [
        ("macho", &[0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1], "Mach-O"),
        ("fat-macho", &[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2], "Mach-O"),
        ("dos", b"MZ\x90\x00 just a DOS stub", "PE header"),
        ("garbage", b"definitely not a binary", "ELF or PE"),
    ];
    for (name, bytes, expected) in cases {
        let input = input_file(name, bytes);
        let output = phantom(&["info", input.to_str().unwrap()]);
        assert_clean_error(&output);
        assert!(
            stderr(&output).contains(expected),
            "{name}: {}",
            stderr(&output)
        );
        let _ = std::fs::remove_file(input);
    }
}

#[test]
fn truncated_elf_is_an_error_not_a_panic() {
    let mut header = b"\x7fELF\x02\x01\x01".to_vec();
    header.resize(20, 0);
    let input = input_file("truncated-elf", &header);
    assert_clean_error(&protect(&input, &["--profile", "strings"]));
    let _ = std::fs::remove_file(input);
}

#[test]
fn unknown_pass_lists_available_passes() {
    let input = input_file("unknown-pass", b"\x7fELF");
    let output = protect(&input, &["-p", "no_such_pass"]);
    assert_clean_error(&output);
    let message = stderr(&output);
    assert!(message.contains("no_such_pass"), "{message}");
    assert!(message.contains("string_encryption"), "{message}");
    let _ = std::fs::remove_file(input);
}
