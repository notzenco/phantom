//! Integration test: lift an ELF binary → emit (no transforms) → verify it runs.

use std::process::Command;

use phantom_backends::{Backend, ElfBackend};
use phantom_frontends::detect_frontend;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/hello_x86_64");

fn fixture_exists() -> bool {
    std::path::Path::new(FIXTURE).exists()
}

#[test]
fn roundtrip_produces_valid_elf() {
    if !fixture_exists() {
        eprintln!("Skipping: fixture not found at {FIXTURE}");
        return;
    }

    let data = std::fs::read(FIXTURE).expect("read fixture");

    // Lift.
    let frontend = detect_frontend(&data).expect("detect frontend");
    let module = frontend.lift(&data).expect("lift");

    assert!(!module.functions.is_empty(), "should have functions");
    assert!(!module.data_sections.is_empty(), "should have data sections");

    // Emit (no transforms).
    let backend = ElfBackend::new();
    let output = backend.emit(&module).expect("emit");

    // Write to temp file.
    let tmp = std::env::temp_dir().join("phantom_test_roundtrip");
    std::fs::write(&tmp, &output).expect("write output");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Execute and verify output.
    let result = Command::new(&tmp).output().expect("execute roundtrip binary");
    assert!(result.status.success(), "roundtrip binary should exit 0");
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert_eq!(stdout.trim(), "Hello, World!", "should print Hello, World!");

    // Cleanup.
    let _ = std::fs::remove_file(&tmp);
}
