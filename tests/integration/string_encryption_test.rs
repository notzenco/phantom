//! Integration test: lift → string encryption → emit → verify encrypted binary runs.

use std::process::Command;

use phantom_backends::{Backend, ElfBackend};
use phantom_core::pipeline::Pipeline;
use phantom_frontends::detect_frontend;
use phantom_passes::StringEncryptionPass;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/hello_x86_64");

fn fixture_exists() -> bool {
    std::path::Path::new(FIXTURE).exists()
}

#[test]
fn string_encryption_hides_strings() {
    if !fixture_exists() {
        eprintln!("Skipping: fixture not found at {FIXTURE}");
        return;
    }

    let data = std::fs::read(FIXTURE).expect("read fixture");

    // Verify "Hello, World!" is in the original binary.
    assert!(
        data.windows(13).any(|w| w == b"Hello, World!"),
        "fixture should contain 'Hello, World!' in plaintext"
    );

    // Lift.
    let frontend = detect_frontend(&data).expect("detect frontend");
    let mut module = frontend.lift(&data).expect("lift");

    // Apply string encryption.
    let mut pipeline = Pipeline::new();
    pipeline.add_pass(Box::new(StringEncryptionPass::with_seed(42)));
    pipeline.run(&mut module).expect("run pipeline");

    // Emit.
    let backend = ElfBackend::new();
    let output = backend.emit(&module).expect("emit");

    // Verify "Hello, World!" is NOT in plaintext in the output.
    assert!(
        !output.windows(13).any(|w| w == b"Hello, World!"),
        "encrypted binary should NOT contain 'Hello, World!' in plaintext"
    );

    // Write to temp file and execute.
    let tmp = std::env::temp_dir().join("phantom_test_encrypted");
    std::fs::write(&tmp, &output).expect("write output");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let result = Command::new(&tmp).output().expect("execute encrypted binary");
    assert!(
        result.status.success(),
        "encrypted binary should exit 0, got: {:?}, stderr: {}",
        result.status,
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert_eq!(
        stdout.trim(),
        "Hello, World!",
        "encrypted binary should still print Hello, World!"
    );

    // Cleanup.
    let _ = std::fs::remove_file(&tmp);
}
