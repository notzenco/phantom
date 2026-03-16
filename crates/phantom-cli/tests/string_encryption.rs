//! Integration test: run the manifest-driven fixture matrix through string obfuscation.

mod common;

use std::process::Command;

use common::{
    assert_case_output, demos, fixture_binary, modes, probe_hits, protect_binary, temp_path,
};

#[test]
fn string_encryption_matrix_hides_probes_and_preserves_behavior() {
    for demo in demos() {
        for &mode in modes() {
            let input = fixture_binary(demo, mode);
            assert!(input.exists(), "fixture should exist: {}", input.display());

            let output = temp_path(&format!("{}-{}-strings", demo.name, mode.as_str()));
            let protect = protect_binary(&input, &output, Some("strings"));
            assert!(
                protect.status.success(),
                "string protection failed for {}/{}: {}",
                demo.name,
                mode.as_str(),
                String::from_utf8_lossy(&protect.stderr)
            );

            let protected = std::fs::read(&output).expect("read protected binary");
            let hits = probe_hits(&protected, &demo.string_probes);
            assert!(
                hits.is_empty(),
                "protected binary still contains plaintext probes for {}/{}: {:?}",
                demo.name,
                mode.as_str(),
                hits
            );

            for case in &demo.cases {
                let run = Command::new(&output)
                    .args(&case.args)
                    .output()
                    .expect("execute protected binary");
                assert_case_output(
                    case,
                    &run,
                    &format!(
                        "string protection {}/{} case {}",
                        demo.name,
                        mode.as_str(),
                        case.name
                    ),
                );
            }

            let _ = std::fs::remove_file(output);
        }
    }
}
