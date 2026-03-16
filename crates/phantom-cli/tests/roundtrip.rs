//! Integration test: run the manifest-driven fixture matrix through roundtrip protection.

mod common;

use std::process::Command;

use common::{assert_case_output, demos, fixture_binary, modes, protect_binary, temp_path};

#[test]
fn roundtrip_matrix_preserves_behavior() {
    for demo in demos() {
        let _ = &demo.source;
        for &mode in modes() {
            let input = fixture_binary(demo, mode);
            assert!(input.exists(), "fixture should exist: {}", input.display());

            let output = temp_path(&format!("{}-{}-roundtrip", demo.name, mode.as_str()));
            let protect = protect_binary(&input, &output, None);
            assert!(
                protect.status.success(),
                "roundtrip protect failed for {}/{}: {}",
                demo.name,
                mode.as_str(),
                String::from_utf8_lossy(&protect.stderr)
            );

            for case in &demo.cases {
                let run = Command::new(&output)
                    .args(&case.args)
                    .output()
                    .expect("execute roundtrip binary");
                assert_case_output(
                    case,
                    &run,
                    &format!("roundtrip {}/{} case {}", demo.name, mode.as_str(), case.name),
                );
            }

            let _ = std::fs::remove_file(output);
        }
    }
}
