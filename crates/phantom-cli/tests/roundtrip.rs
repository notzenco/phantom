//! Integration test: run the manifest-driven fixture matrix through roundtrip protection.

mod common;

use common::{assert_case_output, demos, fixture_binary, protect_binary, targets, temp_path};

#[test]
fn roundtrip_matrix_preserves_behavior() {
    for target in targets() {
        for demo in demos() {
            let input = fixture_binary(demo, target);
            assert!(input.exists(), "fixture should exist: {}", input.display());

            let output = temp_path(&format!("{}-{}-roundtrip", demo.name, target.mode))
                .with_extension(target.suffix.trim_start_matches('.'));
            let protect = protect_binary(&input, &output, None);
            assert!(
                protect.status.success(),
                "roundtrip protect failed for {}/{}: {}",
                demo.name,
                target.mode,
                String::from_utf8_lossy(&protect.stderr)
            );

            for case in &demo.cases {
                let run = target
                    .command(&output)
                    .args(&case.args)
                    .output()
                    .expect("execute roundtrip binary");
                assert_case_output(
                    case,
                    &run,
                    &format!("roundtrip {}/{} case {}", demo.name, target.mode, case.name),
                );
            }

            let _ = std::fs::remove_file(output);
        }
    }
}
