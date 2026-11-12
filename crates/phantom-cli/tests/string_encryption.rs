//! Integration test: run the manifest-driven fixture matrix through string obfuscation.

mod common;

use common::{
    assert_case_output, demos, fixture_binary, probe_hits, protect_binary, targets, temp_path,
};

#[test]
fn string_encryption_matrix_hides_probes_and_preserves_behavior() {
    for target in targets() {
        for demo in demos() {
            let input = fixture_binary(demo, target);
            assert!(input.exists(), "fixture should exist: {}", input.display());

            // A probe the compiler optimised away would make the hidden-string check
            // below pass vacuously, so every probe must exist before protection.
            let original = std::fs::read(&input).expect("read fixture binary");
            let present = probe_hits(&original, &demo.string_probes);
            assert_eq!(
                present, demo.string_probes,
                "probes missing from the unprotected {}/{} binary",
                demo.name, target.mode
            );

            let output = temp_path(&format!("{}-{}-strings", demo.name, target.mode))
                .with_extension(target.suffix.trim_start_matches('.'));
            let protect = protect_binary(&input, &output, Some("strings"));
            assert!(
                protect.status.success(),
                "string protection failed for {}/{}: {}",
                demo.name,
                target.mode,
                String::from_utf8_lossy(&protect.stderr)
            );

            let protected = std::fs::read(&output).expect("read protected binary");
            let hits = probe_hits(&protected, &demo.string_probes);
            assert!(
                hits.is_empty(),
                "protected binary still contains plaintext probes for {}/{}: {:?}",
                demo.name,
                target.mode,
                hits
            );

            for case in &demo.cases {
                let run = target
                    .command(&output)
                    .args(&case.args)
                    .output()
                    .expect("execute protected binary");
                assert_case_output(
                    case,
                    &run,
                    &format!(
                        "string protection {}/{} case {}",
                        demo.name, target.mode, case.name
                    ),
                );
            }

            let _ = std::fs::remove_file(output);
        }
    }
}
