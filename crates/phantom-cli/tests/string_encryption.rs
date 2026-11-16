//! Integration test: run the manifest-driven fixture matrix through string obfuscation.

mod common;

use common::{
    case_output_mismatch, demos, fixture_binary, probe_hits, protect_binary, targets, temp_path,
};

#[test]
fn string_encryption_matrix_hides_probes_and_preserves_behavior() {
    let mut failures = Vec::new();
    let mut runs = 0;
    for target in targets() {
        for demo in demos() {
            let label = format!("string protection {}/{}", demo.name, target.mode);
            let input = fixture_binary(demo, target);
            let Ok(original) = std::fs::read(&input) else {
                failures.push(format!("{label}: fixture missing: {}", input.display()));
                continue;
            };

            // A probe the compiler optimised away would make the hidden-string check
            // below pass vacuously, so every probe must exist before protection.
            let present = probe_hits(&original, &demo.string_probes);
            if present != demo.string_probes {
                failures.push(format!(
                    "{label}: probes missing before protection: expected {:?}, found {present:?}",
                    demo.string_probes
                ));
                continue;
            }

            let output = temp_path(&format!("{}-{}-strings", demo.name, target.mode))
                .with_extension(target.suffix.trim_start_matches('.'));
            let protect = protect_binary(&input, &output, Some("strings"));
            if !protect.status.success() {
                failures.push(format!(
                    "{label}: protect failed: {}",
                    String::from_utf8_lossy(&protect.stderr)
                ));
                continue;
            }

            let protected = std::fs::read(&output).expect("read protected binary");
            let hits = probe_hits(&protected, &demo.string_probes);
            if !hits.is_empty() {
                failures.push(format!("{label}: plaintext probes remain: {hits:?}"));
            }

            for case in &demo.cases {
                runs += 1;
                let context = format!("{label} case {}", case.name);
                let run = common::try_run_with_timeout(target.command(&output).args(&case.args));
                failures.extend(match run {
                    Ok(run) => case_output_mismatch(case, &run, &context),
                    Err(err) => Some(format!("{context}: {err}")),
                });
            }

            let _ = std::fs::remove_file(output);
        }
    }
    common::report_matrix("string protection", runs, &failures);
}
