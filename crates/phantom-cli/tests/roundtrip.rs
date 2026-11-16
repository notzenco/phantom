//! Integration test: run the manifest-driven fixture matrix through roundtrip protection.

mod common;

use common::{case_output_mismatch, demos, fixture_binary, protect_binary, targets, temp_path};

#[test]
fn roundtrip_matrix_preserves_behavior() {
    let mut failures = Vec::new();
    let mut runs = 0;
    for target in targets() {
        for demo in demos() {
            let label = format!("roundtrip {}/{}", demo.name, target.mode);
            let input = fixture_binary(demo, target);
            if !input.exists() {
                failures.push(format!("{label}: fixture missing: {}", input.display()));
                continue;
            }

            let output = temp_path(&format!("{}-{}-roundtrip", demo.name, target.mode))
                .with_extension(target.suffix.trim_start_matches('.'));
            let protect = protect_binary(&input, &output, None);
            if !protect.status.success() {
                failures.push(format!(
                    "{label}: protect failed: {}",
                    String::from_utf8_lossy(&protect.stderr)
                ));
                continue;
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
    common::report_matrix("roundtrip", runs, &failures);
}
