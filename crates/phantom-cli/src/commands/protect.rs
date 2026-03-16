use std::path::PathBuf;

use anyhow::Result;
use tracing::info;

use phantom_backends::{Backend, ElfBackend};
use phantom_core::pipeline::Pipeline;
use phantom_frontends::detect_frontend;

/// Full pipeline: lift → transform → emit.
pub fn run(input: &PathBuf, output: &PathBuf, passes: &[String]) -> Result<()> {
    info!("Loading binary: {}", input.display());
    let data = std::fs::read(input)?;

    let frontend = detect_frontend(&data)
        .ok_or_else(|| anyhow::anyhow!("Unsupported binary format"))?;

    info!("Lifting binary to PhIR...");
    let mut module = frontend.lift(&data)?;

    info!(
        "Lifted {} functions, {} data sections",
        module.functions.len(),
        module.data_sections.len()
    );

    // Build the transform pipeline.
    let mut pipeline = Pipeline::new();
    for pass_name in passes {
        let pass = phantom_passes::get_pass(pass_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown pass: {}", pass_name))?;
        pipeline.add_pass(pass);
    }

    if !passes.is_empty() {
        info!("Running {} transform pass(es)...", passes.len());
        pipeline.run(&mut module)?;
    }

    info!("Emitting protected binary...");
    let backend = ElfBackend::new();
    let binary = backend.emit(&module)?;

    std::fs::write(output, &binary)?;

    // Make output executable on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(output, perms)?;
    }

    info!("Protected binary written to: {}", output.display());
    println!("Done. Output: {}", output.display());

    Ok(())
}
