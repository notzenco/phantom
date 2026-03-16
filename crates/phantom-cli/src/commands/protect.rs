use anyhow::Result;
use tracing::info;

use phantom_backends::{Backend, ElfBackend};
use phantom_core::pipeline::Pipeline;
use phantom_frontends::detect_frontend;

use crate::cli::ProtectArgs;

/// Full pipeline: lift → transform → emit.
pub fn run(args: &ProtectArgs) -> Result<()> {
    info!("Loading binary: {}", args.input.display());
    let data = std::fs::read(&args.input)?;

    let frontend =
        detect_frontend(&data).ok_or_else(|| anyhow::anyhow!("Unsupported binary format"))?;

    info!("Lifting binary to PhIR...");
    let mut module = frontend.lift(&data)?;

    info!(
        "Lifted {} functions, {} data sections",
        module.functions.len(),
        module.data_sections.len()
    );

    let resolved_passes = crate::profiles::resolve_passes(
        args.profile.as_deref(),
        args.profile_file.as_deref(),
        &args.passes,
    )?;

    if let Some(profile_name) = args.profile.as_deref() {
        info!(
            "Resolved profile '{}' to {} transform pass(es).",
            profile_name,
            resolved_passes.len()
        );
    }

    // Build the transform pipeline.
    let mut pipeline = Pipeline::new();
    for pass_name in &resolved_passes {
        let pass = phantom_passes::get_pass(pass_name).ok_or_else(|| {
            anyhow::anyhow!("Validated pass '{}' could not be constructed", pass_name)
        })?;
        pipeline.add_pass(pass);
    }

    if !resolved_passes.is_empty() {
        info!("Running {} transform pass(es)...", resolved_passes.len());
        pipeline.run(&mut module)?;
    }

    info!("Emitting protected binary...");
    let backend = ElfBackend::new();
    let binary = backend.emit(&module)?;

    std::fs::write(&args.output, &binary)?;

    // Make output executable on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&args.output, perms)?;
    }

    info!("Protected binary written to: {}", args.output.display());
    println!("Done. Output: {}", args.output.display());

    Ok(())
}
