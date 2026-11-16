use anyhow::{anyhow, bail, Context, Result};
use tracing::info;

use phantom_backends::backend_for;
use phantom_core::ir::module::Module;
use phantom_core::pipeline::Pipeline;

use crate::cli::ProtectArgs;

/// Full pipeline: lift → transform → emit.
pub fn run(args: &ProtectArgs) -> Result<()> {
    let resolved_passes = crate::profiles::resolve_passes(
        args.profile.as_deref(),
        args.profile_file.as_deref(),
        &args.passes,
    )?;

    info!("Loading binary: {}", args.input.display());
    let (data, mut module) = super::load(&args.input)?;
    let functions_lifted = module.functions.len();
    info!(
        "Lifted {} functions, {} data sections",
        functions_lifted,
        module.data_sections.len()
    );

    let mut pipeline = Pipeline::new();
    for (i, pass_name) in resolved_passes.iter().enumerate() {
        // Distinct per-pass seeds keep passes from sharing a key stream.
        let seed = args.seed.map(|s| s.wrapping_add(i as u64));
        let pass = phantom_passes::get_seeded_pass(pass_name, seed)
            .ok_or_else(|| anyhow!("Validated pass '{pass_name}' could not be constructed"))?;
        pipeline.add_pass(pass);
    }

    let before = ModuleState::of(&module);
    if !resolved_passes.is_empty() {
        info!("Running {} transform pass(es)...", resolved_passes.len());
        pipeline.run(&mut module)?;
        if ModuleState::of(&module) == before {
            bail!(
                "{}: the requested passes ({}) found nothing to protect; no output written",
                args.input.display(),
                resolved_passes.join(", ")
            );
        }
    }
    let (changed_bytes, changed_sections) = changed_data(&before, &module);

    let backend = backend_for(module.format)
        .ok_or_else(|| anyhow!("No emitter for {:?} binaries", module.format))?;
    let binary = backend.emit(&module)?;

    std::fs::write(&args.output, &binary)
        .with_context(|| format!("Failed to write {}", args.output.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args.output, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("Failed to make {} executable", args.output.display()))?;
    }

    println!(
        "Protected {} -> {}",
        args.input.display(),
        args.output.display()
    );
    println!("  functions lifted: {functions_lifted}");
    if resolved_passes.is_empty() {
        println!("  passes: none (roundtrip)");
    } else {
        println!("  passes: {}", resolved_passes.join(", "));
        println!("  data encrypted: {changed_bytes} bytes in {changed_sections} section(s)");
    }
    let growth = (binary.len() as f64 / data.len().max(1) as f64 - 1.0) * 100.0;
    println!(
        "  size: {} -> {} bytes ({growth:+.1}%)",
        data.len(),
        binary.len()
    );

    Ok(())
}

/// What a pass can change: data bytes, the set of functions, and instructions
/// marked as modified.
#[derive(PartialEq)]
struct ModuleState {
    data: Vec<Vec<u8>>,
    functions: usize,
    modified_instructions: usize,
}

impl ModuleState {
    fn of(module: &Module) -> Self {
        Self {
            data: module
                .data_sections
                .iter()
                .map(|s| s.data.clone())
                .collect(),
            functions: module.functions.len(),
            modified_instructions: module
                .functions
                .iter()
                .flat_map(|f| f.instructions())
                .filter(|i| i.meta.modified)
                .count(),
        }
    }
}

/// Bytes that differ from `before` across data sections, and how many sections
/// had any.
fn changed_data(before: &ModuleState, after: &Module) -> (usize, usize) {
    let per_section = before
        .data
        .iter()
        .zip(&after.data_sections)
        .map(|(old, new)| old.iter().zip(&new.data).filter(|(a, b)| a != b).count());
    per_section.fold((0, 0), |(bytes, sections), n| {
        (bytes + n, sections + usize::from(n > 0))
    })
}
