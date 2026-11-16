use std::path::Path;

use anyhow::Result;

/// Display binary metadata.
pub fn run(input: &Path) -> Result<()> {
    let (_, module) = super::load(input)?;

    println!("Binary: {}", input.display());
    println!("Architecture: {:?}", module.arch);
    println!("Format: {:?}", module.format);
    println!("Entry point: {:#x}", module.metadata.entry_point);
    println!("PIE: {}", module.metadata.is_pie);
    println!("Program headers: {}", module.metadata.program_headers.len());
    println!("Section headers: {}", module.metadata.section_headers.len());
    println!("Functions: {}", module.functions.len());
    println!("Data sections: {}", module.data_sections.len());

    for ds in &module.data_sections {
        println!(
            "  {} @ {:#x} ({} bytes, r={} w={} x={})",
            ds.name,
            ds.vaddr,
            ds.data.len(),
            ds.permissions.read,
            ds.permissions.write,
            ds.permissions.execute
        );
    }

    Ok(())
}
