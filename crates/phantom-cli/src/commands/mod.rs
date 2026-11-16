pub mod info;
pub mod inspect;
pub mod profiles;
pub mod protect;

use std::path::Path;

use anyhow::{bail, Context, Result};
use phantom_core::ir::module::Module;
use phantom_frontends::detect_frontend;

/// Read `path` and lift it, with errors that name the file and, for formats
/// Phantom cannot lift, what the file appears to be.
pub(crate) fn load(path: &Path) -> Result<(Vec<u8>, Module)> {
    let data = std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let Some(frontend) = detect_frontend(&data) else {
        bail!("{}: {}", path.display(), describe_unsupported(&data));
    };
    let module = frontend
        .lift(&data)
        .with_context(|| format!("Failed to lift {}", path.display()))?;
    Ok((data, module))
}

fn describe_unsupported(data: &[u8]) -> &'static str {
    const MACHO_MAGICS: [[u8; 4]; 5] = [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
    ];
    if data.len() >= 4 && MACHO_MAGICS.iter().any(|m| data[..4] == m[..]) {
        "Mach-O binaries are not supported yet (see README: Why not Mach-O yet)"
    } else if data.starts_with(b"MZ") {
        "DOS executable without a valid PE header; only x86-64 PE executables are supported"
    } else {
        "unrecognised file format; expected an ELF or PE executable"
    }
}
