use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("Emit error: {0}")]
    Emit(String),
    #[error("Encode error: {0}")]
    Encode(String),
    #[error("No raw binary in module")]
    NoRawBinary,
    #[error("Function {name} at {addr:#x} grew from {original} to {new} bytes — too large to patch")]
    FunctionGrew {
        name: String,
        addr: u64,
        original: usize,
        new: usize,
    },
    #[error("Section not found: {0}")]
    SectionNotFound(String),
    #[error("Disassembly error: {0}")]
    Disasm(#[from] phantom_disasm::DisasmError),
}
