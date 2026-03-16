use thiserror::Error;

#[derive(Debug, Error)]
pub enum FrontendError {
    #[error("ELF parse error: {0}")]
    ElfParse(String),
    #[error("Unsupported binary format")]
    UnsupportedFormat,
    #[error("No executable code found")]
    NoCode,
    #[error("Lift error: {0}")]
    Lift(String),
    #[error("Disassembly error: {0}")]
    Disasm(#[from] phantom_disasm::DisasmError),
}
