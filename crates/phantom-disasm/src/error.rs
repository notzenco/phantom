use thiserror::Error;

#[derive(Debug, Error)]
pub enum DisasmError {
    #[error("Decode error: {0}")]
    Decode(String),
    #[error("Encode error: {0}")]
    Encode(String),
    #[error("Invalid address: {addr:#x}")]
    InvalidAddress { addr: u64 },
}
