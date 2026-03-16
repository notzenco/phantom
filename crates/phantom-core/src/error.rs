use thiserror::Error;

#[derive(Debug, Error)]
pub enum PhantomError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Lift error: {0}")]
    Lift(String),

    #[error("Emit error: {0}")]
    Emit(String),

    #[error("Pass error: {0}")]
    Pass(String),

    #[error("Pipeline error: {0}")]
    Pipeline(String),

    #[error("Invalid binary: {0}")]
    InvalidBinary(String),

    #[error("Unsupported architecture: {0}")]
    UnsupportedArch(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
}
