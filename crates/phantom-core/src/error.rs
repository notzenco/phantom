use thiserror::Error;

#[derive(Debug, Error)]
pub enum PhantomError {
    #[error("Pass error: {0}")]
    Pass(String),

    #[error("Pipeline error: {0}")]
    Pipeline(String),
}
