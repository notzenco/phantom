use serde::{Deserialize, Serialize};

pub mod error;
pub mod ir;
pub mod pass;
pub mod pipeline;

pub use error::PhantomError;

/// Target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Unknown,
}

/// Binary container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}
