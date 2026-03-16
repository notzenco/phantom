pub mod elf;
pub mod error;

pub use elf::ElfBackend;
pub use error::BackendError;

use phantom_core::ir::module::Module;

/// Trait for binary emitters.
pub trait Backend {
    /// Emit the Module back to binary form.
    fn emit(&self, module: &Module) -> Result<Vec<u8>, BackendError>;
}
