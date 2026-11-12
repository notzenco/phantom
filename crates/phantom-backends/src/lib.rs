mod common;
pub mod elf;
pub mod error;
pub mod pe;

pub use elf::ElfBackend;
pub use error::BackendError;
pub use pe::PeBackend;

use phantom_core::ir::module::Module;
use phantom_core::BinaryFormat;

/// Trait for binary emitters.
pub trait Backend {
    /// Emit the Module back to binary form.
    fn emit(&self, module: &Module) -> Result<Vec<u8>, BackendError>;
}

/// The emitter for a lifted module's binary format, if one exists.
pub fn backend_for(format: BinaryFormat) -> Option<Box<dyn Backend>> {
    match format {
        BinaryFormat::Elf => Some(Box::new(ElfBackend::new())),
        BinaryFormat::Pe => Some(Box::new(PeBackend::new())),
        BinaryFormat::MachO | BinaryFormat::Unknown => None,
    }
}
