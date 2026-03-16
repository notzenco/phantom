pub mod elf;
pub mod error;

pub use elf::ElfFrontend;
pub use error::FrontendError;

use phantom_core::ir::module::Module;

/// Trait for binary lifters.
pub trait Frontend {
    /// Check if this frontend can handle the given binary data.
    fn can_handle(&self, data: &[u8]) -> bool;
    /// Lift the binary data into a PhIR Module.
    fn lift(&self, data: &[u8]) -> Result<Module, FrontendError>;
}

/// Auto-detect the binary format and return the appropriate frontend.
pub fn detect_frontend(data: &[u8]) -> Option<Box<dyn Frontend>> {
    let elf = ElfFrontend::new();
    if elf.can_handle(data) {
        return Some(Box::new(elf));
    }
    None
}
