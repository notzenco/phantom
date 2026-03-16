use crate::error::PhantomError;
use crate::ir::module::Module;

/// Metadata about a pass.
#[derive(Clone, Debug)]
pub struct PassInfo {
    pub name: String,
    pub description: String,
}

/// Trait for a transformation pass over the IR module.
///
/// Passes are the primary mechanism for analyzing and transforming the IR.
/// Each pass receives a mutable reference to the entire module.
pub trait Pass {
    /// Return metadata about this pass.
    fn info(&self) -> PassInfo;

    /// Execute the pass on the given module.
    fn run(&self, module: &mut Module) -> Result<(), PhantomError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Architecture, BinaryFormat};

    struct NoOpPass;

    impl Pass for NoOpPass {
        fn info(&self) -> PassInfo {
            PassInfo {
                name: "no-op".into(),
                description: "Does nothing".into(),
            }
        }

        fn run(&self, _module: &mut Module) -> Result<(), PhantomError> {
            Ok(())
        }
    }

    #[test]
    fn noop_pass_runs() {
        let pass = NoOpPass;
        let mut module = Module::new("test".into(), Architecture::X86_64, BinaryFormat::Elf);
        assert!(pass.run(&mut module).is_ok());
        assert_eq!(pass.info().name, "no-op");
    }
}
