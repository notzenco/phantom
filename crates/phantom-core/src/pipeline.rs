use tracing::info;

use crate::error::PhantomError;
use crate::ir::module::Module;
use crate::pass::Pass;

/// Ordered pipeline of transformation passes.
pub struct Pipeline {
    passes: Vec<Box<dyn Pass>>,
}

impl Pipeline {
    /// Create a new empty pipeline.
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    /// Append a pass to the end of the pipeline.
    pub fn add_pass(&mut self, pass: Box<dyn Pass>) {
        self.passes.push(pass);
    }

    /// Execute all passes sequentially on the given module.
    pub fn run(&self, module: &mut Module) -> Result<(), PhantomError> {
        for (i, pass) in self.passes.iter().enumerate() {
            let pass_info = pass.info();
            info!(
                "Running pass [{}/{}]: {} — {}",
                i + 1,
                self.passes.len(),
                pass_info.name,
                pass_info.description
            );
            pass.run(module).map_err(|e| {
                PhantomError::Pipeline(format!("Pass '{}' failed: {e}", pass_info.name))
            })?;
        }
        Ok(())
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pass::{Pass, PassInfo};
    use crate::{Architecture, BinaryFormat};
    use std::sync::{Arc, Mutex};

    struct CountingPass {
        counter: Arc<Mutex<Vec<usize>>>,
        index: usize,
    }

    impl Pass for CountingPass {
        fn info(&self) -> PassInfo {
            PassInfo {
                name: format!("counting-pass-{}", self.index),
                description: "Increments counter".into(),
            }
        }

        fn run(&self, _module: &mut Module) -> Result<(), PhantomError> {
            self.counter.lock().unwrap().push(self.index);
            Ok(())
        }
    }

    #[test]
    fn pipeline_executes_in_order() {
        let counter = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = Pipeline::new();

        for i in 0..3 {
            pipeline.add_pass(Box::new(CountingPass {
                counter: Arc::clone(&counter),
                index: i,
            }));
        }

        let mut module = Module::new("test".into(), Architecture::X86_64, BinaryFormat::Elf);
        pipeline.run(&mut module).unwrap();

        let order = counter.lock().unwrap();
        assert_eq!(*order, vec![0, 1, 2]);
    }

    #[test]
    fn empty_pipeline_succeeds() {
        let pipeline = Pipeline::new();
        let mut module = Module::new("test".into(), Architecture::X86_64, BinaryFormat::Elf);
        assert!(pipeline.run(&mut module).is_ok());
    }

    struct FailingPass;

    impl Pass for FailingPass {
        fn info(&self) -> PassInfo {
            PassInfo {
                name: "failing".into(),
                description: "Always fails".into(),
            }
        }

        fn run(&self, _module: &mut Module) -> Result<(), PhantomError> {
            Err(PhantomError::Pass("intentional failure".into()))
        }
    }

    #[test]
    fn pipeline_stops_on_failure() {
        let counter = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = Pipeline::new();

        pipeline.add_pass(Box::new(CountingPass {
            counter: Arc::clone(&counter),
            index: 0,
        }));
        pipeline.add_pass(Box::new(FailingPass));
        pipeline.add_pass(Box::new(CountingPass {
            counter: Arc::clone(&counter),
            index: 2,
        }));

        let mut module = Module::new("test".into(), Architecture::X86_64, BinaryFormat::Elf);
        let result = pipeline.run(&mut module);
        assert!(result.is_err());

        let order = counter.lock().unwrap();
        // Only the first pass should have run
        assert_eq!(*order, vec![0]);
    }
}
