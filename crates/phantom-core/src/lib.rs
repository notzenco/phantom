use serde::{Deserialize, Serialize};

pub mod error;
pub mod ir;
pub mod pass;
pub mod pipeline;

pub use error::PhantomError;
pub use ir::{
    block::{BasicBlock, BlockId, CallTarget, Terminator},
    function::{Function, RawCodeFixup, RawCodeFixupTarget},
    instruction::{Instruction, InstructionMeta, Opcode},
    module::{BinaryMetadata, DataSection, Module, ProgramHeader, Relocation, SectionHeader, SectionPermissions},
    types::{DataRef, ImmValue, MemOperand, Operand, OperandSize, PhysReg, VReg},
};
pub use pass::{Pass, PassInfo};
pub use pipeline::Pipeline;

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
