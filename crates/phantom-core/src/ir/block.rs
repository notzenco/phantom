use serde::{Deserialize, Serialize};

use super::instruction::{Instruction, Opcode};

/// Unique identifier for a basic block within a function.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockId(pub u32);

/// Target of a call instruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CallTarget {
    Direct(u64),
    Named(String),
}

/// Terminator describes how control flow leaves a basic block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Terminator {
    Jump(BlockId),
    Branch {
        opcode: Opcode,
        true_target: BlockId,
        false_target: BlockId,
    },
    Call {
        target: CallTarget,
        return_block: Option<BlockId>,
    },
    Return,
    IndirectJump,
    IndirectCall,
    Fallthrough(BlockId),
    Unreachable,
}

/// A basic block: a straight-line sequence of instructions with a single entry
/// and a terminator that describes outgoing control flow.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub start_addr: u64,
    pub end_addr: u64,
    pub instructions: Vec<Instruction>,
    pub terminator: Terminator,
}

impl BasicBlock {
    /// Immutable reference to the instruction list.
    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    /// Mutable reference to the instruction list.
    pub fn instructions_mut(&mut self) -> &mut Vec<Instruction> {
        &mut self.instructions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::instruction::{InstructionMeta, Opcode};
    use crate::ir::types::OperandSize;

    #[test]
    fn basic_block_construction() {
        let nop = Instruction {
            address: 0x1000,
            original_bytes: vec![0x90],
            opcode: Opcode::Nop,
            operands: vec![],
            operand_size: OperandSize::Byte,
            data_refs: vec![],
            meta: InstructionMeta::default(),
        };
        let bb = BasicBlock {
            id: BlockId(0),
            start_addr: 0x1000,
            end_addr: 0x1001,
            instructions: vec![nop],
            terminator: Terminator::Return,
        };
        assert_eq!(bb.id, BlockId(0));
        assert_eq!(bb.instructions().len(), 1);
        assert_eq!(bb.start_addr, 0x1000);
    }

    #[test]
    fn basic_block_mut_instructions() {
        let mut bb = BasicBlock {
            id: BlockId(1),
            start_addr: 0x2000,
            end_addr: 0x2000,
            instructions: vec![],
            terminator: Terminator::Unreachable,
        };
        bb.instructions_mut().push(Instruction {
            address: 0x2000,
            original_bytes: vec![0xcc],
            opcode: Opcode::Int,
            operands: vec![],
            operand_size: OperandSize::Byte,
            data_refs: vec![],
            meta: InstructionMeta::default(),
        });
        assert_eq!(bb.instructions().len(), 1);
    }
}
