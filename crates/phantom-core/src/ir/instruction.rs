use serde::{Deserialize, Serialize};

use super::types::{DataRef, Operand, OperandSize};

/// Curated set of x86_64 opcodes represented in the IR.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Opcode {
    Mov,
    Lea,
    Push,
    Pop,
    Add,
    Sub,
    Imul,
    Xor,
    And,
    Or,
    Not,
    Neg,
    Shl,
    Shr,
    Sar,
    Cmp,
    Test,
    Jmp,
    Je,
    Jne,
    Jg,
    Jge,
    Jl,
    Jle,
    Ja,
    Jae,
    Jb,
    Jbe,
    Js,
    Jns,
    Call,
    Ret,
    Nop,
    Syscall,
    Int,
    Cdq,
    Cqo,
    Movzx,
    Movsx,
    Cmove,
    Cmovne,
    Cmovg,
    Cmovl,
    Sete,
    Setne,
    Setg,
    Setl,
    Inc,
    Dec,
    Div,
    Idiv,
    Mul,
    /// Opaque bytes that we cannot or choose not to decode.
    RawBytes(Vec<u8>),
}

impl Opcode {
    /// Returns true if this opcode is any kind of jump (conditional or unconditional).
    pub fn is_jump(&self) -> bool {
        matches!(
            self,
            Opcode::Jmp
                | Opcode::Je
                | Opcode::Jne
                | Opcode::Jg
                | Opcode::Jge
                | Opcode::Jl
                | Opcode::Jle
                | Opcode::Ja
                | Opcode::Jae
                | Opcode::Jb
                | Opcode::Jbe
                | Opcode::Js
                | Opcode::Jns
        )
    }

    /// Returns true if this opcode is a conditional jump.
    pub fn is_conditional_jump(&self) -> bool {
        matches!(
            self,
            Opcode::Je
                | Opcode::Jne
                | Opcode::Jg
                | Opcode::Jge
                | Opcode::Jl
                | Opcode::Jle
                | Opcode::Ja
                | Opcode::Jae
                | Opcode::Jb
                | Opcode::Jbe
                | Opcode::Js
                | Opcode::Jns
        )
    }
}

/// Metadata carried alongside each instruction for re-encoding and provenance.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InstructionMeta {
    /// The iced_x86::Code value as u16, used for re-encoding.
    pub iced_code: Option<u16>,
    /// Whether this instruction has been modified by a pass.
    pub modified: bool,
    /// Name of the pass that last modified this instruction.
    pub modified_by: Option<String>,
}

/// A single IR instruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub original_bytes: Vec<u8>,
    pub opcode: Opcode,
    pub operands: Vec<Operand>,
    pub operand_size: OperandSize,
    pub data_refs: Vec<DataRef>,
    pub meta: InstructionMeta,
}

impl Instruction {
    /// Return the size of the original encoded instruction.
    pub fn size(&self) -> usize {
        self.original_bytes.len()
    }

    /// Return whether this instruction has been modified by a pass.
    pub fn is_modified(&self) -> bool {
        self.meta.modified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jmp_is_jump() {
        assert!(Opcode::Jmp.is_jump());
        assert!(!Opcode::Jmp.is_conditional_jump());
    }

    #[test]
    fn conditional_jumps() {
        let conds = [
            Opcode::Je,
            Opcode::Jne,
            Opcode::Jg,
            Opcode::Jge,
            Opcode::Jl,
            Opcode::Jle,
            Opcode::Ja,
            Opcode::Jae,
            Opcode::Jb,
            Opcode::Jbe,
            Opcode::Js,
            Opcode::Jns,
        ];
        for op in &conds {
            assert!(op.is_jump(), "{op:?} should be a jump");
            assert!(op.is_conditional_jump(), "{op:?} should be conditional");
        }
    }

    #[test]
    fn non_jumps() {
        let non_jumps = [
            Opcode::Mov,
            Opcode::Add,
            Opcode::Call,
            Opcode::Ret,
            Opcode::Nop,
        ];
        for op in &non_jumps {
            assert!(!op.is_jump(), "{op:?} should not be a jump");
            assert!(!op.is_conditional_jump(), "{op:?} should not be conditional");
        }
    }

    #[test]
    fn instruction_size_and_modified() {
        let instr = Instruction {
            address: 0x401000,
            original_bytes: vec![0x90],
            opcode: Opcode::Nop,
            operands: vec![],
            operand_size: OperandSize::Byte,
            data_refs: vec![],
            meta: InstructionMeta::default(),
        };
        assert_eq!(instr.size(), 1);
        assert!(!instr.is_modified());
    }
}
