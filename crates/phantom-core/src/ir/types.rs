use serde::{Deserialize, Serialize};

/// Virtual register — used throughout the IR.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VReg(pub u32);

/// Physical register ID (iced-x86 Register cast to u32).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PhysReg(pub u32);

/// Immediate value of various sizes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImmValue {
    Imm8(u8),
    Imm16(u16),
    Imm32(u32),
    Imm64(u64),
}

impl ImmValue {
    /// Return the value as a u64 regardless of width.
    pub fn value(&self) -> u64 {
        match self {
            ImmValue::Imm8(v) => *v as u64,
            ImmValue::Imm16(v) => *v as u64,
            ImmValue::Imm32(v) => *v as u64,
            ImmValue::Imm64(v) => *v,
        }
    }
}

/// Memory operand for load/store instructions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemOperand {
    pub base: Option<VReg>,
    pub index: Option<VReg>,
    pub scale: u8,
    pub displacement: i64,
    pub segment: Option<VReg>,
}

/// Operand in an IR instruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Operand {
    Reg(VReg),
    Imm(ImmValue),
    Mem(MemOperand),
    RipRelative(u64),
}

/// Operand size classification.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandSize {
    Byte,
    Word,
    Dword,
    Qword,
    Xmm,
    Ymm,
}

impl OperandSize {
    /// Return the size in bits.
    pub fn bits(&self) -> u32 {
        match self {
            OperandSize::Byte => 8,
            OperandSize::Word => 16,
            OperandSize::Dword => 32,
            OperandSize::Qword => 64,
            OperandSize::Xmm => 128,
            OperandSize::Ymm => 256,
        }
    }
}

/// Reference to data in a data section.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataRef {
    pub vaddr: u64,
    pub size: usize,
    pub data: Vec<u8>,
    pub is_string: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vreg_construction() {
        let r = VReg(42);
        assert_eq!(r.0, 42);
    }

    #[test]
    fn physreg_construction() {
        let r = PhysReg(7);
        assert_eq!(r.0, 7);
    }

    #[test]
    fn operand_variants() {
        let reg_op = Operand::Reg(VReg(0));
        assert!(matches!(reg_op, Operand::Reg(VReg(0))));

        let imm_op = Operand::Imm(ImmValue::Imm64(0xdead));
        assert!(matches!(imm_op, Operand::Imm(ImmValue::Imm64(0xdead))));

        let mem_op = Operand::Mem(MemOperand {
            base: Some(VReg(1)),
            index: None,
            scale: 1,
            displacement: -8,
            segment: None,
        });
        assert!(matches!(mem_op, Operand::Mem(_)));

        let rip_op = Operand::RipRelative(0x401000);
        assert!(matches!(rip_op, Operand::RipRelative(0x401000)));
    }

    #[test]
    fn imm_value_returns_correct_u64() {
        assert_eq!(ImmValue::Imm8(0xff).value(), 255);
        assert_eq!(ImmValue::Imm16(0x1234).value(), 0x1234);
        assert_eq!(ImmValue::Imm32(0xdeadbeef).value(), 0xdeadbeef);
        assert_eq!(ImmValue::Imm64(0x123456789abcdef0).value(), 0x123456789abcdef0);
    }

    #[test]
    fn operand_size_bits() {
        assert_eq!(OperandSize::Byte.bits(), 8);
        assert_eq!(OperandSize::Word.bits(), 16);
        assert_eq!(OperandSize::Dword.bits(), 32);
        assert_eq!(OperandSize::Qword.bits(), 64);
        assert_eq!(OperandSize::Xmm.bits(), 128);
        assert_eq!(OperandSize::Ymm.bits(), 256);
    }
}
