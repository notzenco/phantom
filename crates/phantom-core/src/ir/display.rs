use std::fmt;

use super::block::BasicBlock;
use super::function::Function;
use super::instruction::{Instruction, Opcode};
use super::module::Module;
use super::types::{ImmValue, MemOperand, Operand, PhysReg, VReg};

impl fmt::Display for VReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

impl fmt::Display for PhysReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "p{}", self.0)
    }
}

impl fmt::Display for ImmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.value())
    }
}

impl fmt::Display for MemOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        let mut need_plus = false;

        if let Some(base) = &self.base {
            write!(f, "{base}")?;
            need_plus = true;
        }

        if let Some(index) = &self.index {
            if need_plus {
                write!(f, " + ")?;
            }
            write!(f, "{index}")?;
            if self.scale > 1 {
                write!(f, "*{}", self.scale)?;
            }
            need_plus = true;
        }

        if self.displacement != 0 {
            if need_plus {
                if self.displacement > 0 {
                    write!(f, " + 0x{:x}", self.displacement)?;
                } else {
                    write!(f, " - 0x{:x}", -self.displacement)?;
                }
            } else {
                write!(f, "0x{:x}", self.displacement)?;
            }
        }

        write!(f, "]")
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Reg(vreg) => write!(f, "{vreg}"),
            Operand::Imm(imm) => write!(f, "{imm}"),
            Operand::Mem(mem) => write!(f, "{mem}"),
            Operand::RipRelative(addr) => write!(f, "[rip+0x{addr:x}]"),
        }
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Opcode::Mov => write!(f, "mov"),
            Opcode::Lea => write!(f, "lea"),
            Opcode::Push => write!(f, "push"),
            Opcode::Pop => write!(f, "pop"),
            Opcode::Add => write!(f, "add"),
            Opcode::Sub => write!(f, "sub"),
            Opcode::Imul => write!(f, "imul"),
            Opcode::Xor => write!(f, "xor"),
            Opcode::And => write!(f, "and"),
            Opcode::Or => write!(f, "or"),
            Opcode::Not => write!(f, "not"),
            Opcode::Neg => write!(f, "neg"),
            Opcode::Shl => write!(f, "shl"),
            Opcode::Shr => write!(f, "shr"),
            Opcode::Sar => write!(f, "sar"),
            Opcode::Cmp => write!(f, "cmp"),
            Opcode::Test => write!(f, "test"),
            Opcode::Jmp => write!(f, "jmp"),
            Opcode::Je => write!(f, "je"),
            Opcode::Jne => write!(f, "jne"),
            Opcode::Jg => write!(f, "jg"),
            Opcode::Jge => write!(f, "jge"),
            Opcode::Jl => write!(f, "jl"),
            Opcode::Jle => write!(f, "jle"),
            Opcode::Ja => write!(f, "ja"),
            Opcode::Jae => write!(f, "jae"),
            Opcode::Jb => write!(f, "jb"),
            Opcode::Jbe => write!(f, "jbe"),
            Opcode::Js => write!(f, "js"),
            Opcode::Jns => write!(f, "jns"),
            Opcode::Call => write!(f, "call"),
            Opcode::Ret => write!(f, "ret"),
            Opcode::Nop => write!(f, "nop"),
            Opcode::Syscall => write!(f, "syscall"),
            Opcode::Int => write!(f, "int"),
            Opcode::Cdq => write!(f, "cdq"),
            Opcode::Cqo => write!(f, "cqo"),
            Opcode::Movzx => write!(f, "movzx"),
            Opcode::Movsx => write!(f, "movsx"),
            Opcode::Cmove => write!(f, "cmove"),
            Opcode::Cmovne => write!(f, "cmovne"),
            Opcode::Cmovg => write!(f, "cmovg"),
            Opcode::Cmovl => write!(f, "cmovl"),
            Opcode::Sete => write!(f, "sete"),
            Opcode::Setne => write!(f, "setne"),
            Opcode::Setg => write!(f, "setg"),
            Opcode::Setl => write!(f, "setl"),
            Opcode::Inc => write!(f, "inc"),
            Opcode::Dec => write!(f, "dec"),
            Opcode::Div => write!(f, "div"),
            Opcode::Idiv => write!(f, "idiv"),
            Opcode::Mul => write!(f, "mul"),
            Opcode::RawBytes(bytes) => {
                write!(f, ".bytes")?;
                for b in bytes {
                    write!(f, " {b:02x}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}: {}", self.address, self.opcode)?;
        for (i, op) in self.operands.iter().enumerate() {
            if i == 0 {
                write!(f, " {op}")?;
            } else {
                write!(f, ", {op}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  block_{} ({:016x}..{:016x}):", self.id.0, self.start_addr, self.end_addr)?;
        for instr in &self.instructions {
            writeln!(f, "    {instr}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "function {} @ {:016x} (size={})",
            self.name, self.address, self.size
        )?;
        for block in &self.blocks {
            write!(f, "{block}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "module {} (arch={:?}, format={:?})",
            self.name, self.arch, self.format
        )?;
        for func in &self.functions {
            write!(f, "{func}")?;
        }
        Ok(())
    }
}
