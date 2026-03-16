use std::collections::{BTreeSet, HashMap};

use goblin::elf::{
    header::{EM_386, EM_X86_64, ET_DYN},
    sym::STT_FUNC,
    Elf,
};
use iced_x86::{Mnemonic, OpKind, Register};
use tracing::{debug, trace};

use phantom_core::{
    ir::{
        block::{BasicBlock, BlockId, CallTarget, Terminator},
        function::Function,
        instruction::{Instruction, InstructionMeta, Opcode},
        module::{
            BinaryMetadata, DataSection, Module, ProgramHeader, SectionHeader, SectionPermissions,
        },
        types::{DataRef, ImmValue, MemOperand, Operand, OperandSize, PhysReg, VReg},
    },
    Architecture, BinaryFormat,
};
use phantom_disasm::iced::DecodedInsn;
use phantom_disasm::IcedDisassembler;

use crate::{Frontend, FrontendError};

/// ELF binary lifter — parses ELF files and lifts them to PhIR.
pub struct ElfFrontend;

impl ElfFrontend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ElfFrontend {
    fn default() -> Self {
        Self::new()
    }
}

impl Frontend for ElfFrontend {
    fn can_handle(&self, data: &[u8]) -> bool {
        data.len() >= 4 && data[..4] == [0x7f, b'E', b'L', b'F']
    }

    fn lift(&self, data: &[u8]) -> Result<Module, FrontendError> {
        lift_elf(data)
    }
}

/// Main ELF lifting entry point.
fn lift_elf(data: &[u8]) -> Result<Module, FrontendError> {
    let elf = Elf::parse(data).map_err(|e| FrontendError::ElfParse(e.to_string()))?;

    let arch = match elf.header.e_machine {
        EM_X86_64 => Architecture::X86_64,
        EM_386 => Architecture::X86,
        _ => return Err(FrontendError::UnsupportedFormat),
    };

    let bitness: u32 = match arch {
        Architecture::X86_64 => 64,
        Architecture::X86 => 32,
        _ => return Err(FrontendError::UnsupportedFormat),
    };

    let mut module = Module::new("elf_module".into(), arch, BinaryFormat::Elf);

    // Extract binary metadata.
    module.metadata = extract_metadata(&elf);

    // Extract data sections.
    module.data_sections = extract_data_sections(&elf, data);

    // Store raw binary.
    module.raw_binary = data.to_vec();

    // Lift functions from symbol table.
    let functions = lift_functions(&elf, data, bitness, &module.data_sections)?;
    module.functions = functions;

    debug!(
        functions = module.functions.len(),
        data_sections = module.data_sections.len(),
        "ELF lift complete"
    );

    Ok(module)
}

/// Extract BinaryMetadata from the parsed ELF.
fn extract_metadata(elf: &Elf) -> BinaryMetadata {
    let entry_point = elf.header.e_entry;
    let is_pie = elf.header.e_type == ET_DYN;

    let program_headers = elf
        .program_headers
        .iter()
        .map(|ph| ProgramHeader {
            p_type: ph.p_type,
            p_flags: ph.p_flags,
            p_offset: ph.p_offset,
            p_vaddr: ph.p_vaddr,
            p_paddr: ph.p_paddr,
            p_filesz: ph.p_filesz,
            p_memsz: ph.p_memsz,
            p_align: ph.p_align,
        })
        .collect();

    let section_headers = elf
        .section_headers
        .iter()
        .map(|sh| {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("")
                .to_string();
            SectionHeader {
                name,
                sh_type: sh.sh_type,
                sh_flags: sh.sh_flags,
                sh_addr: sh.sh_addr,
                sh_offset: sh.sh_offset,
                sh_size: sh.sh_size,
                sh_link: sh.sh_link,
                sh_info: sh.sh_info,
                sh_addralign: sh.sh_addralign,
                sh_entsize: sh.sh_entsize,
            }
        })
        .collect();

    BinaryMetadata {
        entry_point,
        program_headers,
        section_headers,
        is_pie,
    }
}

/// Extract data sections (.rodata, .data, .bss, .data.rel.ro).
fn extract_data_sections(elf: &Elf, data: &[u8]) -> Vec<DataSection> {
    let data_section_names = [".rodata", ".data", ".bss", ".data.rel.ro"];
    let mut sections = Vec::new();

    for sh in &elf.section_headers {
        let name = match elf.shdr_strtab.get_at(sh.sh_name) {
            Some(n) => n,
            None => continue,
        };

        if !data_section_names.contains(&name) {
            continue;
        }

        let permissions = match name {
            ".rodata" | ".data.rel.ro" => SectionPermissions {
                read: true,
                write: false,
                execute: false,
            },
            ".data" | ".bss" => SectionPermissions {
                read: true,
                write: true,
                execute: false,
            },
            _ => continue,
        };

        let section_data = if name == ".bss" {
            Vec::new()
        } else {
            let offset = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            if offset + size <= data.len() {
                data[offset..offset + size].to_vec()
            } else {
                Vec::new()
            }
        };

        debug!(name, vaddr = sh.sh_addr, size = section_data.len(), "extracted data section");

        sections.push(DataSection {
            name: name.to_string(),
            vaddr: sh.sh_addr,
            file_offset: sh.sh_offset,
            data: section_data,
            permissions,
            relocations: vec![],
        });
    }

    sections
}

/// Find the section that contains a given virtual address and return the file offset for that address.
fn find_file_offset_for_addr(elf: &Elf, addr: u64) -> Option<usize> {
    for sh in &elf.section_headers {
        if addr >= sh.sh_addr && addr < sh.sh_addr + sh.sh_size {
            let offset_in_section = (addr - sh.sh_addr) as usize;
            return Some(sh.sh_offset as usize + offset_in_section);
        }
    }
    None
}

/// Lift all function symbols from the ELF.
fn lift_functions(
    elf: &Elf,
    data: &[u8],
    bitness: u32,
    data_sections: &[DataSection],
) -> Result<Vec<Function>, FrontendError> {
    let disasm = IcedDisassembler::new(bitness);
    let mut functions = Vec::new();

    for sym in elf.syms.iter() {
        if sym.st_type() != STT_FUNC || sym.st_size == 0 {
            continue;
        }

        let func_addr = sym.st_value;
        let func_size = sym.st_size;

        let name = elf
            .strtab
            .get_at(sym.st_name)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("sub_{:x}", func_addr));

        // Find the code bytes for this function.
        let file_offset = match find_file_offset_for_addr(elf, func_addr) {
            Some(off) => off,
            None => {
                debug!(name, addr = func_addr, "skipping function: cannot find file offset");
                continue;
            }
        };

        let end = file_offset + func_size as usize;
        if end > data.len() {
            debug!(name, addr = func_addr, "skipping function: extends beyond file");
            continue;
        }

        let code_bytes = &data[file_offset..end];

        match lift_function(&name, func_addr, func_size, code_bytes, &disasm, data_sections) {
            Ok(func) => {
                debug!(
                    name = func.name,
                    blocks = func.blocks.len(),
                    "lifted function"
                );
                functions.push(func);
            }
            Err(e) => {
                debug!(name, addr = func_addr, error = %e, "failed to lift function, skipping");
            }
        }
    }

    Ok(functions)
}

/// Lift a single function from decoded bytes.
fn lift_function(
    name: &str,
    func_addr: u64,
    func_size: u64,
    code_bytes: &[u8],
    disasm: &IcedDisassembler,
    data_sections: &[DataSection],
) -> Result<Function, FrontendError> {
    let decoded = disasm.decode_all(code_bytes, func_addr)?;

    if decoded.is_empty() {
        return Err(FrontendError::Lift(format!(
            "no instructions decoded for function {name}"
        )));
    }

    trace!(name, insn_count = decoded.len(), "decoded instructions for function");

    let mut func = Function::new(name.to_string(), func_addr, func_size);
    let func_end = func_addr + func_size;

    // First pass: find block boundaries (leaders).
    let leaders = find_leaders(&decoded, func_addr, func_end);

    // Second pass: build basic blocks.
    let (blocks, addr_to_block) =
        build_blocks(&decoded, &leaders, &mut func, data_sections)?;

    func.blocks = blocks;

    // Third pass: assign terminators.
    assign_terminators(&mut func, &decoded, &addr_to_block, func_end);

    trace!(name, blocks = func.blocks.len(), "built basic blocks");

    Ok(func)
}

/// Find all "leader" addresses (basic block start points) within a function.
fn find_leaders(decoded: &[DecodedInsn], func_addr: u64, func_end: u64) -> Vec<u64> {
    let mut leaders = BTreeSet::new();
    leaders.insert(func_addr);

    for (i, insn) in decoded.iter().enumerate() {
        let mnemonic = insn.mnemonic;
        let next_addr = insn.address + insn.bytes.len() as u64;

        if is_branch_mnemonic(mnemonic) || mnemonic == Mnemonic::Jmp {
            // The fall-through address is a leader (if within function bounds).
            if next_addr < func_end {
                leaders.insert(next_addr);
            }

            // The branch target is a leader (if within function bounds).
            if let Some(target) = branch_target(&insn.instruction) {
                if target >= func_addr && target < func_end {
                    leaders.insert(target);
                }
            }
        } else if mnemonic == Mnemonic::Call {
            // Instruction after a call is a leader.
            if next_addr < func_end && i + 1 < decoded.len() {
                leaders.insert(next_addr);
            }
        }
    }

    leaders.into_iter().collect()
}

/// Build basic blocks from decoded instructions using the computed leaders.
/// Returns the list of blocks and a map from address to BlockId.
fn build_blocks(
    decoded: &[DecodedInsn],
    leaders: &[u64],
    func: &mut Function,
    data_sections: &[DataSection],
) -> Result<(Vec<BasicBlock>, HashMap<u64, BlockId>), FrontendError> {
    let mut blocks = Vec::new();
    let mut addr_to_block: HashMap<u64, BlockId> = HashMap::new();
    let mut reg_cache: HashMap<u32, VReg> = HashMap::new();

    let mut insn_idx = 0;

    for (block_id_counter, (leader_idx, &leader_addr)) in
        (0_u32..).zip(leaders.iter().enumerate())
    {
        let block_id = BlockId(block_id_counter);
        addr_to_block.insert(leader_addr, block_id);

        // Determine the end of this block: next leader or end of instructions.
        let next_leader = leaders.get(leader_idx + 1).copied();

        let mut instructions = Vec::new();
        let mut block_end_addr = leader_addr;

        while insn_idx < decoded.len() {
            let di = &decoded[insn_idx];

            // If this instruction's address is at or past the next leader, stop.
            if let Some(nl) = next_leader {
                if di.address >= nl {
                    break;
                }
            }

            let phir_insn =
                translate_instruction(di, func, &mut reg_cache, data_sections);
            block_end_addr = di.address + di.bytes.len() as u64;
            instructions.push(phir_insn);
            insn_idx += 1;
        }

        blocks.push(BasicBlock {
            id: block_id,
            start_addr: leader_addr,
            end_addr: block_end_addr,
            instructions,
            terminator: Terminator::Unreachable, // placeholder, set in third pass
        });
    }

    Ok((blocks, addr_to_block))
}

/// Assign terminators to each basic block based on the last instruction.
fn assign_terminators(
    func: &mut Function,
    decoded: &[DecodedInsn],
    addr_to_block: &HashMap<u64, BlockId>,
    func_end: u64,
) {
    // Build a map from address to DecodedInsn for quick lookup.
    let insn_map: HashMap<u64, &DecodedInsn> = decoded.iter().map(|d| (d.address, d)).collect();

    let block_count = func.blocks.len();
    for block_idx in 0..block_count {
        let block = &func.blocks[block_idx];
        let block_id = block.id;
        let block_end = block.end_addr;

        // Find the last instruction in this block.
        let last_insn_addr = match block.instructions.last() {
            Some(insn) => insn.address,
            None => {
                // Empty block — leave as unreachable.
                continue;
            }
        };

        let di = match insn_map.get(&last_insn_addr) {
            Some(di) => di,
            None => continue,
        };

        let mnemonic = di.mnemonic;
        let next_block = addr_to_block.get(&block_end).copied();

        let terminator = if mnemonic == Mnemonic::Ret {
            Terminator::Return
        } else if mnemonic == Mnemonic::Jmp {
            // Unconditional jump.
            if let Some(target) = branch_target(&di.instruction) {
                match addr_to_block.get(&target) {
                    Some(&target_block) => Terminator::Jump(target_block),
                    None => {
                        // Jump target outside function — treat as indirect/external.
                        Terminator::Unreachable
                    }
                }
            } else {
                // Indirect jump (register or memory).
                Terminator::IndirectJump
            }
        } else if is_branch_mnemonic(mnemonic) {
            // Conditional branch.
            let opcode = mnemonic_to_opcode(mnemonic);
            if let Some(target) = branch_target(&di.instruction) {
                let true_target = addr_to_block
                    .get(&target)
                    .copied()
                    .unwrap_or(block_id);
                let false_target = next_block.unwrap_or(block_id);
                Terminator::Branch {
                    opcode,
                    true_target,
                    false_target,
                }
            } else {
                // Conditional branch with unknown target — shouldn't happen normally.
                Terminator::Unreachable
            }
        } else if mnemonic == Mnemonic::Call {
            let call_target = if let Some(target) = branch_target(&di.instruction) {
                CallTarget::Direct(target)
            } else {
                // Indirect call — use 0 as placeholder.
                CallTarget::Direct(0)
            };
            Terminator::Call {
                target: call_target,
                return_block: next_block,
            }
        } else if block_end < func_end {
            // Normal fallthrough.
            match next_block {
                Some(nb) => Terminator::Fallthrough(nb),
                None => Terminator::Unreachable,
            }
        } else {
            // Last block, no explicit terminator.
            Terminator::Unreachable
        };

        func.blocks[block_idx].terminator = terminator;
    }
}

/// Translate a single decoded instruction into a PhIR instruction.
fn translate_instruction(
    di: &DecodedInsn,
    func: &mut Function,
    reg_cache: &mut HashMap<u32, VReg>,
    data_sections: &[DataSection],
) -> Instruction {
    let opcode = mnemonic_to_opcode(di.mnemonic);
    let operand_size = determine_operand_size(&di.instruction);
    let operands = translate_operands(di, func, reg_cache);
    let mut data_refs = Vec::new();

    // Detect data references from RIP-relative operands.
    detect_data_refs(&di.instruction, data_sections, &mut data_refs);

    Instruction {
        address: di.address,
        original_bytes: di.bytes.clone(),
        opcode,
        operands,
        operand_size,
        data_refs,
        meta: InstructionMeta {
            iced_code: Some(di.code as u16),
            modified: false,
            modified_by: None,
        },
    }
}

/// Translate operands from an iced-x86 instruction to PhIR operands.
fn translate_operands(
    di: &DecodedInsn,
    func: &mut Function,
    reg_cache: &mut HashMap<u32, VReg>,
) -> Vec<Operand> {
    let insn = &di.instruction;
    let mut operands = Vec::new();

    for i in 0..insn.op_count() {
        let op = match insn.op_kind(i) {
            OpKind::Register => {
                let reg = insn.op_register(i);
                let vreg = get_or_alloc_vreg(func, reg as u32, reg_cache);
                Operand::Reg(vreg)
            }
            OpKind::NearBranch16 => {
                Operand::Imm(ImmValue::Imm16(insn.near_branch16()))
            }
            OpKind::NearBranch32 => {
                Operand::Imm(ImmValue::Imm32(insn.near_branch32()))
            }
            OpKind::NearBranch64 => {
                Operand::Imm(ImmValue::Imm64(insn.near_branch64()))
            }
            OpKind::FarBranch16 => {
                Operand::Imm(ImmValue::Imm16(insn.far_branch16()))
            }
            OpKind::FarBranch32 => {
                Operand::Imm(ImmValue::Imm32(insn.far_branch32()))
            }
            OpKind::Immediate8 => {
                Operand::Imm(ImmValue::Imm8(insn.immediate8()))
            }
            OpKind::Immediate8_2nd => {
                Operand::Imm(ImmValue::Imm8(insn.immediate8_2nd()))
            }
            OpKind::Immediate16 => {
                Operand::Imm(ImmValue::Imm16(insn.immediate16()))
            }
            OpKind::Immediate32 => {
                Operand::Imm(ImmValue::Imm32(insn.immediate32()))
            }
            OpKind::Immediate64 => {
                Operand::Imm(ImmValue::Imm64(insn.immediate64()))
            }
            OpKind::Immediate8to16 => {
                Operand::Imm(ImmValue::Imm16(insn.immediate8to16() as u16))
            }
            OpKind::Immediate8to32 => {
                Operand::Imm(ImmValue::Imm32(insn.immediate8to32() as u32))
            }
            OpKind::Immediate8to64 => {
                Operand::Imm(ImmValue::Imm64(insn.immediate8to64() as u64))
            }
            OpKind::Immediate32to64 => {
                Operand::Imm(ImmValue::Imm64(insn.immediate32to64() as u64))
            }
            OpKind::Memory => {
                if insn.is_ip_rel_memory_operand() {
                    let target = insn.ip_rel_memory_address();
                    Operand::RipRelative(target)
                } else {
                    let base = {
                        let reg = insn.memory_base();
                        if reg != Register::None {
                            Some(get_or_alloc_vreg(func, reg as u32, reg_cache))
                        } else {
                            None
                        }
                    };
                    let index = {
                        let reg = insn.memory_index();
                        if reg != Register::None {
                            Some(get_or_alloc_vreg(func, reg as u32, reg_cache))
                        } else {
                            None
                        }
                    };
                    let segment = {
                        let reg = insn.segment_prefix();
                        if reg != Register::None {
                            Some(get_or_alloc_vreg(func, reg as u32, reg_cache))
                        } else {
                            None
                        }
                    };
                    Operand::Mem(MemOperand {
                        base,
                        index,
                        scale: insn.memory_index_scale() as u8,
                        displacement: insn.memory_displacement64() as i64,
                        segment,
                    })
                }
            }
            _ => {
                // For any unhandled operand kinds, encode as Imm(0).
                Operand::Imm(ImmValue::Imm64(0))
            }
        };
        operands.push(op);
    }

    operands
}

/// Detect data references from RIP-relative memory operands.
fn detect_data_refs(
    insn: &iced_x86::Instruction,
    data_sections: &[DataSection],
    data_refs: &mut Vec<DataRef>,
) {
    if !insn.is_ip_rel_memory_operand() {
        return;
    }

    let target = insn.ip_rel_memory_address();

    for section in data_sections {
        let section_end = section.vaddr + section.data.len() as u64;
        if target >= section.vaddr && target < section_end {
            let offset = (target - section.vaddr) as usize;
            // Use remaining bytes in section as the referenced data size.
            let remaining = section.data.len() - offset;
            // Heuristic: take up to 256 bytes or until a null terminator for strings.
            let slice = &section.data[offset..];

            // Find a reasonable size: up to null byte or 256 bytes.
            let size = slice
                .iter()
                .position(|&b| b == 0)
                .map(|p| p + 1) // include the null terminator
                .unwrap_or(remaining.min(256));

            let data_bytes = slice[..size].to_vec();
            let is_string = is_printable_string(&data_bytes);

            data_refs.push(DataRef {
                vaddr: target,
                size,
                data: data_bytes,
                is_string,
            });
            break;
        }
    }
}

/// Check if a byte slice looks like a printable ASCII string (optionally null-terminated).
fn is_printable_string(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Strip trailing null if present.
    let content = if data.last() == Some(&0) {
        &data[..data.len() - 1]
    } else {
        data
    };

    if content.is_empty() {
        return false;
    }

    content.iter().all(|&b| {
        (0x20..=0x7e).contains(&b) // printable ASCII
            || b == b'\n'
            || b == b'\r'
            || b == b'\t'
    })
}

/// Get or allocate a VReg for a physical register.
fn get_or_alloc_vreg(
    func: &mut Function,
    phys_reg_id: u32,
    reg_cache: &mut HashMap<u32, VReg>,
) -> VReg {
    *reg_cache
        .entry(phys_reg_id)
        .or_insert_with(|| func.alloc_vreg(PhysReg(phys_reg_id)))
}

/// Map an iced-x86 Mnemonic to a PhIR Opcode.
fn mnemonic_to_opcode(mnemonic: Mnemonic) -> Opcode {
    match mnemonic {
        Mnemonic::Mov => Opcode::Mov,
        Mnemonic::Lea => Opcode::Lea,
        Mnemonic::Push => Opcode::Push,
        Mnemonic::Pop => Opcode::Pop,
        Mnemonic::Add => Opcode::Add,
        Mnemonic::Sub => Opcode::Sub,
        Mnemonic::Imul => Opcode::Imul,
        Mnemonic::Xor => Opcode::Xor,
        Mnemonic::And => Opcode::And,
        Mnemonic::Or => Opcode::Or,
        Mnemonic::Not => Opcode::Not,
        Mnemonic::Neg => Opcode::Neg,
        Mnemonic::Shl => Opcode::Shl,
        Mnemonic::Shr => Opcode::Shr,
        Mnemonic::Sar => Opcode::Sar,
        Mnemonic::Cmp => Opcode::Cmp,
        Mnemonic::Test => Opcode::Test,
        Mnemonic::Jmp => Opcode::Jmp,
        Mnemonic::Je => Opcode::Je,
        Mnemonic::Jne => Opcode::Jne,
        Mnemonic::Jg => Opcode::Jg,
        Mnemonic::Jge => Opcode::Jge,
        Mnemonic::Jl => Opcode::Jl,
        Mnemonic::Jle => Opcode::Jle,
        Mnemonic::Ja => Opcode::Ja,
        Mnemonic::Jae => Opcode::Jae,
        Mnemonic::Jb => Opcode::Jb,
        Mnemonic::Jbe => Opcode::Jbe,
        Mnemonic::Js => Opcode::Js,
        Mnemonic::Jns => Opcode::Jns,
        Mnemonic::Call => Opcode::Call,
        Mnemonic::Ret => Opcode::Ret,
        Mnemonic::Nop => Opcode::Nop,
        Mnemonic::Syscall => Opcode::Syscall,
        Mnemonic::Int => Opcode::Int,
        Mnemonic::Cdq => Opcode::Cdq,
        Mnemonic::Cqo => Opcode::Cqo,
        Mnemonic::Movzx => Opcode::Movzx,
        Mnemonic::Movsx => Opcode::Movsx,
        Mnemonic::Cmove => Opcode::Cmove,
        Mnemonic::Cmovne => Opcode::Cmovne,
        Mnemonic::Cmovg => Opcode::Cmovg,
        Mnemonic::Cmovl => Opcode::Cmovl,
        Mnemonic::Sete => Opcode::Sete,
        Mnemonic::Setne => Opcode::Setne,
        Mnemonic::Setg => Opcode::Setg,
        Mnemonic::Setl => Opcode::Setl,
        Mnemonic::Inc => Opcode::Inc,
        Mnemonic::Dec => Opcode::Dec,
        Mnemonic::Div => Opcode::Div,
        Mnemonic::Idiv => Opcode::Idiv,
        Mnemonic::Mul => Opcode::Mul,
        _ => Opcode::Nop, // fallback — will be replaced by RawBytes below
    }
}

/// Determine the operand size from an iced-x86 instruction.
fn determine_operand_size(insn: &iced_x86::Instruction) -> OperandSize {
    // Try to determine size from the first register operand.
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Register {
            let reg = insn.op_register(i);
            return register_size(reg);
        }
    }

    // Fall back to memory size if available.
    let mem_size = insn.memory_size();
    match mem_size.size() {
        1 => OperandSize::Byte,
        2 => OperandSize::Word,
        4 => OperandSize::Dword,
        8 => OperandSize::Qword,
        16 => OperandSize::Xmm,
        32 => OperandSize::Ymm,
        _ => OperandSize::Qword, // default for 64-bit
    }
}

/// Determine the OperandSize from an iced-x86 Register.
fn register_size(reg: Register) -> OperandSize {
    use Register::*;
    match reg {
        AL | BL | CL | DL | AH | BH | CH | DH | SPL | BPL | SIL | DIL | R8L | R9L | R10L
        | R11L | R12L | R13L | R14L | R15L => OperandSize::Byte,
        AX | BX | CX | DX | SP | BP | SI | DI | R8W | R9W | R10W | R11W | R12W | R13W
        | R14W | R15W => OperandSize::Word,
        EAX | EBX | ECX | EDX | ESP | EBP | ESI | EDI | R8D | R9D | R10D | R11D | R12D
        | R13D | R14D | R15D | EIP => OperandSize::Dword,
        RAX | RBX | RCX | RDX | RSP | RBP | RSI | RDI | R8 | R9 | R10 | R11 | R12 | R13
        | R14 | R15 | RIP => OperandSize::Qword,
        XMM0 | XMM1 | XMM2 | XMM3 | XMM4 | XMM5 | XMM6 | XMM7 | XMM8 | XMM9 | XMM10
        | XMM11 | XMM12 | XMM13 | XMM14 | XMM15 => OperandSize::Xmm,
        YMM0 | YMM1 | YMM2 | YMM3 | YMM4 | YMM5 | YMM6 | YMM7 | YMM8 | YMM9 | YMM10
        | YMM11 | YMM12 | YMM13 | YMM14 | YMM15 => OperandSize::Ymm,
        _ => OperandSize::Qword,
    }
}

/// Check if a mnemonic is a conditional branch (not including unconditional Jmp).
fn is_branch_mnemonic(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Js
            | Mnemonic::Jns
    )
}

/// Extract the branch/jump target address from an instruction, if it's a direct branch.
fn branch_target(insn: &iced_x86::Instruction) -> Option<u64> {
    if insn.op_count() == 0 {
        return None;
    }
    match insn.op_kind(0) {
        OpKind::NearBranch16 => Some(insn.near_branch16() as u64),
        OpKind::NearBranch32 => Some(insn.near_branch32() as u64),
        OpKind::NearBranch64 => Some(insn.near_branch64()),
        OpKind::FarBranch16 => Some(insn.far_branch16() as u64),
        OpKind::FarBranch32 => Some(insn.far_branch32() as u64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_magic_detection() {
        let frontend = ElfFrontend::new();

        // Valid ELF magic.
        let valid = [0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(frontend.can_handle(&valid));

        // Too short.
        assert!(!frontend.can_handle(&[0x7f, b'E', b'L']));

        // Wrong magic.
        assert!(!frontend.can_handle(&[0x00, 0x00, 0x00, 0x00]));

        // PE magic.
        assert!(!frontend.can_handle(&[b'M', b'Z', 0x90, 0x00]));

        // Empty.
        assert!(!frontend.can_handle(&[]));
    }

    #[test]
    fn test_lift_requires_elf() {
        let frontend = ElfFrontend::new();

        // Non-ELF data should produce an error.
        let result = frontend.lift(&[0x00, 0x01, 0x02, 0x03, 0x04]);
        assert!(result.is_err());
        match result {
            Err(FrontendError::ElfParse(_)) => {} // expected
            other => panic!("expected ElfParse error, got: {other:?}"),
        }
    }

    #[test]
    fn test_is_printable_string() {
        assert!(is_printable_string(b"Hello, World!\0"));
        assert!(is_printable_string(b"test\n\0"));
        assert!(is_printable_string(b"abc"));
        assert!(!is_printable_string(&[0x01, 0x02, 0x03]));
        assert!(!is_printable_string(&[]));
        assert!(!is_printable_string(&[0x00])); // just a null
    }

    #[test]
    fn test_mnemonic_to_opcode_known() {
        assert!(matches!(mnemonic_to_opcode(Mnemonic::Mov), Opcode::Mov));
        assert!(matches!(mnemonic_to_opcode(Mnemonic::Lea), Opcode::Lea));
        assert!(matches!(mnemonic_to_opcode(Mnemonic::Ret), Opcode::Ret));
        assert!(matches!(mnemonic_to_opcode(Mnemonic::Call), Opcode::Call));
        assert!(matches!(mnemonic_to_opcode(Mnemonic::Jmp), Opcode::Jmp));
        assert!(matches!(mnemonic_to_opcode(Mnemonic::Je), Opcode::Je));
        assert!(matches!(mnemonic_to_opcode(Mnemonic::Push), Opcode::Push));
        assert!(matches!(mnemonic_to_opcode(Mnemonic::Pop), Opcode::Pop));
    }

    #[test]
    fn test_register_size_mapping() {
        assert_eq!(register_size(Register::AL), OperandSize::Byte);
        assert_eq!(register_size(Register::AX), OperandSize::Word);
        assert_eq!(register_size(Register::EAX), OperandSize::Dword);
        assert_eq!(register_size(Register::RAX), OperandSize::Qword);
        assert_eq!(register_size(Register::XMM0), OperandSize::Xmm);
        assert_eq!(register_size(Register::YMM0), OperandSize::Ymm);
    }

    #[test]
    fn test_is_branch_mnemonic() {
        assert!(is_branch_mnemonic(Mnemonic::Je));
        assert!(is_branch_mnemonic(Mnemonic::Jne));
        assert!(is_branch_mnemonic(Mnemonic::Jg));
        assert!(!is_branch_mnemonic(Mnemonic::Jmp)); // unconditional
        assert!(!is_branch_mnemonic(Mnemonic::Call));
        assert!(!is_branch_mnemonic(Mnemonic::Ret));
        assert!(!is_branch_mnemonic(Mnemonic::Mov));
    }

    #[test]
    fn test_detect_frontend() {
        let elf_data = [0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(detect_frontend(&elf_data).is_some());

        let pe_data = [b'M', b'Z', 0x90, 0x00];
        assert!(detect_frontend(&pe_data).is_none());

        assert!(detect_frontend(&[]).is_none());
    }

    use crate::detect_frontend;
}
