use tracing::debug;

use phantom_core::ir::module::{BinaryMetadata, Module, SectionHeader};

use crate::common::{
    align_up, encode_new_functions, patch_data_sections, patch_existing_functions, read_u16_le,
    read_u64_le, write_u16_le, write_u64_le, NewCode,
};
#[cfg(test)]
use crate::common::{apply_raw_fixups, bitness_for_module, nop_pad};

use crate::error::BackendError;
use crate::Backend;

/// PT_LOAD segment type.
const PT_LOAD: u32 = 1;
/// PF_R | PF_X — readable + executable.
const PF_RX: u32 = 5;
/// Page alignment for new segments.
const PAGE_ALIGN: u64 = 0x1000;
/// Size of a 64-bit ELF program header entry.
const PHDR64_SIZE: usize = 56;

/// ELF binary emitter. Patches the original binary rather than
/// generating from scratch, preserving linker layout and section alignment.
pub struct ElfBackend;

impl ElfBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ElfBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for ElfBackend {
    fn emit(&self, module: &Module) -> Result<Vec<u8>, BackendError> {
        // 1. Start from raw binary.
        if module.raw_binary.is_empty() {
            return Err(BackendError::NoRawBinary);
        }
        let mut binary = module.raw_binary.clone();
        debug!(
            functions = module.functions.len(),
            data_sections = module.data_sections.len(),
            binary_size = binary.len(),
            "Starting ELF emission"
        );

        // Collect new functions (address == 0 or not in any existing section).
        let mut new_func_indices = Vec::new();
        let mut existing_func_indices = Vec::new();

        for (i, func) in module.functions.iter().enumerate() {
            if func.address == 0 || section_for_vaddr(module, func.address).is_none() {
                new_func_indices.push(i);
            } else {
                existing_func_indices.push(i);
            }
        }

        // 2. Patch existing functions.
        patch_existing_functions(module, &mut binary, &existing_func_indices, |vaddr| {
            vaddr_to_file_offset(module, vaddr)
        })?;

        // 3. Patch data sections.
        let modified_section_vaddrs = patch_data_sections(module, &mut binary);

        // 3b. Make segments containing modified data sections writable.
        // This is needed because decryptor thunks decrypt strings in-place at runtime,
        // and read-only segments (e.g., .rodata) would cause a segfault.
        if !modified_section_vaddrs.is_empty() {
            let e_phoff = read_u64_le(&binary, 32) as usize;
            let e_phnum = read_u16_le(&binary, 56) as usize;

            for i in 0..e_phnum {
                let phdr_offset = e_phoff + i * PHDR64_SIZE;
                if phdr_offset + PHDR64_SIZE > binary.len() {
                    break;
                }
                let p_type =
                    u32::from_le_bytes(binary[phdr_offset..phdr_offset + 4].try_into().unwrap());
                if p_type != PT_LOAD {
                    continue;
                }
                let p_vaddr = read_u64_le(&binary, phdr_offset + 16);
                let p_memsz = read_u64_le(&binary, phdr_offset + 40);

                for &sec_vaddr in &modified_section_vaddrs {
                    if sec_vaddr >= p_vaddr && sec_vaddr < p_vaddr + p_memsz {
                        // Add PF_W (0x2) to the segment flags.
                        let p_flags_offset = phdr_offset + 4;
                        let flags = u32::from_le_bytes(
                            binary[p_flags_offset..p_flags_offset + 4]
                                .try_into()
                                .unwrap(),
                        );
                        if flags & 0x2 == 0 {
                            let new_flags = flags | 0x2;
                            binary[p_flags_offset..p_flags_offset + 4]
                                .copy_from_slice(&new_flags.to_le_bytes());
                            debug!(
                                segment_vaddr = %format!("{:#x}", p_vaddr),
                                "Made segment writable for runtime decryption"
                            );
                        }
                        break;
                    }
                }
            }
        }

        // 4. Append new functions.
        if !new_func_indices.is_empty() {
            // Find highest PT_LOAD segment end to choose a load address.
            let highest_end = module
                .metadata
                .program_headers
                .iter()
                .filter(|ph| ph.p_type == PT_LOAD)
                .map(|ph| ph.p_vaddr + ph.p_memsz)
                .max()
                .unwrap_or(0);

            let load_addr = align_up(highest_end, PAGE_ALIGN);

            let NewCode {
                code: new_code,
                placed: func_offsets,
            } = encode_new_functions(module, &new_func_indices, load_addr)?;

            if !new_code.is_empty() {
                append_new_segment(&mut binary, &new_code, load_addr, &module.metadata)?;
            }

            // If there's a __phantom_init function, redirect the entry point to it.
            for &(idx, addr) in &func_offsets {
                if module.functions[idx].name == "__phantom_init" {
                    debug!(
                        old_entry = %format!("{:#x}", module.metadata.entry_point),
                        new_entry = %format!("{:#x}", addr),
                        "Redirecting entry point to __phantom_init"
                    );
                    // e_entry is at offset 24 in a 64-bit ELF header.
                    write_u64_le(&mut binary, 24, addr);
                }
            }
        }

        debug!(final_size = binary.len(), "ELF emission complete");
        Ok(binary)
    }
}

/// Map a virtual address to a file offset using program headers.
fn vaddr_to_file_offset(module: &Module, vaddr: u64) -> Option<u64> {
    for ph in &module.metadata.program_headers {
        if ph.p_type == PT_LOAD && vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_memsz {
            return Some(vaddr - ph.p_vaddr + ph.p_offset);
        }
    }
    None
}

/// Find the section header containing the given virtual address.
fn section_for_vaddr(module: &Module, vaddr: u64) -> Option<&SectionHeader> {
    module
        .metadata
        .section_headers
        .iter()
        .find(|sh| vaddr >= sh.sh_addr && vaddr < sh.sh_addr + sh.sh_size)
}

/// Append new code to the binary by creating a new PT_LOAD segment.
///
/// Strategy to find room for the new phdr (in order of preference):
/// 1. Space after existing phdrs (gap before first section)
/// 2. Overwrite a PT_NOTE phdr (not needed for execution)
/// 3. Error if neither option works
fn append_new_segment(
    binary: &mut Vec<u8>,
    code: &[u8],
    load_addr: u64,
    metadata: &BinaryMetadata,
) -> Result<(), BackendError> {
    // Pad binary to page alignment.
    let aligned_offset = align_up(binary.len() as u64, PAGE_ALIGN) as usize;
    binary.resize(aligned_offset, 0x00);

    let file_offset = binary.len() as u64;

    // Append the code bytes.
    binary.extend_from_slice(code);

    debug!(
        file_offset = %format!("{:#x}", file_offset),
        load_addr = %format!("{:#x}", load_addr),
        code_size = code.len(),
        "Appended new code segment"
    );

    let phdr = build_phdr(
        PT_LOAD,
        PF_RX,
        file_offset,
        load_addr,
        load_addr,
        code.len() as u64,
        code.len() as u64,
        PAGE_ALIGN,
    );

    let e_phoff = read_u64_le(binary, 32) as usize;
    let e_phnum = read_u16_le(binary, 56) as usize;
    let phdr_table_end = e_phoff + e_phnum * PHDR64_SIZE;

    // Strategy 1: Space after existing phdrs.
    let first_content_offset = find_first_content_after(binary, phdr_table_end, metadata);
    if phdr_table_end + PHDR64_SIZE <= first_content_offset {
        binary[phdr_table_end..phdr_table_end + PHDR64_SIZE].copy_from_slice(&phdr);
        write_u16_le(binary, 56, (e_phnum + 1) as u16);
        debug!("Added new PT_LOAD program header in-place");
        return Ok(());
    }

    // Strategy 2: Overwrite a PT_NOTE phdr (type 4). Notes are informational
    // and not required for execution.
    let pt_note: u32 = 4;
    for i in 0..e_phnum {
        let off = e_phoff + i * PHDR64_SIZE;
        let p_type = u32::from_le_bytes(binary[off..off + 4].try_into().unwrap());
        if p_type == pt_note {
            binary[off..off + PHDR64_SIZE].copy_from_slice(&phdr);
            debug!("Overwrote PT_NOTE phdr at index {} with new PT_LOAD", i);
            return Ok(());
        }
    }

    Err(BackendError::Emit(
        "No room for new program header: no space after phdrs and no PT_NOTE to overwrite".into(),
    ))
}

/// Build a 64-bit ELF program header as raw bytes.
#[allow(clippy::too_many_arguments)]
fn build_phdr(
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
) -> [u8; PHDR64_SIZE] {
    let mut buf = [0u8; PHDR64_SIZE];
    buf[0..4].copy_from_slice(&p_type.to_le_bytes());
    buf[4..8].copy_from_slice(&p_flags.to_le_bytes());
    buf[8..16].copy_from_slice(&p_offset.to_le_bytes());
    buf[16..24].copy_from_slice(&p_vaddr.to_le_bytes());
    buf[24..32].copy_from_slice(&p_paddr.to_le_bytes());
    buf[32..40].copy_from_slice(&p_filesz.to_le_bytes());
    buf[40..48].copy_from_slice(&p_memsz.to_le_bytes());
    buf[48..56].copy_from_slice(&p_align.to_le_bytes());
    buf
}

/// Find the offset of the first content after `after_offset`.
/// This is used to determine if there's room to insert a program header in-place.
fn find_first_content_after(
    _binary: &[u8],
    after_offset: usize,
    metadata: &BinaryMetadata,
) -> usize {
    let mut earliest = usize::MAX;

    for sh in &metadata.section_headers {
        let off = sh.sh_offset as usize;
        if off > after_offset && off < earliest {
            earliest = off;
        }
    }

    earliest
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::ir::block::{BasicBlock, BlockId, Terminator};
    use phantom_core::ir::function::{RawCodeFixup, RawCodeFixupTarget};
    use phantom_core::ir::instruction::{Instruction, InstructionMeta, Opcode};
    use phantom_core::ir::module::{
        DataSection, Module, ProgramHeader, SectionHeader, SectionPermissions,
    };
    use phantom_core::ir::types::OperandSize;
    use phantom_core::{Architecture, BinaryFormat};

    /// Create a minimal module with program headers for testing.
    fn make_test_module() -> Module {
        let mut m = Module::new("test.elf".into(), Architecture::X86_64, BinaryFormat::Elf);
        m.metadata.program_headers.push(ProgramHeader {
            p_type: PT_LOAD,
            p_flags: 5,
            p_offset: 0x0,
            p_vaddr: 0x400000,
            p_paddr: 0x400000,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_align: 0x1000,
        });
        m.metadata.program_headers.push(ProgramHeader {
            p_type: PT_LOAD,
            p_flags: 5,
            p_offset: 0x1000,
            p_vaddr: 0x401000,
            p_paddr: 0x401000,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_align: 0x1000,
        });
        m.metadata.section_headers.push(SectionHeader {
            name: ".text".into(),
            sh_type: 1,
            sh_flags: 6,
            sh_addr: 0x401000,
            sh_offset: 0x1000,
            sh_size: 0x1000,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 16,
            sh_entsize: 0,
        });
        m
    }

    /// Create a simple NOP instruction.
    fn nop_insn(addr: u64) -> Instruction {
        Instruction {
            address: addr,
            original_bytes: vec![0x90],
            opcode: Opcode::Nop,
            operands: vec![],
            operand_size: OperandSize::Byte,
            data_refs: vec![],
            meta: InstructionMeta::default(),
        }
    }

    /// Create a RET instruction.
    fn ret_insn(addr: u64) -> Instruction {
        Instruction {
            address: addr,
            original_bytes: vec![0xC3],
            opcode: Opcode::Ret,
            operands: vec![],
            operand_size: OperandSize::Byte,
            data_refs: vec![],
            meta: InstructionMeta::default(),
        }
    }

    #[test]
    fn test_vaddr_to_offset() {
        let m = make_test_module();

        // Address in second PT_LOAD: vaddr 0x401000, offset 0x1000.
        assert_eq!(vaddr_to_file_offset(&m, 0x401000), Some(0x1000));
        assert_eq!(vaddr_to_file_offset(&m, 0x401100), Some(0x1100));

        // Address in first PT_LOAD: vaddr 0x400000, offset 0x0.
        assert_eq!(vaddr_to_file_offset(&m, 0x400000), Some(0x0));
        assert_eq!(vaddr_to_file_offset(&m, 0x400080), Some(0x80));

        // Address outside any segment.
        assert_eq!(vaddr_to_file_offset(&m, 0x500000), None);
    }

    #[test]
    fn test_section_for_vaddr() {
        let m = make_test_module();

        let sh = section_for_vaddr(&m, 0x401000);
        assert!(sh.is_some());
        assert_eq!(sh.unwrap().name, ".text");

        let sh = section_for_vaddr(&m, 0x401FFF);
        assert!(sh.is_some());

        let sh = section_for_vaddr(&m, 0x500000);
        assert!(sh.is_none());
    }

    #[test]
    fn test_nop_padding() {
        let mut buf = vec![0xCC, 0xCC];
        nop_pad(&mut buf, 5);
        assert_eq!(buf, vec![0xCC, 0xCC, 0x90, 0x90, 0x90]);
    }

    #[test]
    fn test_nop_padding_already_at_target() {
        let mut buf = vec![0xCC; 3];
        nop_pad(&mut buf, 3);
        assert_eq!(buf.len(), 3);
        // No NOPs added.
        assert!(buf.iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn test_no_raw_binary_error() {
        let m = Module::new("empty".into(), Architecture::X86_64, BinaryFormat::Elf);
        let backend = ElfBackend::new();
        let result = backend.emit(&m);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BackendError::NoRawBinary));
    }

    #[test]
    fn test_pass_through_unmodified() {
        // Create a module with raw binary and an unmodified function.
        let mut m = make_test_module();

        // Raw binary: 8KB of zeros.
        m.raw_binary = vec![0x00; 0x2000];

        // Function at 0x401000 with NOP + RET (2 bytes), original size = 5.
        let mut func = phantom_core::ir::function::Function::new("test_fn".into(), 0x401000, 5);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            start_addr: 0x401000,
            end_addr: 0x401002,
            instructions: vec![nop_insn(0x401000), ret_insn(0x401001)],
            terminator: Terminator::Return,
        });
        m.functions.push(func);

        let backend = ElfBackend::new();
        let result = backend.emit(&m).unwrap();

        // Check that NOP and RET were written at offset 0x1000.
        assert_eq!(result[0x1000], 0x90); // NOP
        assert_eq!(result[0x1001], 0xC3); // RET
                                          // Remaining 3 bytes should be NOP-padded.
        assert_eq!(result[0x1002], 0x90);
        assert_eq!(result[0x1003], 0x90);
        assert_eq!(result[0x1004], 0x90);
    }

    #[test]
    fn test_function_grew_error() {
        let mut m = make_test_module();
        m.raw_binary = vec![0x00; 0x2000];

        // Function with original size 1, but has 2 instructions.
        let mut func = phantom_core::ir::function::Function::new("tiny".into(), 0x401000, 1);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            start_addr: 0x401000,
            end_addr: 0x401002,
            instructions: vec![nop_insn(0x401000), ret_insn(0x401001)],
            terminator: Terminator::Return,
        });
        m.functions.push(func);

        let backend = ElfBackend::new();
        let result = backend.emit(&m);
        assert!(result.is_err());
        match result.unwrap_err() {
            BackendError::FunctionGrew {
                name,
                original,
                new,
                ..
            } => {
                assert_eq!(name, "tiny");
                assert_eq!(original, 1);
                assert_eq!(new, 2);
            }
            e => panic!("Expected FunctionGrew, got: {e}"),
        }
    }

    #[test]
    fn test_data_section_patching() {
        let mut m = make_test_module();
        m.raw_binary = vec![0x00; 0x2000];

        // Add a data section.
        m.data_sections.push(DataSection {
            name: ".rodata".into(),
            vaddr: 0x401100,
            file_offset: 0x1100,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: false,
            },
            relocations: vec![],
        });

        let backend = ElfBackend::new();
        let result = backend.emit(&m).unwrap();

        assert_eq!(&result[0x1100..0x1104], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 0x1000), 0);
        assert_eq!(align_up(1, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_up(0xFFF, 0x1000), 0x1000);
    }

    #[test]
    fn test_build_phdr() {
        let phdr = build_phdr(
            PT_LOAD, PF_RX, 0x3000, 0x600000, 0x600000, 0x100, 0x100, 0x1000,
        );
        assert_eq!(phdr.len(), PHDR64_SIZE);

        // Verify p_type.
        assert_eq!(u32::from_le_bytes(phdr[0..4].try_into().unwrap()), PT_LOAD);
        // Verify p_flags.
        assert_eq!(u32::from_le_bytes(phdr[4..8].try_into().unwrap()), PF_RX);
        // Verify p_offset.
        assert_eq!(u64::from_le_bytes(phdr[8..16].try_into().unwrap()), 0x3000);
        // Verify p_vaddr.
        assert_eq!(
            u64::from_le_bytes(phdr[16..24].try_into().unwrap()),
            0x600000
        );
        // Verify p_filesz.
        assert_eq!(u64::from_le_bytes(phdr[32..40].try_into().unwrap()), 0x100);
        // Verify p_align.
        assert_eq!(u64::from_le_bytes(phdr[48..56].try_into().unwrap()), 0x1000);
    }

    #[test]
    fn test_raw_bytes_opcode_passthrough() {
        let mut m = make_test_module();
        m.raw_binary = vec![0x00; 0x2000];

        let raw_data = vec![0x48, 0x89, 0xE5]; // mov rbp, rsp
        let mut func = phantom_core::ir::function::Function::new("raw_fn".into(), 0x401000, 4);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            start_addr: 0x401000,
            end_addr: 0x401004,
            instructions: vec![
                Instruction {
                    address: 0x401000,
                    original_bytes: raw_data.clone(),
                    opcode: Opcode::RawBytes(raw_data.clone()),
                    operands: vec![],
                    operand_size: OperandSize::Qword,
                    data_refs: vec![],
                    meta: InstructionMeta {
                        iced_code: None,
                        modified: true,
                        modified_by: Some("test".into()),
                    },
                },
                ret_insn(0x401003),
            ],
            terminator: Terminator::Return,
        });
        m.functions.push(func);

        let backend = ElfBackend::new();
        let result = backend.emit(&m).unwrap();

        // Raw bytes should be written at offset 0x1000.
        assert_eq!(&result[0x1000..0x1003], &raw_data[..]);
        assert_eq!(result[0x1003], 0xC3); // RET
    }

    #[test]
    fn test_raw_fixups_patch_function_address() {
        let mut func = phantom_core::ir::function::Function::new("raw_fn".into(), 0x401000, 16);
        func.raw_fixups.push(RawCodeFixup {
            offset: 4,
            target: RawCodeFixupTarget::FunctionAddress { offset: 12 },
        });

        let mut encoded = vec![0u8; 16];
        apply_raw_fixups(&mut encoded, &func, 0x500000).unwrap();

        let patched = u64::from_le_bytes(encoded[4..12].try_into().unwrap());
        assert_eq!(patched, 0x50000c);
    }

    #[test]
    fn test_bitness_for_module() {
        let m64 = Module::new("test".into(), Architecture::X86_64, BinaryFormat::Elf);
        assert_eq!(bitness_for_module(&m64), 64);

        let m32 = Module::new("test".into(), Architecture::X86, BinaryFormat::Elf);
        assert_eq!(bitness_for_module(&m32), 32);
    }

    #[test]
    fn test_read_write_helpers() {
        let mut buf = vec![0u8; 16];
        write_u64_le(&mut buf, 0, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(read_u64_le(&buf, 0), 0xDEAD_BEEF_CAFE_BABE);

        write_u16_le(&mut buf, 8, 0x1234);
        assert_eq!(read_u16_le(&buf, 8), 0x1234);
    }

    #[test]
    fn test_emit_preserves_unrelated_bytes() {
        // The emitter should not touch bytes outside of patched regions.
        let mut m = make_test_module();
        m.raw_binary = vec![0xAA; 0x2000];

        let backend = ElfBackend::new();
        let result = backend.emit(&m).unwrap();

        // No functions or data sections to patch, so binary should be unchanged.
        assert_eq!(result, m.raw_binary);
    }

    #[test]
    fn test_default_trait() {
        let _backend = ElfBackend;
    }
}
