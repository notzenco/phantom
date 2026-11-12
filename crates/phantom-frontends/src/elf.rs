use goblin::elf::{
    header::{EM_386, EM_X86_64, ET_DYN},
    reloc::R_X86_64_RELATIVE,
    sym::STT_FUNC,
    Elf,
};
use tracing::debug;

use phantom_core::{
    ir::{
        function::Function,
        module::{
            BinaryMetadata, DataSection, Module, ProgramHeader, SectionHeader, SectionPermissions,
        },
    },
    Architecture, BinaryFormat,
};
use phantom_disasm::IcedDisassembler;

use crate::x86::{lift_function, string_refs_for_pointers};
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
    let elf = Elf::parse(data).map_err(|e| FrontendError::Parse(e.to_string()))?;

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
    module.data_refs = string_refs_for_pointers(
        pointer_targets(&elf, &module.data_sections),
        &module.data_sections,
    );

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
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
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

        debug!(
            name,
            vaddr = sh.sh_addr,
            size = section_data.len(),
            "extracted data section"
        );

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

/// Addresses stored as pointers in data. A PIE stores zeros in the file and lets
/// `R_X86_64_RELATIVE` relocations supply the address; a fixed-address executable
/// stores absolute addresses directly, so aligned words are read as candidates.
fn pointer_targets(elf: &Elf, data_sections: &[DataSection]) -> Vec<u64> {
    if elf.header.e_type == ET_DYN {
        return elf
            .dynrelas
            .iter()
            .filter(|r| r.r_type == R_X86_64_RELATIVE)
            .filter_map(|r| r.r_addend.map(|a| a as u64))
            .collect();
    }
    data_sections
        .iter()
        .flat_map(|s| {
            let skip = (s.vaddr.wrapping_neg() % 8) as usize;
            s.data
                .get(skip..)
                .unwrap_or_default()
                .as_chunks::<8>()
                .0
                .iter()
                .map(|w| u64::from_le_bytes(*w))
        })
        .collect()
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
                debug!(
                    name,
                    addr = func_addr,
                    "skipping function: cannot find file offset"
                );
                continue;
            }
        };

        let end = file_offset + func_size as usize;
        if end > data.len() {
            debug!(
                name,
                addr = func_addr,
                "skipping function: extends beyond file"
            );
            continue;
        }

        let code_bytes = &data[file_offset..end];

        match lift_function(
            &name,
            func_addr,
            func_size,
            code_bytes,
            &disasm,
            data_sections,
        ) {
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
            Err(FrontendError::Parse(_)) => {} // expected
            other => panic!("expected Parse error, got: {other:?}"),
        }
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
