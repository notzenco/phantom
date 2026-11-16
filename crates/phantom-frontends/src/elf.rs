use std::ops::Range;

use goblin::elf::{
    header::{EM_X86_64, ET_DYN},
    program_header::{PT_GNU_RELRO, PT_LOAD},
    reloc::R_X86_64_RELATIVE,
    section_header::SHF_ALLOC,
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

use crate::x86::{lift_function, string_refs_for_pointers, unmark_loader_owned_strings};
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

    // The backend writes ELF64 headers and x86-64 code, so anything else would
    // be emitted corrupt rather than protected.
    if !elf.is_64 || elf.header.e_machine != EM_X86_64 {
        return Err(FrontendError::Unsupported(format!(
            "{}-bit ELF for machine {}; only 64-bit x86-64 ELF is supported",
            if elf.is_64 { 64 } else { 32 },
            goblin::elf::header::machine_to_str(elf.header.e_machine),
        )));
    }
    let arch = Architecture::X86_64;
    let bitness = 64;

    let mut module = Module::new("elf_module".into(), arch, BinaryFormat::Elf);

    // Extract binary metadata.
    module.metadata = extract_metadata(&elf);

    // Extract data sections.
    module.data_sections = extract_data_sections(&elf, data);
    let relr = relr_slots(&elf, data);
    module.data_refs = string_refs_for_pointers(
        pointer_targets(&elf, data, &relr, &module.data_sections),
        &module.data_sections,
    );

    // Store raw binary.
    module.raw_binary = data.to_vec();

    // Lift functions from symbol table.
    let functions = lift_functions(&elf, data, bitness, &module.data_sections)?;
    module.functions = functions;

    let mut slots = relocated_slots(&elf);
    slots.extend_from_slice(&relr);
    let loader_ranges = loader_owned_ranges(&slots, &module.metadata.program_headers);
    unmark_loader_owned_strings(&mut module, &loader_ranges);

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
/// `R_X86_64_RELATIVE` relocations supply the address, unless the relocations are
/// packed (`DT_RELR`), in which case the file holds the link-time address; a
/// fixed-address executable stores absolute addresses directly, so aligned words
/// are read as candidates.
fn pointer_targets(
    elf: &Elf,
    data: &[u8],
    relr: &[u64],
    data_sections: &[DataSection],
) -> Vec<u64> {
    if elf.header.e_type == ET_DYN {
        let relocated = elf
            .dynrelas
            .iter()
            .filter(|r| r.r_type == R_X86_64_RELATIVE)
            .filter_map(|r| r.r_addend.map(|a| a as u64));
        let packed = relr
            .iter()
            .filter_map(|&slot| read_u64_at_vaddr(elf, data, slot));
        return relocated.chain(packed).collect();
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

const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;

/// Addresses the loader or start-up code rewrites through a relocation: every
/// dynamic relocation plus allocated relocation sections such as a static
/// binary's `.rela.iplt`. Packed `DT_RELR` slots come from [`relr_slots`].
fn relocated_slots(elf: &Elf) -> Vec<u64> {
    let mut slots: Vec<u64> = elf
        .dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
        .map(|r| r.r_offset)
        .collect();
    for (idx, relocs) in &elf.shdr_relocs {
        let allocated = elf
            .section_headers
            .get(*idx)
            .is_some_and(|sh| sh.sh_flags & SHF_ALLOC as u64 != 0);
        if allocated {
            slots.extend(relocs.iter().map(|r| r.r_offset));
        }
    }
    slots
}

/// Slots relocated through the packed `DT_RELR` table, which goblin does not parse.
fn relr_slots(elf: &Elf, data: &[u8]) -> Vec<u64> {
    let Some(dynamic) = &elf.dynamic else {
        return Vec::new();
    };
    let tag = |t| dynamic.dyns.iter().find(|d| d.d_tag == t).map(|d| d.d_val);
    let (Some(addr), Some(size)) = (tag(DT_RELR), tag(DT_RELRSZ)) else {
        return Vec::new();
    };
    let table = vaddr_to_offset(elf, addr)
        .zip(usize::try_from(size).ok())
        .and_then(|(start, len)| data.get(start..start.checked_add(len)?));
    let Some(table) = table else {
        return Vec::new();
    };
    decode_relr(
        table
            .as_chunks::<8>()
            .0
            .iter()
            .map(|w| u64::from_le_bytes(*w)),
    )
}

/// Expand `DT_RELR` entries: an even entry is an address to relocate, an odd one
/// a bitmap whose bits 1..=63 relocate the following words.
fn decode_relr(entries: impl IntoIterator<Item = u64>) -> Vec<u64> {
    let mut slots = Vec::new();
    let mut next = 0u64;
    for entry in entries {
        if entry & 1 == 0 {
            slots.push(entry);
            next = entry.wrapping_add(8);
        } else {
            slots.extend(
                (1..64u64)
                    .filter(|bit| entry >> bit & 1 == 1)
                    .map(|bit| next.wrapping_add((bit - 1) * 8)),
            );
            next = next.wrapping_add(63 * 8);
        }
    }
    slots
}

/// Ranges the loader writes or write-protects before the entry point: each
/// relocated 8-byte slot and every `PT_GNU_RELRO` segment, which is read-only by
/// the time the decryptor runs.
fn loader_owned_ranges(slots: &[u64], program_headers: &[ProgramHeader]) -> Vec<Range<u64>> {
    slots
        .iter()
        .map(|&slot| slot..slot.saturating_add(8))
        .chain(
            program_headers
                .iter()
                .filter(|ph| ph.p_type == PT_GNU_RELRO)
                .map(|ph| ph.p_vaddr..ph.p_vaddr.saturating_add(ph.p_memsz)),
        )
        .collect()
}

/// File offset backing `vaddr`, from the loadable segments.
fn vaddr_to_offset(elf: &Elf, vaddr: u64) -> Option<usize> {
    let ph = elf.program_headers.iter().find(|ph| {
        ph.p_type == PT_LOAD && vaddr >= ph.p_vaddr && vaddr - ph.p_vaddr < ph.p_filesz
    })?;
    usize::try_from(ph.p_offset.checked_add(vaddr - ph.p_vaddr)?).ok()
}

fn read_u64_at_vaddr(elf: &Elf, data: &[u8], vaddr: u64) -> Option<u64> {
    let start = vaddr_to_offset(elf, vaddr)?;
    let bytes = data.get(start..start.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
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

    /// A bare little-endian ELF header with no program or section headers.
    fn elf_header(class: u8, machine: u16) -> Vec<u8> {
        let is64 = class == 2;
        let mut h = vec![0u8; if is64 { 64 } else { 52 }];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = class;
        h[5] = 1; // little endian
        h[6] = 1; // EV_CURRENT
        h[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        h[18..20].copy_from_slice(&machine.to_le_bytes());
        h[20..24].copy_from_slice(&1u32.to_le_bytes());
        let (ehsize, phentsize, shentsize, at) = if is64 {
            (64u16, 56u16, 64u16, 52)
        } else {
            (52, 32, 40, 40)
        };
        h[at..at + 2].copy_from_slice(&ehsize.to_le_bytes());
        h[at + 2..at + 4].copy_from_slice(&phentsize.to_le_bytes());
        h[at + 6..at + 8].copy_from_slice(&shentsize.to_le_bytes());
        h
    }

    #[test]
    fn lifts_elf64_x86_64_header() {
        let module = ElfFrontend::new()
            .lift(&elf_header(2, EM_X86_64))
            .expect("x86-64 ELF64 is supported");
        assert_eq!(module.arch, Architecture::X86_64);
    }

    #[test]
    fn rejects_32_bit_and_mismatched_elf() {
        // The backend writes ELF64 structures and x86-64 code, so anything else
        // must be refused rather than silently corrupted.
        use goblin::elf::header::EM_386;
        for (class, machine) in [(1, EM_386), (2, EM_386), (1, EM_X86_64)] {
            match ElfFrontend::new().lift(&elf_header(class, machine)) {
                Err(FrontendError::Unsupported(msg)) => {
                    assert!(msg.contains("x86-64"), "unhelpful message: {msg}")
                }
                other => {
                    panic!("class {class} machine {machine}: expected rejection, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn decodes_packed_relative_relocations() {
        // An address entry, then a bitmap covering the next 63 words: bits 1 and 3
        // relocate the first and third words after the address entry's word.
        let slots = decode_relr([0x1000, (1 << 1 | 1 << 3) | 1, 0x3000]);
        assert_eq!(slots, vec![0x1000, 0x1008, 0x1018, 0x3000]);
        // Successive bitmaps continue 63 words further on.
        let slots = decode_relr([0x1000, 1, 0b11]);
        assert_eq!(slots, vec![0x1000, 0x1000 + 8 + 63 * 8]);
    }

    #[test]
    fn loader_ranges_cover_relocated_slots_and_relro() {
        let relro = ProgramHeader {
            p_type: PT_GNU_RELRO,
            p_flags: 4,
            p_offset: 0x2000,
            p_vaddr: 0x3000,
            p_paddr: 0x3000,
            p_filesz: 0x100,
            p_memsz: 0x100,
            p_align: 1,
        };
        let ranges = loader_owned_ranges(&[0x5000], std::slice::from_ref(&relro));
        assert!(ranges.contains(&(0x5000..0x5008)));
        assert!(ranges.contains(&(0x3000..0x3100)));
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
