//! PE/COFF (Windows) lifter for x86-64 executables.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use goblin::pe::{data_directories::DataDirectoryType, PE};
use tracing::debug;

use phantom_core::{
    ir::module::{BinaryMetadata, DataSection, Module, SectionHeader, SectionPermissions},
    Architecture, BinaryFormat,
};
use phantom_disasm::IcedDisassembler;

use crate::x86::{lift_function, string_refs_for_pointers};
use crate::{Frontend, FrontendError};

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_REL_BASED_HIGHLOW: u8 = 3;
const IMAGE_REL_BASED_DIR64: u8 = 10;

/// Windows PE lifter.
pub struct PeFrontend;

impl PeFrontend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PeFrontend {
    fn default() -> Self {
        Self::new()
    }
}

impl Frontend for PeFrontend {
    fn can_handle(&self, data: &[u8]) -> bool {
        if data.len() < 0x40 || &data[..2] != b"MZ" {
            return false;
        }
        let pe_offset = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
        data.get(pe_offset..pe_offset + 4) == Some(b"PE\0\0".as_slice())
    }

    fn lift(&self, data: &[u8]) -> Result<Module, FrontendError> {
        lift_pe(data)
    }
}

fn lift_pe(data: &[u8]) -> Result<Module, FrontendError> {
    let pe = PE::parse(data).map_err(|e| FrontendError::Parse(e.to_string()))?;

    if !pe.is_64 || pe.header.coff_header.machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(FrontendError::UnsupportedFormat);
    }
    if pe.is_lib {
        // A DLL entry point runs on every process/thread attach and detach, so an
        // init routine that decrypts in place would re-encrypt on the second call.
        return Err(FrontendError::Lift(
            "PE DLLs are not supported yet; only executables can be protected".into(),
        ));
    }

    let image_base = pe.image_base;
    let mut module = Module::new("pe_module".into(), Architecture::X86_64, BinaryFormat::Pe);
    module.metadata = extract_metadata(&pe);
    module.data_sections = extract_data_sections(&pe, data);
    module.raw_binary = data.to_vec();

    let disasm = IcedDisassembler::new(64);
    let names = function_names(&pe, data);
    for (rva, end_rva) in function_ranges(&pe) {
        let Some(code) = slice_for_rva(&pe, data, rva, end_rva - rva) else {
            debug!(rva, "skipping function: not backed by file data");
            continue;
        };
        let addr = image_base + rva as u64;
        let name = names
            .get(&rva)
            .cloned()
            .unwrap_or_else(|| format!("sub_{addr:x}"));
        match lift_function(
            &name,
            addr,
            (end_rva - rva) as u64,
            code,
            &disasm,
            &module.data_sections,
        ) {
            Ok(func) => module.functions.push(func),
            Err(e) => debug!(name, error = %e, "failed to lift function, skipping"),
        }
    }

    module.data_refs = string_refs_for_pointers(pointer_targets(&pe, data), &module.data_sections);

    let loader_ranges = loader_owned_ranges(&pe);
    unmark_loader_owned_strings(&mut module, &loader_ranges);

    debug!(
        functions = module.functions.len(),
        data_sections = module.data_sections.len(),
        "PE lift complete"
    );
    Ok(module)
}

fn extract_metadata(pe: &PE) -> BinaryMetadata {
    let dll_characteristics = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.dll_characteristics)
        .unwrap_or(0);

    let section_headers = pe
        .sections
        .iter()
        .map(|s| SectionHeader {
            name: section_name(s),
            sh_type: 0,
            sh_flags: s.characteristics as u64,
            sh_addr: pe.image_base + s.virtual_address as u64,
            sh_offset: s.pointer_to_raw_data as u64,
            sh_size: s.virtual_size.max(s.size_of_raw_data) as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        })
        .collect();

    BinaryMetadata {
        entry_point: pe.image_base + pe.entry as u64,
        program_headers: Vec::new(),
        section_headers,
        is_pie: dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0,
    }
}

fn section_name(section: &goblin::pe::section_table::SectionTable) -> String {
    section
        .real_name
        .clone()
        .or_else(|| section.name().ok().map(str::to_string))
        .unwrap_or_default()
}

/// Initialized, non-executable, non-discardable sections hold the string literals.
fn extract_data_sections(pe: &PE, data: &[u8]) -> Vec<DataSection> {
    pe.sections
        .iter()
        .filter(|s| {
            s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
                && s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE) == 0
        })
        .filter_map(|s| {
            // Bytes past the raw data are zero-filled by the loader and not in the file.
            let len = s.virtual_size.min(s.size_of_raw_data) as usize;
            let start = s.pointer_to_raw_data as usize;
            let bytes = data.get(start..start + len)?;
            Some(DataSection {
                name: section_name(s),
                vaddr: pe.image_base + s.virtual_address as u64,
                file_offset: start as u64,
                data: bytes.to_vec(),
                permissions: SectionPermissions {
                    read: s.characteristics & IMAGE_SCN_MEM_READ != 0,
                    write: s.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    execute: false,
                },
                relocations: vec![],
            })
        })
        .collect()
}

/// Function bounds from the x64 exception directory (`.pdata`). Leaf functions that
/// need no unwind info have no entry and are not lifted.
fn function_ranges(pe: &PE) -> Vec<(u32, u32)> {
    let mut ranges = BTreeMap::new();
    if let Some(exceptions) = &pe.exception_data {
        for rf in exceptions.functions().flatten() {
            if rf.end_address > rf.begin_address {
                ranges.entry(rf.begin_address).or_insert(rf.end_address);
            }
        }
    }
    ranges.into_iter().collect()
}

/// Names from exports and, when present (e.g. unstripped MinGW builds), COFF symbols.
fn function_names(pe: &PE, data: &[u8]) -> HashMap<u32, String> {
    let mut names = HashMap::new();
    for export in &pe.exports {
        if let Some(name) = export.name {
            names.insert(export.rva as u32, name.to_string());
        }
    }

    let coff = &pe.header.coff_header;
    let (Ok(Some(symbols)), Ok(Some(strings))) = (coff.symbols(data), coff.strings(data)) else {
        return names;
    };
    for (_, _, symbol) in symbols.iter() {
        if !symbol.is_function_definition() || symbol.section_number < 1 {
            continue;
        }
        let Some(section) = pe.sections.get(symbol.section_number as usize - 1) else {
            continue;
        };
        if let Ok(name) = symbol.name(&strings) {
            names
                .entry(section.virtual_address + symbol.value)
                .or_insert_with(|| name.to_string());
        }
    }
    names
}

fn slice_for_rva<'a>(pe: &PE, data: &'a [u8], rva: u32, len: u32) -> Option<&'a [u8]> {
    let section = pe.sections.iter().find(|s| {
        rva >= s.virtual_address && rva + len <= s.virtual_address + s.size_of_raw_data
    })?;
    let start = (section.pointer_to_raw_data + (rva - section.virtual_address)) as usize;
    data.get(start..start + len as usize)
}

/// Virtual-address ranges the Windows loader reads or rewrites before the entry
/// point runs: data directories (imports, IAT, TLS, load config, resources, ...)
/// and every base-relocated slot. Encrypting bytes there would break loading.
fn loader_owned_ranges(pe: &PE) -> Vec<Range<u64>> {
    let base = pe.image_base;
    let mut ranges = Vec::new();

    if let Some(optional) = pe.header.optional_header {
        for (kind, dir) in optional.data_directories.dirs() {
            // The certificate table entry is a file offset, not an RVA.
            if matches!(kind, DataDirectoryType::CertificateTable) || dir.size == 0 {
                continue;
            }
            let start = base + dir.virtual_address as u64;
            ranges.push(start..start + dir.size as u64);
        }
    }

    if let Some(relocations) = &pe.relocation_data {
        for block in relocations.blocks().flatten() {
            for word in block.words().flatten() {
                let width = match word.reloc_type() {
                    IMAGE_REL_BASED_DIR64 => 8,
                    IMAGE_REL_BASED_HIGHLOW => 4,
                    _ => continue,
                };
                let start = base + block.rva as u64 + word.offset() as u64;
                ranges.push(start..start + width);
            }
        }
    }

    ranges
}

/// Addresses held in 64-bit base-relocated slots: every absolute pointer in an
/// ASLR-capable image has one, so these are the image's data pointers.
fn pointer_targets(pe: &PE, data: &[u8]) -> Vec<u64> {
    let Some(relocations) = &pe.relocation_data else {
        return Vec::new();
    };
    relocations
        .blocks()
        .flatten()
        .flat_map(|block| {
            block
                .words()
                .flatten()
                .filter(|w| w.reloc_type() == IMAGE_REL_BASED_DIR64)
                .map(|w| block.rva + w.offset() as u32)
                .collect::<Vec<_>>()
        })
        .filter_map(|rva| slice_for_rva(pe, data, rva, 8))
        .map(|slot| u64::from_le_bytes(slot.try_into().unwrap()))
        .collect()
}

fn unmark_loader_owned_strings(module: &mut Module, ranges: &[Range<u64>]) {
    let code_refs = module
        .functions
        .iter_mut()
        .flat_map(|f| f.instructions_mut())
        .flat_map(|insn| insn.data_refs.iter_mut());
    for dref in code_refs.chain(module.data_refs.iter_mut()) {
        if !dref.is_string {
            continue;
        }
        let span = dref.vaddr..dref.vaddr + dref.size as u64;
        if ranges
            .iter()
            .any(|r| r.start < span.end && span.start < r.end)
        {
            debug!(
                vaddr = dref.vaddr,
                "string overlaps loader-owned data; leaving it"
            );
            dref.is_string = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pe_signature() {
        let mut image = vec![0u8; 0x100];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(PeFrontend::new().can_handle(&image));

        image[0x80] = b'X';
        assert!(!PeFrontend::new().can_handle(&image));
        assert!(!PeFrontend::new().can_handle(b"MZ"));
        assert!(!PeFrontend::new().can_handle(&[0x7f, b'E', b'L', b'F']));
    }

    #[test]
    fn strings_overlapping_loader_ranges_are_unmarked() {
        use phantom_core::ir::function::Function;
        use phantom_core::ir::instruction::{Instruction, InstructionMeta, Opcode};
        use phantom_core::ir::types::{DataRef, OperandSize};
        use phantom_core::{BasicBlock, BlockId, Terminator};

        let dref = |vaddr| DataRef {
            vaddr,
            size: 4,
            data: b"AB\0\0".to_vec(),
            is_string: true,
        };
        let mut module = Module::new("t".into(), Architecture::X86_64, BinaryFormat::Pe);
        let mut func = Function::new("f".into(), 0x1000, 1);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            start_addr: 0x1000,
            end_addr: 0x1001,
            instructions: vec![Instruction {
                address: 0x1000,
                original_bytes: vec![0x90],
                opcode: Opcode::Nop,
                operands: vec![],
                operand_size: OperandSize::Byte,
                data_refs: vec![dref(0x2000), dref(0x3002)],
                meta: InstructionMeta::default(),
            }],
            terminator: Terminator::Return,
        });
        module.functions.push(func);

        let iat = 0x3000..0x3004;
        unmark_loader_owned_strings(&mut module, std::slice::from_ref(&iat));

        let refs = &module.functions[0].blocks[0].instructions[0].data_refs;
        assert!(refs[0].is_string, "unrelated string stays eligible");
        assert!(!refs[1].is_string, "IAT-like overlap must be left alone");
    }
}
