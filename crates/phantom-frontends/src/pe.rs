//! PE/COFF (Windows) lifter for x86-64 executables.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use goblin::pe::{data_directories::DataDirectoryType, PE};
use tracing::{debug, warn};

use phantom_core::{
    ir::module::{BinaryMetadata, DataSection, Module, SectionHeader, SectionPermissions},
    Architecture, BinaryFormat,
};
use phantom_disasm::IcedDisassembler;

use crate::x86::{
    lift_function, string_refs_for_pointers, unmark_loader_owned_strings,
    unmark_strings_used_before_entry,
};
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
        return Err(FrontendError::Unsupported(
            "only x86-64 (PE32+, AMD64) Windows executables are supported".into(),
        ));
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

    let loader_ranges = loader_owned_ranges(&pe, data);
    unmark_loader_owned_strings(&mut module, &loader_ranges);

    // TLS callbacks run before the entry point, on every thread attach.
    let callbacks = pe
        .tls_data
        .as_ref()
        .map(|tls| tls.callbacks.clone())
        .unwrap_or_default();
    let kept = unmark_strings_used_before_entry(&mut module, &callbacks);
    if kept > 0 {
        warn!(
            "{kept} string(s) used by TLS callbacks, which run before the entry point, \
             are left unencrypted"
        );
    }

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
fn loader_owned_ranges(pe: &PE, data: &[u8]) -> Vec<Range<u64>> {
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

    let dirs = LoaderDirectories::of(pe);
    ranges.extend(directory_targets(&dirs, base, |rva, len| {
        slice_for_rva(pe, data, rva, len)
    }));

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

/// RVAs of the directories whose contents point at further loader-read data.
struct LoaderDirectories {
    export: Option<u32>,
    import: Option<u32>,
    tls: Option<u32>,
}

impl LoaderDirectories {
    fn of(pe: &PE) -> Self {
        let dirs = pe.header.optional_header.map(|oh| oh.data_directories);
        let rva = |dir: Option<goblin::pe::data_directories::DataDirectory>| {
            dir.filter(|d| d.size > 0).map(|d| d.virtual_address)
        };
        Self {
            export: dirs
                .as_ref()
                .and_then(|d| rva(d.get_export_table().copied())),
            import: dirs
                .as_ref()
                .and_then(|d| rva(d.get_import_table().copied())),
            tls: dirs.as_ref().and_then(|d| rva(d.get_tls_table().copied())),
        }
    }
}

/// Objects outside the directory spans that the loader reads through them:
/// DLL and function names, import lookup and address tables, export tables,
/// and the TLS template, index and callback array (the template is copied for
/// the main thread before the entry point runs). `read(rva, len)` returns
/// image bytes; malformed tables just end the walk.
fn directory_targets<'a>(
    dirs: &LoaderDirectories,
    image_base: u64,
    read: impl Fn(u32, u32) -> Option<&'a [u8]>,
) -> Vec<Range<u64>> {
    const MAX_ENTRIES: u32 = 1 << 16;
    let u32_at = |rva: u32| read(rva, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let u64_at = |rva: u32| read(rva, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    // Length of the NUL-terminated string at `rva`, including the NUL.
    let cstr_len = |rva: u32| {
        (0..512u32).find_map(|i| match read(rva.checked_add(i)?, 1)? {
            [0] => Some(i + 1),
            _ => None,
        })
    };
    let to_rva = |va: u64| u32::try_from(va.checked_sub(image_base)?).ok();
    let mut ranges: Vec<Range<u32>> = Vec::new();
    let mut push = |start: u32, len: u32| {
        if let Some(end) = start.checked_add(len) {
            ranges.push(start..end);
        }
    };

    if let Some(dir) = dirs.import {
        for desc in (0..MAX_ENTRIES).map_while(|i| dir.checked_add(i.checked_mul(20)?)) {
            let (Some(lookup), Some(name), Some(iat)) =
                (u32_at(desc), u32_at(desc + 12), u32_at(desc + 16))
            else {
                break;
            };
            if lookup == 0 && name == 0 && iat == 0 {
                break;
            }
            if let Some(len) = cstr_len(name) {
                push(name, len);
            }
            let table = if lookup != 0 { lookup } else { iat };
            let mut count = 0;
            while let Some(entry) = table.checked_add(count * 8).and_then(u64_at) {
                count += 1;
                if entry == 0 || count >= MAX_ENTRIES {
                    break;
                }
                if entry & 1 << 63 == 0 {
                    let hint_name = entry as u32 & 0x7fff_ffff;
                    if let Some(len) = hint_name.checked_add(2).and_then(cstr_len) {
                        push(hint_name, len + 2);
                    }
                }
            }
            push(lookup, count * 8);
            push(iat, count * 8);
        }
    }

    if let Some(dir) = dirs.export {
        let field = |off| dir.checked_add(off).and_then(u32_at);
        if let (
            Some(name),
            Some(functions),
            Some(names),
            Some(f_table),
            Some(n_table),
            Some(o_table),
        ) = (
            field(12),
            field(20),
            field(24),
            field(28),
            field(32),
            field(36),
        ) {
            let (functions, names) = (functions.min(MAX_ENTRIES), names.min(MAX_ENTRIES));
            if let Some(len) = cstr_len(name) {
                push(name, len);
            }
            push(f_table, functions * 4);
            push(n_table, names * 4);
            push(o_table, names * 2);
            for i in 0..names {
                if let Some(name) = n_table.checked_add(i * 4).and_then(u32_at) {
                    if let Some(len) = cstr_len(name) {
                        push(name, len);
                    }
                }
            }
        }
    }

    if let Some(dir) = dirs.tls {
        let va_field = |off| dir.checked_add(off).and_then(u64_at).and_then(to_rva);
        if let (Some(start), Some(end)) = (va_field(0), va_field(8)) {
            push(start, end.saturating_sub(start));
        }
        if let Some(index) = va_field(16) {
            push(index, 4);
        }
        if let Some(callbacks) = va_field(24) {
            let count = (0..MAX_ENTRIES)
                .take_while(|i| {
                    callbacks
                        .checked_add(i * 8)
                        .and_then(u64_at)
                        .is_some_and(|cb| cb != 0)
                })
                .count() as u32;
            push(callbacks, (count + 1) * 8);
        }
    }

    ranges
        .into_iter()
        .filter(|r| r.start != 0 && !r.is_empty())
        .map(|r| image_base + r.start as u64..image_base + r.end as u64)
        .collect()
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
    fn directory_targets_are_loader_owned() {
        const BASE: u64 = 0x1_4000_0000;
        let mut image = vec![0u8; 0x1000];
        let put = |image: &mut Vec<u8>, at: usize, bytes: &[u8]| {
            image[at..at + bytes.len()].copy_from_slice(bytes)
        };
        let u32le = |v: u32| v.to_le_bytes();
        let u64le = |v: u64| v.to_le_bytes();

        // Import descriptor -> DLL name, lookup table, address table, hint/name.
        put(&mut image, 0x100, &u32le(0x300)); // OriginalFirstThunk
        put(&mut image, 0x10c, &u32le(0x200)); // Name
        put(&mut image, 0x110, &u32le(0x380)); // FirstThunk
        put(&mut image, 0x200, b"KERNEL32.dll\0");
        for table in [0x300, 0x380] {
            put(&mut image, table, &u64le(0x400));
            put(&mut image, table + 8, &u64le(1 << 63 | 7)); // by ordinal
        }
        put(&mut image, 0x402, b"ExitProcess\0");

        // TLS directory (virtual addresses) -> template, index, callbacks.
        put(&mut image, 0x500, &u64le(BASE + 0x600));
        put(&mut image, 0x508, &u64le(BASE + 0x610));
        put(&mut image, 0x510, &u64le(BASE + 0x620));
        put(&mut image, 0x518, &u64le(BASE + 0x630));
        put(&mut image, 0x630, &u64le(BASE + 0x900));

        // Export directory -> DLL name, address/name/ordinal tables, names.
        put(&mut image, 0x70c, &u32le(0x780));
        put(&mut image, 0x714, &u32le(1));
        put(&mut image, 0x718, &u32le(1));
        put(&mut image, 0x71c, &u32le(0x7a0));
        put(&mut image, 0x720, &u32le(0x7b0));
        put(&mut image, 0x724, &u32le(0x7b8));
        put(&mut image, 0x780, b"a.exe\0");
        put(&mut image, 0x7b0, &u32le(0x7c0));
        put(&mut image, 0x7c0, b"run\0");

        let read = |rva: u32, len: u32| image.get(rva as usize..(rva + len) as usize);
        let dirs = LoaderDirectories {
            export: Some(0x700),
            import: Some(0x100),
            tls: Some(0x500),
        };
        let ranges = directory_targets(&dirs, BASE, read);

        for expected in [
            0x200..0x20d, // DLL name
            0x300..0x318, // lookup table incl. terminator
            0x380..0x398, // address table incl. terminator
            0x400..0x40e, // hint + "ExitProcess\0"
            0x600..0x610, // TLS template
            0x620..0x624, // TLS index
            0x630..0x640, // callback array incl. terminator
            0x7a0..0x7a4, // export address table
            0x7b0..0x7b4, // export name pointers
            0x7b8..0x7ba, // export ordinals
            0x780..0x786, // export DLL name
            0x7c0..0x7c4, // export name
        ] {
            let expected = BASE + expected.start..BASE + expected.end;
            assert!(
                ranges.contains(&expected),
                "missing {expected:x?} in {ranges:x?}"
            );
        }
    }

    #[test]
    fn strings_overlapping_loader_ranges_are_unmarked() {
        use crate::x86::unmark_loader_owned_strings;
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
