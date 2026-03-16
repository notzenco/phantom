use serde::{Deserialize, Serialize};

use super::function::Function;
use crate::{Architecture, BinaryFormat};

/// Permission flags for a data section.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct SectionPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Kind of relocation.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum RelocationKind {
    Absolute,
    Relative,
    RipRelative,
}

/// A relocation entry within a data section.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relocation {
    pub offset: u64,
    pub size: u8,
    pub target_addr: u64,
    pub kind: RelocationKind,
}

/// A data section (e.g. .rodata, .data, .bss).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataSection {
    pub name: String,
    pub vaddr: u64,
    pub file_offset: u64,
    pub data: Vec<u8>,
    pub permissions: SectionPermissions,
    pub relocations: Vec<Relocation>,
}

/// ELF program header, stored for faithful re-emission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// ELF section header, stored for faithful re-emission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionHeader {
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// Binary-level metadata carried through the pipeline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryMetadata {
    pub entry_point: u64,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
    pub is_pie: bool,
}

/// Top-level IR container representing an entire binary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub arch: Architecture,
    pub format: BinaryFormat,
    pub functions: Vec<Function>,
    pub data_sections: Vec<DataSection>,
    pub raw_binary: Vec<u8>,
    pub metadata: BinaryMetadata,
}

impl Module {
    /// Create a new empty module.
    pub fn new(name: String, arch: Architecture, format: BinaryFormat) -> Self {
        Self {
            name,
            arch,
            format,
            functions: Vec::new(),
            data_sections: Vec::new(),
            raw_binary: Vec::new(),
            metadata: BinaryMetadata {
                entry_point: 0,
                program_headers: Vec::new(),
                section_headers: Vec::new(),
                is_pie: false,
            },
        }
    }

    /// Look up a function by name.
    pub fn function(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Look up a function mutably by name.
    pub fn function_mut(&mut self, name: &str) -> Option<&mut Function> {
        self.functions.iter_mut().find(|f| f.name == name)
    }

    /// Find the data section whose address range contains `addr`.
    pub fn data_section_for_addr(&self, addr: u64) -> Option<&DataSection> {
        self.data_sections.iter().find(|s| {
            addr >= s.vaddr && addr < s.vaddr + s.data.len() as u64
        })
    }

    /// Find the data section mutably whose address range contains `addr`.
    pub fn data_section_for_addr_mut(&mut self, addr: u64) -> Option<&mut DataSection> {
        self.data_sections.iter_mut().find(|s| {
            addr >= s.vaddr && addr < s.vaddr + s.data.len() as u64
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::function::Function;

    #[test]
    fn module_new() {
        let m = Module::new("test.elf".into(), Architecture::X86_64, BinaryFormat::Elf);
        assert_eq!(m.name, "test.elf");
        assert_eq!(m.arch, Architecture::X86_64);
        assert_eq!(m.format, BinaryFormat::Elf);
        assert!(m.functions.is_empty());
        assert!(m.data_sections.is_empty());
        assert!(m.raw_binary.is_empty());
    }

    #[test]
    fn function_lookup() {
        let mut m = Module::new("test".into(), Architecture::X86_64, BinaryFormat::Elf);
        m.functions.push(Function::new("main".into(), 0x401000, 50));
        m.functions.push(Function::new("helper".into(), 0x402000, 30));

        assert!(m.function("main").is_some());
        assert!(m.function("helper").is_some());
        assert!(m.function("missing").is_none());
    }

    #[test]
    fn data_section_for_addr_lookup() {
        let mut m = Module::new("test".into(), Architecture::X86_64, BinaryFormat::Elf);
        m.data_sections.push(DataSection {
            name: ".rodata".into(),
            vaddr: 0x600000,
            file_offset: 0x2000,
            data: vec![0u8; 256],
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: false,
            },
            relocations: vec![],
        });

        // Address within the section
        assert!(m.data_section_for_addr(0x600000).is_some());
        assert!(m.data_section_for_addr(0x6000ff).is_some());

        // Address outside the section
        assert!(m.data_section_for_addr(0x600100).is_none());
        assert!(m.data_section_for_addr(0x500000).is_none());
    }
}
