//! PE32+ (Windows x86-64) emitter. Like the ELF backend it patches the original
//! image in place and appends injected code as a new section.

use tracing::{debug, warn};

use phantom_core::ir::module::Module;

use crate::common::{
    align_up, encode_new_functions, patch_data_sections, patch_existing_functions, NewCode,
};
use crate::error::BackendError;
use crate::Backend;

const PE32_PLUS_MAGIC: u16 = 0x20b;
const SECTION_HEADER_SIZE: usize = 40;
const CERTIFICATE_DIRECTORY: usize = 4;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const INJECTED_SECTION_NAME: &[u8; 8] = b".phantom";

/// Windows PE emitter.
pub struct PeBackend;

impl PeBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PeBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// File offsets of the PE header fields this backend reads or rewrites.
#[derive(Debug, Clone, Copy)]
struct Layout {
    coff: usize,
    optional: usize,
    sections: usize,
}

#[derive(Debug, Clone, Copy)]
struct Section {
    header_offset: usize,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
}

impl Layout {
    fn parse(binary: &[u8]) -> Result<Self, BackendError> {
        let pe = read_u32(binary, 0x3c)? as usize;
        if binary.get(pe..pe + 4) != Some(b"PE\0\0".as_slice()) {
            return Err(BackendError::Emit("missing PE signature".into()));
        }
        let coff = pe + 4;
        let optional = coff + 20;
        if read_u16(binary, optional)? != PE32_PLUS_MAGIC {
            return Err(BackendError::Emit("only PE32+ images are supported".into()));
        }
        let sections = optional + read_u16(binary, coff + 16)? as usize;
        Ok(Self {
            coff,
            optional,
            sections,
        })
    }

    fn section_count(&self, binary: &[u8]) -> Result<usize, BackendError> {
        Ok(read_u16(binary, self.coff + 2)? as usize)
    }

    fn image_base(&self, binary: &[u8]) -> Result<u64, BackendError> {
        read_u64(binary, self.optional + 24)
    }

    fn section_alignment(&self, binary: &[u8]) -> Result<u64, BackendError> {
        Ok(read_u32(binary, self.optional + 32)? as u64)
    }

    fn file_alignment(&self, binary: &[u8]) -> Result<u64, BackendError> {
        Ok(read_u32(binary, self.optional + 36)? as u64)
    }

    fn size_of_headers(&self, binary: &[u8]) -> Result<usize, BackendError> {
        Ok(read_u32(binary, self.optional + 60)? as usize)
    }

    fn data_directory(&self, index: usize) -> usize {
        self.optional + 112 + index * 8
    }

    fn sections(&self, binary: &[u8]) -> Result<Vec<Section>, BackendError> {
        (0..self.section_count(binary)?)
            .map(|i| {
                let off = self.sections + i * SECTION_HEADER_SIZE;
                Ok(Section {
                    header_offset: off,
                    virtual_size: read_u32(binary, off + 8)?,
                    virtual_address: read_u32(binary, off + 12)?,
                    raw_size: read_u32(binary, off + 16)?,
                    raw_pointer: read_u32(binary, off + 20)?,
                })
            })
            .collect()
    }
}

impl Section {
    fn virtual_extent(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        }
    }
}

impl Backend for PeBackend {
    fn emit(&self, module: &Module) -> Result<Vec<u8>, BackendError> {
        if module.raw_binary.is_empty() {
            return Err(BackendError::NoRawBinary);
        }
        let mut binary = module.raw_binary.clone();
        let layout = Layout::parse(&binary)?;
        let image_base = layout.image_base(&binary)?;
        let sections = layout.sections(&binary)?;

        let in_image = |vaddr: u64| {
            sections.iter().any(|s| {
                let start = image_base + s.virtual_address as u64;
                vaddr >= start && vaddr < start + s.virtual_extent() as u64
            })
        };
        let (new_funcs, existing_funcs): (Vec<usize>, Vec<usize>) = (0..module.functions.len())
            .partition(|&i| {
                let addr = module.functions[i].address;
                addr == 0 || !in_image(addr)
            });

        patch_existing_functions(module, &mut binary, &existing_funcs, |vaddr| {
            let rva = vaddr.checked_sub(image_base)?;
            sections.iter().find_map(|s| {
                let start = s.virtual_address as u64;
                (rva >= start && rva < start + s.raw_size as u64)
                    .then(|| s.raw_pointer as u64 + (rva - start))
            })
        })?;

        // Decryption happens in place at runtime, so sections holding encrypted
        // data must be mapped writable.
        for vaddr in patch_data_sections(module, &mut binary) {
            let rva = vaddr - image_base;
            if let Some(s) = sections.iter().find(|s| {
                rva >= s.virtual_address as u64
                    && rva < (s.virtual_address + s.virtual_extent()) as u64
            }) {
                let flags = read_u32(&binary, s.header_offset + 36)?;
                write_u32(
                    &mut binary,
                    s.header_offset + 36,
                    flags | IMAGE_SCN_MEM_WRITE,
                );
            }
        }

        if !new_funcs.is_empty() {
            strip_certificate(&mut binary, &layout)?;

            let section_alignment = layout.section_alignment(&binary)?;
            let image_end = sections
                .iter()
                .map(|s| (s.virtual_address + s.virtual_extent()) as u64)
                .max()
                .unwrap_or(0);
            let new_rva = align_up(image_end, section_alignment);

            let NewCode { code, placed } =
                encode_new_functions(module, &new_funcs, image_base + new_rva)?;
            append_code_section(&mut binary, &layout, new_rva as u32, &code)?;

            if let Some(&(_, addr)) = placed
                .iter()
                .find(|(idx, _)| module.functions[*idx].name == "__phantom_init")
            {
                let entry_rva = (addr - image_base) as u32;
                debug!(entry_rva = %format!("{entry_rva:#x}"), "Redirecting entry point");
                write_u32(&mut binary, layout.optional + 16, entry_rva);
            }
        }

        let checksum = pe_checksum(&binary, layout.optional + 64);
        write_u32(&mut binary, layout.optional + 64, checksum);
        Ok(binary)
    }
}

/// Modifying the image invalidates any Authenticode signature, and the signature
/// blob must stay at the end of the file, so drop it.
fn strip_certificate(binary: &mut Vec<u8>, layout: &Layout) -> Result<(), BackendError> {
    let dir = layout.data_directory(CERTIFICATE_DIRECTORY);
    let offset = read_u32(binary, dir)? as usize;
    let size = read_u32(binary, dir + 4)? as usize;
    if size == 0 {
        return Ok(());
    }
    warn!("Removing Authenticode signature invalidated by protection");
    if offset + size == binary.len() {
        binary.truncate(offset);
    }
    write_u32(binary, dir, 0);
    write_u32(binary, dir + 4, 0);
    Ok(())
}

/// Append `code` as a new executable section mapped at `rva`.
fn append_code_section(
    binary: &mut Vec<u8>,
    layout: &Layout,
    rva: u32,
    code: &[u8],
) -> Result<(), BackendError> {
    let count = layout.section_count(binary)?;
    let header = layout.sections + count * SECTION_HEADER_SIZE;
    let header_end = header + SECTION_HEADER_SIZE;
    let first_raw = layout
        .sections(binary)?
        .iter()
        .filter(|s| s.raw_size > 0)
        .map(|s| s.raw_pointer as usize)
        .min()
        .unwrap_or(usize::MAX);
    if header_end > layout.size_of_headers(binary)?
        || header_end > first_raw
        || binary[header..header_end].iter().any(|&b| b != 0)
    {
        return Err(BackendError::Emit(
            "No room for another section header in the PE headers".into(),
        ));
    }

    let file_alignment = layout.file_alignment(binary)?;
    let section_alignment = layout.section_alignment(binary)?;
    let raw_pointer = align_up(binary.len() as u64, file_alignment) as usize;
    let raw_size = align_up(code.len() as u64, file_alignment) as usize;
    binary.resize(raw_pointer, 0);
    binary.extend_from_slice(code);
    binary.resize(raw_pointer + raw_size, 0);

    binary[header..header + 8].copy_from_slice(INJECTED_SECTION_NAME);
    write_u32(binary, header + 8, code.len() as u32);
    write_u32(binary, header + 12, rva);
    write_u32(binary, header + 16, raw_size as u32);
    write_u32(binary, header + 20, raw_pointer as u32);
    write_u32(
        binary,
        header + 36,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    );

    write_u16(binary, layout.coff + 2, (count + 1) as u16);
    let size_of_code = read_u32(binary, layout.optional + 4)?;
    write_u32(binary, layout.optional + 4, size_of_code + raw_size as u32);
    let size_of_image = align_up(rva as u64 + code.len() as u64, section_alignment);
    write_u32(binary, layout.optional + 56, size_of_image as u32);

    debug!(
        rva = %format!("{rva:#x}"),
        raw_pointer = %format!("{raw_pointer:#x}"),
        size = code.len(),
        "Appended .phantom section"
    );
    Ok(())
}

/// The standard PE image checksum, computed with the checksum field treated as zero.
fn pe_checksum(binary: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    for (i, chunk) in binary.chunks(2).enumerate() {
        let offset = i * 2;
        if offset == checksum_offset || offset == checksum_offset + 2 {
            continue;
        }
        let word = match chunk {
            [lo, hi] => u16::from_le_bytes([*lo, *hi]),
            [lo] => *lo as u16,
            _ => unreachable!(),
        };
        sum += word as u64;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum as u32) + binary.len() as u32
}

fn field<const N: usize>(binary: &[u8], offset: usize) -> Result<[u8; N], BackendError> {
    binary
        .get(offset..offset + N)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| BackendError::Emit(format!("PE header truncated at {offset:#x}")))
}

fn read_u16(binary: &[u8], offset: usize) -> Result<u16, BackendError> {
    field(binary, offset).map(u16::from_le_bytes)
}

fn read_u32(binary: &[u8], offset: usize) -> Result<u32, BackendError> {
    field(binary, offset).map(u32::from_le_bytes)
}

fn read_u64(binary: &[u8], offset: usize) -> Result<u64, BackendError> {
    field(binary, offset).map(u64::from_le_bytes)
}

fn write_u16(binary: &mut [u8], offset: usize, value: u16) {
    binary[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(binary: &mut [u8], offset: usize, value: u32) {
    binary[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPT: usize = 0x80 + 24;
    const SECTIONS: usize = OPT + 240;

    /// A minimal PE32+ image: one `.text` section at RVA 0x1000, headers 0x400 bytes.
    fn synthetic_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x600];
        image[..2].copy_from_slice(b"MZ");
        write_u32(&mut image, 0x3c, 0x80);
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        write_u16(&mut image, 0x84, 0x8664);
        write_u16(&mut image, 0x86, 1);
        write_u16(&mut image, 0x94, 240);
        write_u16(&mut image, OPT, PE32_PLUS_MAGIC);
        image[OPT + 24..OPT + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        write_u32(&mut image, OPT + 32, 0x1000);
        write_u32(&mut image, OPT + 36, 0x200);
        write_u32(&mut image, OPT + 56, 0x2000);
        write_u32(&mut image, OPT + 60, 0x400);
        image[SECTIONS..SECTIONS + 8].copy_from_slice(b".text\0\0\0");
        write_u32(&mut image, SECTIONS + 8, 0x10);
        write_u32(&mut image, SECTIONS + 12, 0x1000);
        write_u32(&mut image, SECTIONS + 16, 0x200);
        write_u32(&mut image, SECTIONS + 20, 0x400);
        image
    }

    #[test]
    fn parses_layout_of_synthetic_image() {
        let image = synthetic_image();
        let layout = Layout::parse(&image).unwrap();
        assert_eq!(layout.sections, SECTIONS);
        assert_eq!(layout.image_base(&image).unwrap(), 0x1_4000_0000);
        let sections = layout.sections(&image).unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].virtual_address, 0x1000);
    }

    #[test]
    fn appends_section_and_updates_headers() {
        let mut image = synthetic_image();
        let layout = Layout::parse(&image).unwrap();
        append_code_section(&mut image, &layout, 0x2000, &[0xC3; 5]).unwrap();

        assert_eq!(layout.section_count(&image).unwrap(), 2);
        let new = layout.sections(&image).unwrap()[1];
        assert_eq!(new.virtual_address, 0x2000);
        assert_eq!(new.virtual_size, 5);
        assert_eq!(new.raw_pointer, 0x600);
        assert_eq!(new.raw_size, 0x200);
        assert_eq!(read_u32(&image, OPT + 56).unwrap(), 0x3000);
        assert_eq!(image.len(), 0x800);
        assert_eq!(&image[0x600..0x605], &[0xC3; 5]);
    }

    #[test]
    fn refuses_to_overwrite_nonzero_header_bytes() {
        let mut image = synthetic_image();
        image[SECTIONS + SECTION_HEADER_SIZE] = 0xAA;
        let layout = Layout::parse(&image).unwrap();
        assert!(append_code_section(&mut image, &layout, 0x2000, &[0xC3]).is_err());
    }

    #[test]
    fn checksum_ignores_its_own_field() {
        let mut image = synthetic_image();
        let before = pe_checksum(&image, OPT + 64);
        write_u32(&mut image, OPT + 64, 0xDEAD_BEEF);
        assert_eq!(pe_checksum(&image, OPT + 64), before);
        image[0x500] ^= 1;
        assert_ne!(pe_checksum(&image, OPT + 64), before);
    }

    #[test]
    fn strips_trailing_certificate() {
        let mut image = synthetic_image();
        image.extend_from_slice(&[0x55; 0x20]);
        let layout = Layout::parse(&image).unwrap();
        let dir = layout.data_directory(CERTIFICATE_DIRECTORY);
        write_u32(&mut image, dir, 0x600);
        write_u32(&mut image, dir + 4, 0x20);

        strip_certificate(&mut image, &layout).unwrap();
        assert_eq!(image.len(), 0x600);
        assert_eq!(read_u32(&image, dir + 4).unwrap(), 0);
    }
}
