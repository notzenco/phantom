//! Format-independent encoding and patching shared by every binary emitter.

use tracing::{debug, trace, warn};

use phantom_core::ir::function::{Function, RawCodeFixupTarget};
use phantom_core::ir::instruction::Opcode;
use phantom_core::ir::module::Module;
use phantom_disasm::IcedEncoder;

use crate::error::BackendError;

/// Re-encode every lifted function that already lives in the image and write it
/// back over its original bytes, NOP-padding any slack.
pub(crate) fn patch_existing_functions(
    module: &Module,
    binary: &mut [u8],
    indices: &[usize],
    vaddr_to_offset: impl Fn(u64) -> Option<u64>,
) -> Result<(), BackendError> {
    let bitness = bitness_for_module(module);
    for &idx in indices {
        let func = &module.functions[idx];
        let mut encoded = re_encode_function(func, bitness)?;
        apply_raw_fixups(&mut encoded, func, func.address)?;

        let original_size = func.size as usize;
        if encoded.len() > original_size {
            return Err(BackendError::FunctionGrew {
                name: func.name.clone(),
                addr: func.address,
                original: original_size,
                new: encoded.len(),
            });
        }

        let offset = vaddr_to_offset(func.address).ok_or_else(|| {
            BackendError::Emit(format!(
                "Cannot map function {} at {:#x} to file offset",
                func.name, func.address
            ))
        })? as usize;

        nop_pad(&mut encoded, original_size);
        if offset + encoded.len() > binary.len() {
            return Err(BackendError::Emit(format!(
                "Function {} at offset {:#x} extends beyond binary (size {:#x})",
                func.name,
                offset,
                binary.len()
            )));
        }

        binary[offset..offset + encoded.len()].copy_from_slice(&encoded);
        trace!(
            func = %func.name,
            addr = %format!("{:#x}", func.address),
            file_offset = %format!("{:#x}", offset),
            encoded_size = encoded.len(),
            "Patched existing function"
        );
    }
    Ok(())
}

/// Write data sections whose contents changed back into the image, returning
/// the virtual addresses of the sections that were modified.
pub(crate) fn patch_data_sections(module: &Module, binary: &mut [u8]) -> Vec<u64> {
    let mut modified = Vec::new();
    for ds in &module.data_sections {
        let offset = ds.file_offset as usize;
        let end = offset + ds.data.len();
        if end > binary.len() {
            warn!(section = %ds.name, "Data section extends beyond binary, skipping");
            continue;
        }
        if binary[offset..end] != ds.data[..] {
            binary[offset..end].copy_from_slice(&ds.data);
            modified.push(ds.vaddr);
            debug!(
                section = %ds.name,
                offset = %format!("{:#x}", offset),
                size = ds.data.len(),
                "Patched data section"
            );
        }
    }
    modified
}

/// Injected functions laid out back to back from a chosen load address.
pub(crate) struct NewCode {
    pub code: Vec<u8>,
    /// `(function index, assigned virtual address)` for each injected function.
    pub placed: Vec<(usize, u64)>,
}

/// Lay out injected functions back to back starting at `load_addr`.
pub(crate) fn encode_new_functions(
    module: &Module,
    indices: &[usize],
    load_addr: u64,
) -> Result<NewCode, BackendError> {
    let bitness = bitness_for_module(module);
    let mut code = Vec::new();
    let mut placed = Vec::new();
    for &idx in indices {
        let func = &module.functions[idx];
        let func_addr = load_addr + code.len() as u64;
        let mut encoded = re_encode_function_at(func, bitness, func_addr)?;
        apply_raw_fixups(&mut encoded, func, func_addr)?;
        code.extend_from_slice(&encoded);
        placed.push((idx, func_addr));
        debug!(
            func = %func.name,
            addr = %format!("{:#x}", func_addr),
            size = encoded.len(),
            "Encoded new function"
        );
    }
    Ok(NewCode { code, placed })
}

/// Re-encode a function using its original addresses.
///
/// For each instruction:
/// - Unmodified instructions use `original_bytes` directly (safest).
/// - Modified instructions with `iced_code` are re-encoded via IcedEncoder.
/// - `RawBytes` opcodes use the bytes from the variant.
pub(crate) fn re_encode_function(func: &Function, bitness: u32) -> Result<Vec<u8>, BackendError> {
    re_encode_function_impl(func, bitness, None)
}

/// Re-encode a function at a specific base address (for new functions).
pub(crate) fn re_encode_function_at(
    func: &Function,
    bitness: u32,
    base_addr: u64,
) -> Result<Vec<u8>, BackendError> {
    re_encode_function_impl(func, bitness, Some(base_addr))
}

/// Core re-encoding implementation.
///
/// If `base_addr` is Some, all instructions are offset from that base.
/// If None, instructions keep their original addresses.
pub(crate) fn re_encode_function_impl(
    func: &Function,
    bitness: u32,
    base_addr: Option<u64>,
) -> Result<Vec<u8>, BackendError> {
    let encoder = IcedEncoder::new(bitness);
    let mut result = Vec::new();

    // Sort blocks by start_addr to ensure correct ordering.
    let mut blocks: Vec<_> = func.blocks.iter().collect();
    blocks.sort_by_key(|b| b.start_addr);

    // Compute offset from original function address to new base (if any).
    let addr_delta = base_addr
        .map(|ba| ba as i64 - func.address as i64)
        .unwrap_or(0);

    for block in blocks {
        for insn in &block.instructions {
            let bytes = if !insn.meta.modified {
                // Unmodified: pass through original bytes.
                insn.original_bytes.clone()
            } else if let Opcode::RawBytes(ref raw) = insn.opcode {
                // RawBytes: use the stored bytes.
                raw.clone()
            } else if let Some(iced_code) = insn.meta.iced_code {
                // Modified with iced metadata: re-encode.
                let rip = (insn.address as i64 + addr_delta) as u64;
                re_encode_modified_instruction(insn, iced_code, rip, &encoder, bitness)?
            } else {
                // Modified but no iced metadata — fall back to original bytes.
                warn!(
                    addr = %format!("{:#x}", insn.address),
                    "Modified instruction without iced_code, using original bytes"
                );
                insn.original_bytes.clone()
            };

            result.extend_from_slice(&bytes);
        }
    }

    Ok(result)
}

/// Apply backend raw code fixups for injected bytecode functions.
pub(crate) fn apply_raw_fixups(
    encoded: &mut [u8],
    func: &Function,
    function_addr: u64,
) -> Result<(), BackendError> {
    for fixup in &func.raw_fixups {
        let offset = fixup.offset as usize;
        let end = offset + 8;
        if end > encoded.len() {
            return Err(BackendError::Emit(format!(
                "Raw fixup for function {} at offset {:#x} exceeds encoded size {:#x}",
                func.name,
                offset,
                encoded.len()
            )));
        }

        let value = match fixup.target {
            RawCodeFixupTarget::FunctionAddress { offset } => function_addr + offset,
        };

        encoded[offset..end].copy_from_slice(&value.to_le_bytes());
    }

    Ok(())
}

/// Re-encode a single modified instruction using iced-x86.
///
/// Decodes the original bytes to get the iced instruction, then re-encodes at the
/// target RIP. This lets BlockEncoder handle RIP-relative fixups correctly.
pub(crate) fn re_encode_modified_instruction(
    insn: &phantom_core::ir::instruction::Instruction,
    _iced_code: u16,
    rip: u64,
    encoder: &IcedEncoder,
    bitness: u32,
) -> Result<Vec<u8>, BackendError> {
    // Decode the original bytes to reconstruct the iced_x86::Instruction.
    // We use the original bytes as a base and then apply modifications.
    // For Phase 1, the primary modification is to data references (e.g., LEA
    // pointing to a new address). The iced instruction carries the displacement,
    // so we decode the original, update the displacement if a RipRelative operand
    // changed, and re-encode.
    let disasm = phantom_disasm::IcedDisassembler::new(bitness);
    let decoded = disasm.decode_all(&insn.original_bytes, insn.address)?;

    if decoded.is_empty() {
        return Err(BackendError::Encode(format!(
            "Failed to decode instruction at {:#x} for re-encoding",
            insn.address
        )));
    }

    let mut iced_insn = decoded[0].instruction;

    // Apply operand modifications. Check for RipRelative operands that indicate
    // the target address changed.
    for op in &insn.operands {
        if let phantom_core::ir::types::Operand::RipRelative(target_addr) = op {
            // Update the memory displacement to the new target.
            iced_insn.set_memory_displacement64(*target_addr);
        }
    }

    let bytes = encoder.encode_instruction(&iced_insn, rip)?;
    Ok(bytes)
}

/// Pad a byte buffer with NOP (0x90) instructions to reach `target_len`.
pub(crate) fn nop_pad(buf: &mut Vec<u8>, target_len: usize) {
    while buf.len() < target_len {
        buf.push(0x90);
    }
}

/// Read a little-endian u64 from binary at the given offset.
pub(crate) fn read_u64_le(binary: &[u8], offset: usize) -> u64 {
    let bytes: [u8; 8] = binary[offset..offset + 8].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

/// Read a little-endian u16 from binary at the given offset.
pub(crate) fn read_u16_le(binary: &[u8], offset: usize) -> u16 {
    let bytes: [u8; 2] = binary[offset..offset + 2].try_into().unwrap();
    u16::from_le_bytes(bytes)
}

/// Write a little-endian u64 to binary at the given offset.
pub(crate) fn write_u64_le(binary: &mut [u8], offset: usize, value: u64) {
    binary[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Write a little-endian u16 to binary at the given offset.
pub(crate) fn write_u16_le(binary: &mut [u8], offset: usize, value: u16) {
    binary[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Align a value up to the given alignment (must be a power of two).
pub(crate) fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Determine bitness from the module's architecture.
pub(crate) fn bitness_for_module(module: &Module) -> u32 {
    match module.arch {
        phantom_core::Architecture::X86_64 => 64,
        phantom_core::Architecture::X86 => 32,
        _ => 64, // Default to 64-bit.
    }
}
