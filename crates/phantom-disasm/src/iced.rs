use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, InstructionBlock,
};
use tracing::trace;

use crate::DisasmError;

/// A decoded instruction with its raw bytes and iced-x86 metadata.
#[derive(Clone, Debug)]
pub struct DecodedInsn {
    /// Virtual address of this instruction.
    pub address: u64,
    /// Raw bytes of the instruction.
    pub bytes: Vec<u8>,
    /// The decoded iced-x86 instruction (full struct, needed for re-encoding).
    pub instruction: iced_x86::Instruction,
    /// The mnemonic of this instruction.
    pub mnemonic: iced_x86::Mnemonic,
    /// The Code enum value (stored for InstructionMeta.iced_code).
    pub code: iced_x86::Code,
    /// Operand count.
    pub op_count: u32,
}

/// Disassembler wrapping iced-x86's `Decoder`.
pub struct IcedDisassembler {
    bitness: u32,
}

impl IcedDisassembler {
    /// Create a new disassembler for the given bitness (32 or 64).
    pub fn new(bitness: u32) -> Self {
        Self { bitness }
    }

    /// Decode all instructions in the byte slice starting at `base_address`.
    pub fn decode_all(
        &self,
        bytes: &[u8],
        base_address: u64,
    ) -> Result<Vec<DecodedInsn>, DisasmError> {
        let mut decoder = Decoder::new(self.bitness, bytes, DecoderOptions::NONE);
        decoder.set_ip(base_address);

        let mut results = Vec::new();
        let mut offset: usize = 0;

        for insn in decoder.iter() {
            let len = insn.len();
            let raw = bytes[offset..offset + len].to_vec();

            trace!(
                address = insn.ip(),
                len,
                mnemonic = ?insn.mnemonic(),
                "decoded instruction"
            );

            results.push(DecodedInsn {
                address: insn.ip(),
                bytes: raw,
                mnemonic: insn.mnemonic(),
                code: insn.code(),
                op_count: insn.op_count(),
                instruction: insn,
            });

            offset += len;
        }

        Ok(results)
    }

    /// Decode a single instruction at the given `offset` within the byte slice.
    ///
    /// `base_address` is the virtual address corresponding to `bytes[0]`.
    pub fn decode_at(
        &self,
        bytes: &[u8],
        base_address: u64,
        offset: usize,
    ) -> Result<DecodedInsn, DisasmError> {
        if offset >= bytes.len() {
            return Err(DisasmError::InvalidAddress {
                addr: base_address + offset as u64,
            });
        }

        let slice = &bytes[offset..];
        let ip = base_address + offset as u64;

        let mut decoder = Decoder::new(self.bitness, slice, DecoderOptions::NONE);
        decoder.set_ip(ip);

        let insn = decoder.iter().next().ok_or_else(|| {
            DisasmError::Decode(format!("failed to decode instruction at {ip:#x}"))
        })?;

        // iced-x86 returns a INVALID instruction on decode failure rather than None
        if insn.is_invalid() {
            return Err(DisasmError::Decode(format!(
                "invalid instruction at {ip:#x}"
            )));
        }

        let len = insn.len();
        let raw = slice[..len].to_vec();

        Ok(DecodedInsn {
            address: insn.ip(),
            bytes: raw,
            mnemonic: insn.mnemonic(),
            code: insn.code(),
            op_count: insn.op_count(),
            instruction: insn,
        })
    }
}

/// Encoder wrapping iced-x86's `BlockEncoder`.
pub struct IcedEncoder {
    bitness: u32,
}

impl IcedEncoder {
    /// Create a new encoder for the given bitness (32 or 64).
    pub fn new(bitness: u32) -> Self {
        Self { bitness }
    }

    /// Re-encode a single instruction at the given `rip`.
    ///
    /// Uses `BlockEncoder` so that RIP-relative fixups are handled correctly.
    pub fn encode_instruction(
        &self,
        instruction: &iced_x86::Instruction,
        rip: u64,
    ) -> Result<Vec<u8>, DisasmError> {
        let instructions = [*instruction];
        let block = InstructionBlock::new(&instructions, rip);
        let encoded = BlockEncoder::encode(self.bitness, block, BlockEncoderOptions::NONE)
            .map_err(|e| DisasmError::Encode(e.to_string()))?;
        Ok(encoded.code_buffer)
    }

    /// Re-encode multiple instructions as a contiguous block at the given `rip`.
    ///
    /// Uses `BlockEncoder` which correctly resolves relative jumps/calls within
    /// the block.
    pub fn encode_instructions(
        &self,
        instructions: &[iced_x86::Instruction],
        rip: u64,
    ) -> Result<Vec<u8>, DisasmError> {
        let block = InstructionBlock::new(instructions, rip);
        let encoded = BlockEncoder::encode(self.bitness, block, BlockEncoderOptions::NONE)
            .map_err(|e| DisasmError::Encode(e.to_string()))?;
        Ok(encoded.code_buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Code, Mnemonic, Register};

    #[test]
    fn decode_nop() {
        let disasm = IcedDisassembler::new(64);
        let insns = disasm.decode_all(&[0x90], 0x1000).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, Mnemonic::Nop);
        assert_eq!(insns[0].bytes.len(), 1);
        assert_eq!(insns[0].address, 0x1000);
    }

    #[test]
    fn decode_multiple() {
        let disasm = IcedDisassembler::new(64);
        // nop, nop, ret
        let insns = disasm.decode_all(&[0x90, 0x90, 0xC3], 0x1000).unwrap();
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].mnemonic, Mnemonic::Nop);
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[1].mnemonic, Mnemonic::Nop);
        assert_eq!(insns[1].address, 0x1001);
        assert_eq!(insns[2].mnemonic, Mnemonic::Ret);
        assert_eq!(insns[2].address, 0x1002);
    }

    #[test]
    fn roundtrip() {
        // mov rax, rbx = 48 89 D8
        let original = [0x48u8, 0x89, 0xD8];
        let base = 0x1000u64;

        let disasm = IcedDisassembler::new(64);
        let insns = disasm.decode_all(&original, base).unwrap();
        assert_eq!(insns.len(), 1);

        let encoder = IcedEncoder::new(64);
        let encoded = encoder
            .encode_instruction(&insns[0].instruction, base)
            .unwrap();
        assert_eq!(encoded, original);
    }

    #[test]
    fn encode_single() {
        // Manually construct: mov rax, rbx using iced_x86's factory
        let insn =
            iced_x86::Instruction::with2(Code::Mov_r64_rm64, Register::RAX, Register::RBX)
                .unwrap();

        let encoder = IcedEncoder::new(64);
        let bytes = encoder.encode_instruction(&insn, 0x1000).unwrap();
        // Mov_r64_rm64 encodes as 48 8B C3 (REX.W + MOV r64, r/m64)
        assert_eq!(bytes, [0x48, 0x8B, 0xC3]);

        // Verify we can decode it back to a mov
        let disasm = IcedDisassembler::new(64);
        let decoded = disasm.decode_all(&bytes, 0x1000).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].mnemonic, Mnemonic::Mov);
        assert_eq!(decoded[0].instruction.op0_register(), Register::RAX);
        assert_eq!(decoded[0].instruction.op1_register(), Register::RBX);
    }

    #[test]
    fn decode_rip_relative() {
        // LEA rax, [rip+0x10]  =>  48 8D 05 10 00 00 00
        let bytes = [0x48u8, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        let base = 0x1000u64;

        let disasm = IcedDisassembler::new(64);
        let insns = disasm.decode_all(&bytes, base).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, Mnemonic::Lea);
        assert_eq!(insns[0].op_count, 2);
        // First operand is RAX
        assert_eq!(insns[0].instruction.op0_register(), Register::RAX);
        // The memory displacement target should be rip + 7 (insn len) + 0x10 = 0x1017
        assert_eq!(
            insns[0].instruction.memory_displacement64(),
            base + 7 + 0x10
        );
    }

    #[test]
    fn decode_at_offset() {
        let disasm = IcedDisassembler::new(64);
        // nop, nop, ret
        let bytes = [0x90u8, 0x90, 0xC3];
        let insn = disasm.decode_at(&bytes, 0x1000, 2).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Ret);
        assert_eq!(insn.address, 0x1002);
    }

    #[test]
    fn decode_at_out_of_bounds() {
        let disasm = IcedDisassembler::new(64);
        let bytes = [0x90u8];
        let result = disasm.decode_at(&bytes, 0x1000, 5);
        assert!(result.is_err());
    }
}
