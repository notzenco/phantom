//! String encryption pass — encrypts string literals in data sections using XOR
//! and generates position-independent x86_64 decryptor thunks.

use std::collections::HashMap;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tracing::{debug, info, warn};

use phantom_core::ir::block::{BasicBlock, BlockId, Terminator};
use phantom_core::ir::function::{Function, RawCodeFixup, RawCodeFixupTarget};
use phantom_core::ir::instruction::{Instruction, InstructionMeta, Opcode};
use phantom_core::ir::module::Module;
use phantom_core::ir::types::OperandSize;
use phantom_core::pass::{Pass, PassInfo};
use phantom_core::PhantomError;

/// Information about a string reference found in the IR.
#[derive(Debug, Clone)]
struct StringRef {
    /// Virtual address of the referenced string data.
    vaddr: u64,
    /// Size of the string data (including any null terminator).
    size: usize,
}

/// Metadata for an encrypted string.
#[derive(Debug, Clone)]
struct EncryptedString {
    /// Virtual address of the string in the data section.
    vaddr: u64,
    /// Length of the string data that was encrypted.
    len: usize,
    /// XOR key used to encrypt.
    key: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RawCodeBlob {
    bytes: Vec<u8>,
    fixups: Vec<RawCodeFixup>,
}

/// A transform pass that encrypts string literals in data sections using XOR
/// and generates x86_64 decryptor thunks to decrypt them at runtime.
///
/// The pass:
/// 1. Scans instructions for data references marked as strings
/// 2. XOR-encrypts those string bytes in-place in their data sections
/// 3. Generates a position-independent decryptor thunk for each string
/// 4. Patches original LEA instructions to CALL the appropriate thunk
pub struct StringEncryptionPass {
    /// Optional RNG seed for reproducible builds (useful for testing).
    seed: Option<u64>,
}

impl StringEncryptionPass {
    /// Create a new pass with a random (non-deterministic) key.
    pub fn new() -> Self {
        Self { seed: None }
    }

    /// Create a new pass with a specific seed for reproducible output.
    pub fn with_seed(seed: u64) -> Self {
        Self { seed: Some(seed) }
    }
}

impl Default for StringEncryptionPass {
    fn default() -> Self {
        Self::new()
    }
}

impl Pass for StringEncryptionPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "string_encryption".into(),
            description: "Encrypts string literals with XOR and generates decryptor thunks".into(),
        }
    }

    fn run(&self, module: &mut Module) -> Result<(), PhantomError> {
        // Step 1: Collect all string references from instructions.
        let string_refs = collect_string_refs(module);
        if string_refs.is_empty() {
            info!("No string references found; nothing to encrypt.");
            return Ok(());
        }
        info!("Found {} string reference(s).", string_refs.len());

        // Deduplicate by vaddr — the same string may be referenced from multiple places.
        let unique_vaddrs = deduplicate_by_vaddr(&string_refs);
        info!(
            "After deduplication: {} unique string(s) to encrypt.",
            unique_vaddrs.len()
        );

        // Step 2: Encrypt strings in data sections and generate thunk metadata.
        let encrypted = encrypt_strings(module, &unique_vaddrs, self.seed)?;

        // Step 3: Generate per-string decryptor thunk functions.
        let mut thunk_codes = Vec::new();
        for enc in &encrypted {
            let thunk_code = generate_thunk_with_fixups(enc.vaddr, enc.len, &enc.key);
            debug!(
                "Generated decryptor thunk ({} bytes) for string at {:#x}",
                thunk_code.bytes.len(),
                enc.vaddr,
            );
            thunk_codes.push(thunk_code);
        }

        // Step 4: Generate a single __phantom_init function that:
        //   - Calls each decryptor thunk sequentially
        //   - Jumps to the original entry point
        // The backend assigns addresses and redirects the ELF entry point.
        let original_entry = module.metadata.entry_point;
        let init_code = generate_init_function_with_fixups(&thunk_codes, original_entry);
        let init_fn = make_thunk_function("__phantom_init", &init_code);
        module.functions.push(init_fn);

        info!(
            "Generated __phantom_init ({} bytes) wrapping {} decryptor thunk(s), entry={:#x}",
            init_code.bytes.len(),
            thunk_codes.len(),
            original_entry,
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Step 1 helpers
// ---------------------------------------------------------------------------

/// Walk every function/block/instruction and collect string DataRef entries.
fn collect_string_refs(module: &Module) -> Vec<StringRef> {
    let mut refs = Vec::new();
    for func in &module.functions {
        for block in &func.blocks {
            for instr in &block.instructions {
                for dref in &instr.data_refs {
                    if dref.is_string {
                        refs.push(StringRef {
                            vaddr: dref.vaddr,
                            size: dref.size,
                        });
                    }
                }
            }
        }
    }
    refs
}

/// Return one representative `(vaddr, size)` per unique vaddr,
/// preserving discovery order.
fn deduplicate_by_vaddr(refs: &[StringRef]) -> Vec<(u64, usize)> {
    let mut seen = HashMap::new();
    let mut out = Vec::new();
    for r in refs {
        seen.entry(r.vaddr).or_insert_with(|| {
            out.push((r.vaddr, r.size));
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Step 2: Encryption
// ---------------------------------------------------------------------------

/// XOR-encrypt each unique string in its data section, returning metadata.
fn encrypt_strings(
    module: &mut Module,
    unique: &[(u64, usize)],
    seed: Option<u64>,
) -> Result<Vec<EncryptedString>, PhantomError> {
    let mut rng: Box<dyn RngCore> = match seed {
        Some(s) => Box::new(StdRng::seed_from_u64(s)),
        None => Box::new(StdRng::from_entropy()),
    };

    let mut encrypted = Vec::with_capacity(unique.len());

    for &(vaddr, size) in unique {
        let section = module.data_section_for_addr_mut(vaddr).ok_or_else(|| {
            PhantomError::Pass(format!(
                "No data section contains string at {vaddr:#x}"
            ))
        })?;

        let offset = (vaddr - section.vaddr) as usize;
        if offset + size > section.data.len() {
            warn!(
                "String at {vaddr:#x} (len {size}) extends past section '{}'; skipping.",
                section.name
            );
            continue;
        }

        // Generate random XOR key.
        let key: Vec<u8> = (0..size).map(|_| rng.gen::<u8>()).collect();

        // Encrypt in-place.
        xor_in_place(&mut section.data[offset..offset + size], &key);

        encrypted.push(EncryptedString {
            vaddr,
            len: size,
            key,
        });

        debug!("Encrypted {size} bytes at {vaddr:#x} in section '{}'", section.name);
    }

    Ok(encrypted)
}

/// XOR `data` with `key` in-place (key is repeated if shorter, but here they
/// are always the same length).
fn xor_in_place(data: &mut [u8], key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

/// XOR two byte slices, returning a new Vec (useful for tests).
pub fn xor_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

// We need the RngCore trait to box different RNG types.
use rand::RngCore;

// ---------------------------------------------------------------------------
// Step 3: Thunk generation
// ---------------------------------------------------------------------------

/// Generate a position-independent x86_64 decryptor thunk for a single string.
///
/// The thunk:
/// 1. Saves caller-saved registers it uses
/// 2. XOR-decrypts the string data in-place using a key embedded after the RET
/// 3. Loads the (now-decrypted) string address into RAX
/// 4. Restores registers and returns
///
/// Key bytes are appended immediately after the RET instruction.
#[allow(clippy::vec_init_then_push)]
pub fn generate_thunk(string_vaddr: u64, string_len: usize, key: &[u8]) -> Vec<u8> {
    generate_thunk_with_fixups(string_vaddr, string_len, key).bytes
}

#[allow(clippy::vec_init_then_push)]
fn generate_thunk_with_fixups(string_vaddr: u64, string_len: usize, key: &[u8]) -> RawCodeBlob {
    assert_eq!(
        key.len(),
        string_len,
        "key length must equal string length"
    );

    let mut code = Vec::new();
    let mut fixups = Vec::new();

    // Save registers we clobber.
    code.push(0x53); // push rbx
    code.push(0x57); // push rdi
    code.push(0x56); // push rsi
    code.push(0x51); // push rcx
    code.push(0x52); // push rdx

    // Compute the image load bias as runtime_ip - link_time_ip.
    code.extend_from_slice(&[0x48, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00]); // lea rbx, [rip+0]
    let anchor_offset = code.len() as u64;
    code.extend_from_slice(&[0x48, 0xBA]); // mov rdx, imm64
    let anchor_fixup_offset = code.len() as u64;
    code.extend_from_slice(&0u64.to_le_bytes());
    fixups.push(RawCodeFixup {
        offset: anchor_fixup_offset,
        target: RawCodeFixupTarget::FunctionAddress {
            offset: anchor_offset,
        },
    });
    code.extend_from_slice(&[0x48, 0x29, 0xD3]); // sub rbx, rdx

    // mov rsi, imm64  — link-time address of the encrypted string
    code.extend_from_slice(&[0x48, 0xBE]);
    code.extend_from_slice(&string_vaddr.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x01, 0xDE]); // add rsi, rbx

    // mov ecx, imm32  — string length (loop counter)
    code.push(0xB9);
    code.extend_from_slice(&(string_len as u32).to_le_bytes());

    // lea rdi, [rip + disp32]  — address of key data (after the RET)
    let lea_pos = code.len();
    code.extend_from_slice(&[0x48, 0x8D, 0x3D]);
    code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

    // XOR decryption loop:
    let loop_start = code.len();

    // mov dl, [rsi]
    code.extend_from_slice(&[0x8A, 0x16]);
    // xor dl, [rdi]
    code.extend_from_slice(&[0x32, 0x17]);
    // mov [rsi], dl
    code.extend_from_slice(&[0x88, 0x16]);
    // inc rsi
    code.extend_from_slice(&[0x48, 0xFF, 0xC6]);
    // inc rdi
    code.extend_from_slice(&[0x48, 0xFF, 0xC7]);
    // dec ecx
    code.extend_from_slice(&[0xFF, 0xC9]);
    // jnz loop_start
    let jnz_pos = code.len();
    code.extend_from_slice(&[0x75, 0x00]); // placeholder rel8

    let loop_end = code.len();
    // Fix up jnz displacement (backward jump).
    let jnz_disp = (loop_start as isize - loop_end as isize) as i8;
    code[jnz_pos + 1] = jnz_disp as u8;

    // mov rax, imm64  — return the relocated decrypted string address in rax
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&string_vaddr.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x01, 0xD8]); // add rax, rbx

    // Restore saved registers.
    code.push(0x5A); // pop rdx
    code.push(0x59); // pop rcx
    code.push(0x5E); // pop rsi
    code.push(0x5F); // pop rdi
    code.push(0x5B); // pop rbx

    // ret
    code.push(0xC3);

    let ret_pos = code.len();

    // Append key bytes after the RET.
    code.extend_from_slice(key);

    // Fix up the LEA displacement to point to the key data.
    let lea_next_ip = lea_pos + 7; // LEA is 7 bytes: 48 8D 3D xx xx xx xx
    let disp = (ret_pos as i32) - (lea_next_ip as i32);
    code[lea_pos + 3..lea_pos + 7].copy_from_slice(&disp.to_le_bytes());

    RawCodeBlob { bytes: code, fixups }
}

/// Generate the __phantom_init function that inlines all decryptor thunks
/// and then jumps to the original entry point.
///
/// Layout:
///   [thunk_0 code (without its trailing RET)] [thunk_1 code ...] ... [jmp original_entry]
///
/// Each thunk is self-contained: it saves/restores registers and decrypts one string.
/// We inline them sequentially (replacing each RET with the next thunk) and end
/// with a jump to the original entry point.
pub fn generate_init_function(thunk_codes: &[Vec<u8>], original_entry: u64) -> Vec<u8> {
    let blobs = thunk_codes
        .iter()
        .map(|code| RawCodeBlob {
            bytes: code.clone(),
            fixups: Vec::new(),
        })
        .collect::<Vec<_>>();
    generate_init_function_with_fixups(&blobs, original_entry).bytes
}

fn generate_init_function_with_fixups(
    thunk_codes: &[RawCodeBlob],
    original_entry: u64,
) -> RawCodeBlob {
    let mut code = Vec::new();
    let mut fixups = Vec::new();

    // Preserve process-entry register state expected by the original entry point.
    code.push(0x50); // push rax
    code.push(0x53); // push rbx
    code.push(0x52); // push rdx

    for thunk in thunk_codes {
        let thunk_len = thunk.bytes.len() as i32;
        code.push(0xE8); // CALL rel32
        let jmp_size: i32 = 5;
        code.extend_from_slice(&jmp_size.to_le_bytes());

        code.push(0xE9); // JMP rel32
        code.extend_from_slice(&thunk_len.to_le_bytes());

        let thunk_offset = code.len() as u64;
        code.extend_from_slice(&thunk.bytes);
        fixups.extend(thunk.fixups.iter().cloned().map(|fixup| RawCodeFixup {
            offset: thunk_offset + fixup.offset,
            target: match fixup.target {
                RawCodeFixupTarget::FunctionAddress { offset } => {
                    RawCodeFixupTarget::FunctionAddress {
                        offset: thunk_offset + offset,
                    }
                }
            },
        }));
    }

    // Compute the image load bias, then jump to the relocated original entry.
    code.extend_from_slice(&[0x48, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00]); // lea rbx, [rip+0]
    let anchor_offset = code.len() as u64;
    code.extend_from_slice(&[0x48, 0xBA]); // mov rdx, imm64
    let anchor_fixup_offset = code.len() as u64;
    code.extend_from_slice(&0u64.to_le_bytes());
    fixups.push(RawCodeFixup {
        offset: anchor_fixup_offset,
        target: RawCodeFixupTarget::FunctionAddress {
            offset: anchor_offset,
        },
    });
    code.extend_from_slice(&[0x48, 0x29, 0xD3]); // sub rbx, rdx

    code.extend_from_slice(&[0x49, 0xBB]); // mov r11, imm64
    code.extend_from_slice(&original_entry.to_le_bytes());
    code.extend_from_slice(&[0x49, 0x01, 0xDB]); // add r11, rbx

    code.push(0x5A); // pop rdx
    code.push(0x5B); // pop rbx
    code.push(0x58); // pop rax
    code.extend_from_slice(&[0x41, 0xFF, 0xE3]); // jmp r11

    RawCodeBlob { bytes: code, fixups }
}

/// Wrap thunk code bytes into a `Function` with a single `RawBytes` instruction.
fn make_thunk_function(name: &str, code: &RawCodeBlob) -> Function {
    let instr = Instruction {
        address: 0,
        original_bytes: code.bytes.clone(),
        opcode: Opcode::RawBytes(code.bytes.clone()),
        operands: vec![],
        operand_size: OperandSize::Byte,
        data_refs: vec![],
        meta: InstructionMeta {
            iced_code: None,
            modified: true,
            modified_by: Some("string_encryption".into()),
        },
    };

    let block = BasicBlock {
        id: BlockId(0),
        start_addr: 0,
        end_addr: 0,
        instructions: vec![instr],
        terminator: Terminator::Return,
    };

    let mut func = Function::new(name.into(), 0, code.bytes.len() as u64);
    func.blocks.push(block);
    func.raw_fixups = code.fixups.clone();
    func
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::ir::module::{DataSection, SectionPermissions};
    use phantom_core::ir::types::DataRef;
    use phantom_core::{Architecture, BinaryFormat};

    /// XOR encrypt then decrypt with the same key produces the original.
    #[test]
    fn test_xor_roundtrip() {
        let original = b"Hello, World!\0";
        let key: Vec<u8> = (0..original.len()).map(|i| (i as u8).wrapping_mul(37)).collect();

        let encrypted = xor_bytes(original, &key);
        assert_ne!(&encrypted, original);

        let decrypted = xor_bytes(&encrypted, &key);
        assert_eq!(&decrypted, original);
    }

    /// Different keys produce different ciphertext.
    #[test]
    fn test_xor_different_keys() {
        let data = b"test string";
        let key1 = vec![0xAA; data.len()];
        let key2 = vec![0x55; data.len()];

        let enc1 = xor_bytes(data, &key1);
        let enc2 = xor_bytes(data, &key2);

        assert_ne!(enc1, enc2);
    }

    /// XOR with a zero key is the identity.
    #[test]
    fn test_xor_zero_key_identity() {
        let data = b"unchanged";
        let key = vec![0u8; data.len()];
        assert_eq!(xor_bytes(data, &key), data.to_vec());
    }

    /// Generated thunk bytes are non-empty and contain the key.
    #[test]
    fn test_thunk_generation() {
        let key = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let thunk = generate_thunk_with_fixups(0x400000, 4, &key);

        assert!(!thunk.bytes.is_empty());
        // The key bytes should appear at the end of the thunk.
        assert_eq!(&thunk.bytes[thunk.bytes.len() - 4..], &key);
        // Should end with the key bytes preceded by a RET (0xC3).
        assert_eq!(thunk.bytes[thunk.bytes.len() - 4 - 1], 0xC3);
        assert_eq!(thunk.fixups.len(), 1);
    }

    /// Thunk contains the string vaddr encoded as a little-endian u64.
    #[test]
    fn test_thunk_contains_vaddr() {
        let vaddr: u64 = 0x0040_2000;
        let key = vec![0x42; 8];
        let thunk = generate_thunk(vaddr, 8, &key);

        let vaddr_bytes = vaddr.to_le_bytes();
        // The vaddr should appear at least once (in the mov rsi, imm64).
        assert!(thunk
            .windows(8)
            .any(|w| w == vaddr_bytes));
    }

    /// Pass metadata is correct.
    #[test]
    fn test_pass_info() {
        let pass = StringEncryptionPass::new();
        let info = pass.info();
        assert_eq!(info.name, "string_encryption");
        assert!(!info.description.is_empty());
    }

    /// Pass runs without error on a module with no strings.
    #[test]
    fn test_pass_on_empty_module() {
        let pass = StringEncryptionPass::with_seed(42);
        let mut module = Module::new("empty".into(), Architecture::X86_64, BinaryFormat::Elf);
        assert!(pass.run(&mut module).is_ok());
        // No thunk functions should have been added.
        assert!(module.functions.is_empty());
    }

    /// Pass runs without error on a module with functions but no string refs.
    #[test]
    fn test_pass_on_module_no_strings() {
        let pass = StringEncryptionPass::with_seed(42);
        let mut module = Module::new("nostrings".into(), Architecture::X86_64, BinaryFormat::Elf);

        let mut func = Function::new("main".into(), 0x401000, 10);
        let block = BasicBlock {
            id: BlockId(0),
            start_addr: 0x401000,
            end_addr: 0x401005,
            instructions: vec![Instruction {
                address: 0x401000,
                original_bytes: vec![0x90],
                opcode: Opcode::Nop,
                operands: vec![],
                operand_size: OperandSize::Byte,
                data_refs: vec![],
                meta: InstructionMeta::default(),
            }],
            terminator: Terminator::Return,
        };
        func.blocks.push(block);
        module.functions.push(func);

        assert!(pass.run(&mut module).is_ok());
        // Only the original function should exist.
        assert_eq!(module.functions.len(), 1);
    }

    /// Full scenario: create a module with a known string DataRef, run the pass,
    /// verify the data section bytes have been encrypted (changed).
    #[test]
    fn test_string_detection_and_encryption() {
        let pass = StringEncryptionPass::with_seed(12345);

        let string_data = b"Hello World\0";
        let string_vaddr: u64 = 0x600000;
        let string_len = string_data.len();

        let mut module = Module::new("test".into(), Architecture::X86_64, BinaryFormat::Elf);

        // Add a data section containing the string.
        module.data_sections.push(DataSection {
            name: ".rodata".into(),
            vaddr: string_vaddr,
            file_offset: 0x2000,
            data: string_data.to_vec(),
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: false,
            },
            relocations: vec![],
        });

        // Add a function with a LEA instruction referencing the string.
        let lea_instr = Instruction {
            address: 0x401000,
            original_bytes: vec![0x48, 0x8D, 0x35, 0x00, 0x00, 0x20, 0x00], // lea rsi, [rip+...]
            opcode: Opcode::Lea,
            operands: vec![],
            operand_size: OperandSize::Qword,
            data_refs: vec![DataRef {
                vaddr: string_vaddr,
                size: string_len,
                data: string_data.to_vec(),
                is_string: true,
            }],
            meta: InstructionMeta::default(),
        };

        let block = BasicBlock {
            id: BlockId(0),
            start_addr: 0x401000,
            end_addr: 0x401007,
            instructions: vec![lea_instr],
            terminator: Terminator::Return,
        };

        let mut func = Function::new("main".into(), 0x401000, 7);
        func.blocks.push(block);
        module.functions.push(func);

        // Run the pass.
        pass.run(&mut module).unwrap();

        // Verify: the data section bytes should no longer match the original.
        let section = module.data_section_for_addr(string_vaddr).unwrap();
        assert_ne!(
            &section.data[..string_len],
            string_data,
            "String data should be encrypted"
        );

        // Verify: a __phantom_init function was added.
        assert!(
            module.function("__phantom_init").is_some(),
            "Init function should exist"
        );

        // Verify: the original LEA instruction is NOT modified (entry-point
        // redirection is used instead of LEA patching).
        let main_fn = module.function("main").unwrap();
        let first_instr = &main_fn.blocks[0].instructions[0];
        assert!(
            matches!(first_instr.opcode, Opcode::Lea),
            "LEA should remain unmodified"
        );
        assert!(!first_instr.meta.modified);
    }

    /// Verify that with a seed, the pass is deterministic.
    #[test]
    fn test_deterministic_with_seed() {
        let string_data = b"Deterministic\0";
        let string_vaddr: u64 = 0x600000;

        let make_module = || {
            let mut m = Module::new("det".into(), Architecture::X86_64, BinaryFormat::Elf);
            m.data_sections.push(DataSection {
                name: ".rodata".into(),
                vaddr: string_vaddr,
                file_offset: 0x2000,
                data: string_data.to_vec(),
                permissions: SectionPermissions {
                    read: true,
                    write: false,
                    execute: false,
                },
                relocations: vec![],
            });
            let instr = Instruction {
                address: 0x401000,
                original_bytes: vec![0x48, 0x8D, 0x35, 0, 0, 0, 0],
                opcode: Opcode::Lea,
                operands: vec![],
                operand_size: OperandSize::Qword,
                data_refs: vec![DataRef {
                    vaddr: string_vaddr,
                    size: string_data.len(),
                    data: string_data.to_vec(),
                    is_string: true,
                }],
                meta: InstructionMeta::default(),
            };
            let block = BasicBlock {
                id: BlockId(0),
                start_addr: 0x401000,
                end_addr: 0x401007,
                instructions: vec![instr],
                terminator: Terminator::Return,
            };
            let mut func = Function::new("main".into(), 0x401000, 7);
            func.blocks.push(block);
            m.functions.push(func);
            m
        };

        let mut m1 = make_module();
        let mut m2 = make_module();

        StringEncryptionPass::with_seed(9999).run(&mut m1).unwrap();
        StringEncryptionPass::with_seed(9999).run(&mut m2).unwrap();

        assert_eq!(
            m1.data_sections[0].data,
            m2.data_sections[0].data,
            "Same seed should produce identical ciphertext"
        );
    }

    /// Verify that multiple references to the same string only encrypt once.
    #[test]
    fn test_dedup_same_vaddr() {
        let pass = StringEncryptionPass::with_seed(42);

        let string_data = b"shared\0";
        let string_vaddr: u64 = 0x600000;

        let mut module = Module::new("dedup".into(), Architecture::X86_64, BinaryFormat::Elf);
        module.data_sections.push(DataSection {
            name: ".rodata".into(),
            vaddr: string_vaddr,
            file_offset: 0x2000,
            data: string_data.to_vec(),
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: false,
            },
            relocations: vec![],
        });

        let make_lea = |addr| Instruction {
            address: addr,
            original_bytes: vec![0x48, 0x8D, 0x35, 0, 0, 0, 0],
            opcode: Opcode::Lea,
            operands: vec![],
            operand_size: OperandSize::Qword,
            data_refs: vec![DataRef {
                vaddr: string_vaddr,
                size: string_data.len(),
                data: string_data.to_vec(),
                is_string: true,
            }],
            meta: InstructionMeta::default(),
        };

        let block = BasicBlock {
            id: BlockId(0),
            start_addr: 0x401000,
            end_addr: 0x40100E,
            instructions: vec![make_lea(0x401000), make_lea(0x401007)],
            terminator: Terminator::Return,
        };

        let mut func = Function::new("main".into(), 0x401000, 14);
        func.blocks.push(block);
        module.functions.push(func);

        pass.run(&mut module).unwrap();

        // Should have __phantom_init + original function (no per-string thunks).
        assert!(
            module.function("__phantom_init").is_some(),
            "Init function should exist"
        );
        // There should be exactly 2 functions: main + __phantom_init.
        assert_eq!(module.functions.len(), 2);

        // LEA instructions should remain unmodified.
        let main_fn = module.function("main").unwrap();
        for instr in &main_fn.blocks[0].instructions {
            assert!(
                matches!(instr.opcode, Opcode::Lea),
                "LEA instructions should remain unmodified"
            );
        }
    }

    /// XOR encryption round-trip via data section (in-place).
    #[test]
    fn test_xor_in_place_roundtrip() {
        let original = b"roundtrip test\0".to_vec();
        let key: Vec<u8> = vec![0xAB; original.len()];

        let mut data = original.clone();
        xor_in_place(&mut data, &key);
        assert_ne!(data, original);

        xor_in_place(&mut data, &key);
        assert_eq!(data, original);
    }

    /// Thunk for a single-byte string is generated correctly.
    #[test]
    fn test_thunk_single_byte() {
        let key = vec![0xFF];
        let thunk = generate_thunk(0x1000, 1, &key);
        assert!(!thunk.is_empty());
        // Key is 1 byte at the end.
        assert_eq!(thunk[thunk.len() - 1], 0xFF);
        // RET before key.
        assert_eq!(thunk[thunk.len() - 2], 0xC3);
    }

    #[test]
    fn test_init_function_carries_fixups() {
        let thunk = generate_thunk_with_fixups(0x401000, 4, &[1, 2, 3, 4]);
        let init = generate_init_function_with_fixups(&[thunk], 0x402000);

        assert!(!init.bytes.is_empty());
        assert_eq!(init.fixups.len(), 2);
    }
}
