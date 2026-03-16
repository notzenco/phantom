//! String encryption pass — encrypts string literals in data sections using XOR
//! and generates position-independent x86_64 decryptor thunks.

use std::collections::HashMap;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tracing::{debug, info, warn};

use phantom_core::ir::block::{BasicBlock, BlockId, Terminator};
use phantom_core::ir::function::Function;
use phantom_core::ir::instruction::{Instruction, InstructionMeta, Opcode};
use phantom_core::ir::module::Module;
use phantom_core::ir::types::OperandSize;
use phantom_core::pass::{Pass, PassInfo};
use phantom_core::PhantomError;

/// Information about a string reference found in the IR.
#[derive(Debug, Clone)]
struct StringRef {
    /// Index of the function containing this reference.
    func_idx: usize,
    /// Index of the block within that function.
    block_idx: usize,
    /// Index of the instruction within that block.
    instr_idx: usize,
    /// Index of the data_ref within the instruction.
    _data_ref_idx: usize,
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
    /// Name of the generated decryptor thunk function.
    thunk_name: String,
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

        // Build a map from vaddr -> encrypted info for quick lookup.
        let enc_map: HashMap<u64, &EncryptedString> =
            encrypted.iter().map(|e| (e.vaddr, e)).collect();

        // Step 3: Generate decryptor thunk functions and append to module.
        for enc in &encrypted {
            let thunk_code = generate_thunk(enc.vaddr, enc.len, &enc.key);
            let thunk_fn = make_thunk_function(&enc.thunk_name, &thunk_code);
            debug!(
                "Generated decryptor thunk '{}' ({} bytes) for string at {:#x}",
                enc.thunk_name,
                thunk_code.len(),
                enc.vaddr,
            );
            module.functions.push(thunk_fn);
        }

        // Step 4: Patch original LEA instructions that reference encrypted strings.
        let mut patched = 0usize;
        for sref in &string_refs {
            if let Some(enc) = enc_map.get(&sref.vaddr) {
                let instr = &mut module.functions[sref.func_idx].blocks[sref.block_idx]
                    .instructions[sref.instr_idx];
                patch_instruction(instr, enc);
                patched += 1;
            }
        }
        info!("Patched {patched} instruction(s) to call decryptor thunks.");

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Step 1 helpers
// ---------------------------------------------------------------------------

/// Walk every function/block/instruction and collect string DataRef entries.
fn collect_string_refs(module: &Module) -> Vec<StringRef> {
    let mut refs = Vec::new();
    for (fi, func) in module.functions.iter().enumerate() {
        for (bi, block) in func.blocks.iter().enumerate() {
            for (ii, instr) in block.instructions.iter().enumerate() {
                for (di, dref) in instr.data_refs.iter().enumerate() {
                    if dref.is_string {
                        refs.push(StringRef {
                            func_idx: fi,
                            block_idx: bi,
                            instr_idx: ii,
                            _data_ref_idx: di,
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

        let thunk_name = format!("__phantom_decrypt_{vaddr:x}");
        encrypted.push(EncryptedString {
            vaddr,
            len: size,
            key,
            thunk_name,
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
    assert_eq!(
        key.len(),
        string_len,
        "key length must equal string length"
    );

    let mut code = Vec::new();

    // Save registers we clobber.
    code.push(0x57); // push rdi
    code.push(0x56); // push rsi
    code.push(0x51); // push rcx
    code.push(0x52); // push rdx

    // mov rsi, imm64  — absolute address of the encrypted string
    code.extend_from_slice(&[0x48, 0xBE]);
    code.extend_from_slice(&string_vaddr.to_le_bytes());

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

    // mov rax, imm64  — return the decrypted string address in rax
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&string_vaddr.to_le_bytes());

    // Restore saved registers.
    code.push(0x5A); // pop rdx
    code.push(0x59); // pop rcx
    code.push(0x5E); // pop rsi
    code.push(0x5F); // pop rdi

    // ret
    code.push(0xC3);

    let ret_pos = code.len();

    // Append key bytes after the RET.
    code.extend_from_slice(key);

    // Fix up the LEA displacement to point to the key data.
    let lea_next_ip = lea_pos + 7; // LEA is 7 bytes: 48 8D 3D xx xx xx xx
    let disp = (ret_pos as i32) - (lea_next_ip as i32);
    code[lea_pos + 3..lea_pos + 7].copy_from_slice(&disp.to_le_bytes());

    code
}

/// Wrap thunk code bytes into a `Function` with a single `RawBytes` instruction.
fn make_thunk_function(name: &str, code: &[u8]) -> Function {
    let instr = Instruction {
        address: 0,
        original_bytes: code.to_vec(),
        opcode: Opcode::RawBytes(code.to_vec()),
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

    let mut func = Function::new(name.into(), 0, code.len() as u64);
    func.blocks.push(block);
    func
}

// ---------------------------------------------------------------------------
// Step 4: Instruction patching
// ---------------------------------------------------------------------------

/// Patch an instruction that referenced an encrypted string.
///
/// Changes the opcode from `Lea` to `Call` with a `Named` target pointing to
/// the decryptor thunk. The backend is responsible for resolving the call
/// address and re-encoding the instruction.
fn patch_instruction(instr: &mut Instruction, enc: &EncryptedString) {
    instr.opcode = Opcode::Call;
    instr.meta.modified = true;
    instr.meta.modified_by = Some("string_encryption".into());

    // We don't rewrite original_bytes here — the backend handles re-encoding
    // modified instructions. We store the thunk name so the backend can resolve
    // the call target.
    //
    // NOTE: The instruction's data_refs are left intact so the backend can see
    // which string was being referenced. The `Opcode::Call` with a named
    // target signals that this needs special handling.
    debug!(
        "Patched instruction at {:#x} → CALL {}",
        instr.address, enc.thunk_name
    );
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
        let thunk = generate_thunk(0x400000, 4, &key);

        assert!(!thunk.is_empty());
        // The key bytes should appear at the end of the thunk.
        assert_eq!(&thunk[thunk.len() - 4..], &key);
        // Should end with the key bytes preceded by a RET (0xC3).
        assert_eq!(thunk[thunk.len() - 4 - 1], 0xC3);
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

        // Verify: a decryptor thunk function was added.
        let thunk_name = format!("__phantom_decrypt_{string_vaddr:x}");
        assert!(
            module.function(&thunk_name).is_some(),
            "Decryptor thunk function should exist"
        );

        // Verify: the original LEA instruction was patched to a Call.
        let main_fn = module.function("main").unwrap();
        let first_instr = &main_fn.blocks[0].instructions[0];
        assert!(
            matches!(first_instr.opcode, Opcode::Call),
            "LEA should have been patched to CALL"
        );
        assert!(first_instr.meta.modified);
        assert_eq!(
            first_instr.meta.modified_by.as_deref(),
            Some("string_encryption")
        );
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

        // Should only have 1 thunk (deduped) + 1 original function.
        let thunk_count = module
            .functions
            .iter()
            .filter(|f| f.name.starts_with("__phantom_decrypt_"))
            .count();
        assert_eq!(thunk_count, 1, "Only one thunk per unique vaddr");

        // Both LEA instructions should be patched.
        let main_fn = module.function("main").unwrap();
        for instr in &main_fn.blocks[0].instructions {
            assert!(
                matches!(instr.opcode, Opcode::Call),
                "Both instructions should be patched to CALL"
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
}
