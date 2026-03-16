# phantom-backends

Binary emitters that produce protected executables from Phantom IR.

## Approach

The backend uses **patch-based emission** — it starts from the original binary bytes (`module.raw_binary`) and patches in modifications. This preserves the original linker layout, section alignment, and metadata.

## Emission Pipeline

1. **Patch existing functions** — Re-encode modified instructions, NOP-pad if smaller, error if larger
2. **Patch data sections** — Write modified data (e.g., encrypted strings) back to file offsets
3. **Make segments writable** — Add PF_W to segments containing encrypted data (for runtime decryption)
4. **Append new functions** — Add new code (decryptor thunks) as a new PT_LOAD segment
5. **Redirect entry point** — If `__phantom_init` exists, set it as the ELF entry point

New PT_LOAD segments are added by overwriting a PT_NOTE program header (not needed for execution), avoiding phdr table relocation.

## Usage

```rust
use phantom_backends::{Backend, ElfBackend};

let backend = ElfBackend::new();
let protected_bytes = backend.emit(&module)?;
std::fs::write("protected", &protected_bytes)?;
```
