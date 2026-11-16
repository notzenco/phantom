# phantom-frontends

Binary lifters that parse executable formats and produce Phantom IR (PhIR).

## Supported Formats

| Format | Frontend | Status |
|--------|----------|--------|
| ELF (x86-64) | `ElfFrontend` | Implemented |
| PE32+ executables (x86-64) | `PeFrontend` | Implemented |
| Mach-O | — | Planned (Phase 3) |

Both frontends share the x86 lifter in `x86.rs` (basic blocks, instruction translation, data-reference detection) and also record strings reached through pointers stored in data (`Module::data_refs`).

## PE Lifter

`PeFrontend` takes function bounds from the x64 exception directory (`.pdata`), names from exports and COFF symbols, and string candidates from RIP-relative operands and base-relocated pointers. Data the Windows loader reads before the entry point is excluded from string encryption: the data directories, the import names and tables, export tables and names, and TLS template, index and callback array they point to, and every relocated slot. Load-configuration tables and delay-load data are not walked. Strings referenced directly by TLS callbacks, which run before the entry point, are left unencrypted with a warning. DLLs are rejected.

## ELF Lifter

The `ElfFrontend` performs:

1. **ELF parsing** via goblin; only 64-bit x86-64 ELF is accepted
2. **Data section extraction** (.rodata, .data, .bss, .data.rel.ro)
3. **Function lifting** from symbol table (STT_FUNC symbols)
4. **Basic block discovery** using leader-based splitting (branch targets, fall-throughs)
5. **Instruction translation** from iced-x86 to PhIR (opcode mapping, operand translation)
6. **Data reference detection** for RIP-relative operands pointing into data sections
7. **Loader exclusions**: strings overlapping a relocated slot (dynamic, allocated and packed `DT_RELR` relocations) or a `PT_GNU_RELRO` segment are not encrypted, nor are strings referenced directly by `DT_PREINIT_ARRAY` routines or IFUNC resolvers of a dynamically linked executable

Functions come from `.symtab`, so a stripped binary lifts no code and only strings reached through pointers in data are found; the lifter warns when the symbol table is missing.

## Usage

```rust
use phantom_frontends::{detect_frontend, Frontend};

let data = std::fs::read("binary.elf")?;
let frontend = detect_frontend(&data).expect("unsupported format");
let module = frontend.lift(&data)?;
```
