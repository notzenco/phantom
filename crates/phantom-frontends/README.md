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

`PeFrontend` takes function bounds from the x64 exception directory (`.pdata`), names from exports and COFF symbols, and string candidates from RIP-relative operands and base-relocated pointers. Anything the Windows loader reads before the entry point (data directories, relocated slots) is excluded from string encryption. DLLs are rejected.

## ELF Lifter

The `ElfFrontend` performs:

1. **ELF parsing** via goblin (architecture detection, metadata extraction)
2. **Data section extraction** (.rodata, .data, .bss, .data.rel.ro)
3. **Function lifting** from symbol table (STT_FUNC symbols)
4. **Basic block discovery** using leader-based splitting (branch targets, fall-throughs)
5. **Instruction translation** from iced-x86 to PhIR (opcode mapping, operand translation)
6. **Data reference detection** for RIP-relative operands pointing into data sections

## Usage

```rust
use phantom_frontends::{detect_frontend, Frontend};

let data = std::fs::read("binary.elf")?;
let frontend = detect_frontend(&data).expect("unsupported format");
let module = frontend.lift(&data)?;
```
