# phantom-frontends

Binary lifters that parse executable formats and produce Phantom IR (PhIR).

## Supported Formats

| Format | Frontend | Status |
|--------|----------|--------|
| ELF (x86-64) | `ElfFrontend` | Implemented |
| PE | — | Planned (Phase 3) |
| Mach-O | — | Planned (Phase 3) |

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
