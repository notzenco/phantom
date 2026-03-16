# Phantom

Open-source code protector for security research and education. Phantom combines obfuscation, VM protection, packing/encryption, and anti-analysis techniques under a compiler-style architecture.

> **Disclaimer**: This tool is intended for security research, education, and authorized protection of your own software. Do not use it to tamper with software you do not own or have authorization to modify.

## Architecture

Phantom uses a compiler-style IR pipeline:

```
Frontend (lifter) --> Phantom IR (PhIR) --> Transform Passes --> Backend (emitter)
```

The IR is register-based, designed for compiled binaries (ELF/PE/Mach-O). Transform passes analyze and modify the IR to apply protections, then the backend emits a working protected binary.

```
                    +-------------------+
  ELF binary -----> |  ELF Frontend     | ----> PhIR Module
                    |  (goblin+iced-x86)|       (functions, blocks,
                    +-------------------+        instructions, data)
                                                      |
                                                      v
                                              +----------------+
                                              | Transform Pass |
                                              | (str encrypt)  |
                                              +----------------+
                                                      |
                                                      v
                    +-------------------+        PhIR Module
  Protected ELF <-- |  ELF Backend      | <---- (modified)
                    |  (patch-based)    |
                    +-------------------+
```

## Current Status (Phase 1)

End-to-end pipeline for x86-64 ELF binaries with string encryption:

- **Lift** static ELF binaries to PhIR (intermediate representation)
- **Transform** with string encryption (XOR + runtime decryptor thunks)
- **Emit** working protected ELF binaries

### What works

- Roundtrip: lift an ELF, emit it back, binary runs identically
- String encryption: all string literals encrypted with XOR, decrypted at runtime via entry-point redirection
- IR inspection: dump the intermediate representation for any function
- Binary metadata display

## Installation

Requires Rust 1.75+ (2021 edition).

```sh
git clone https://github.com/notzenco/phantom.git
cd phantom
cargo build --release
```

The binary is at `target/release/phantom-cli`.

## Usage

### Protect a binary

```sh
# Roundtrip (no transforms) -- verifies the pipeline works
phantom-cli protect -i ./my_binary -o ./my_binary_protected

# Apply string encryption
phantom-cli protect -i ./my_binary -o ./my_binary_protected -p string_encryption
```

### Inspect binary metadata

```sh
phantom-cli info ./my_binary
```

Output:
```
Binary: ./my_binary
Architecture: X86_64
Format: Elf
Entry point: 0x402dc0
PIE: false
Functions: 1378
Data sections: 4
```

### Dump IR

```sh
# Dump a specific function's IR
phantom-cli inspect ./my_binary --function main

# Dump as JSON
phantom-cli inspect ./my_binary --function main --json
```

Output:
```
function main @ 0000000000402ee5 (size=26)
  block_0 (0000000000402ee5..0000000000402ef8):
    0000000000402ee5: push v0
    0000000000402ee6: mov v0, v1
    0000000000402ee9: lea v2, [rip+0x47c010]
    0000000000402ef0: mov v3, v2
    0000000000402ef3: call 0x406150
  block_1 (0000000000402ef8..0000000000402eff):
    0000000000402ef8: mov v4, 0x0
    0000000000402efd: pop v0
    0000000000402efe: ret
```

## Project Structure

```
phantom/
├── crates/
│   ├── phantom-core/          # IR definitions, pass trait, pipeline
│   ├── phantom-disasm/        # iced-x86 disassembly/encoding wrapper
│   ├── phantom-frontends/     # Binary lifters (ELF -> PhIR)
│   ├── phantom-backends/      # Binary emitters (PhIR -> ELF)
│   ├── phantom-passes/        # Transform passes (string encryption)
│   └── phantom-cli/           # CLI interface
└── tests/
    ├── fixtures/              # Test binaries
    └── integration/           # End-to-end tests
```

### Crate Dependency Graph

```
phantom-cli
├── phantom-frontends
│   ├── phantom-core
│   └── phantom-disasm
│       └── phantom-core
├── phantom-backends
│   ├── phantom-core
│   └── phantom-disasm
└── phantom-passes
    └── phantom-core
```

## How String Encryption Works

1. **Scan**: Find all RIP-relative references to data sections that look like printable strings
2. **Encrypt**: XOR each string in the data section with a random key
3. **Generate thunks**: Create position-independent x86-64 decryptor functions for each string
4. **Init function**: Generate `__phantom_init` that calls all decryptor thunks, then jumps to the original entry point
5. **Redirect entry**: The backend sets the ELF entry point to `__phantom_init`
6. **Segment setup**: Data segments containing encrypted strings are made writable; new code is loaded via a PT_LOAD segment (replacing a PT_NOTE header)

At runtime: init runs first, decrypts all strings in-place, then transfers control to the original program entry. The program runs normally with decrypted strings.

## Testing

```sh
# Run all tests (68 unit + integration tests)
cargo test --workspace

# Run clippy
cargo clippy --workspace -- -D warnings

# Build test fixtures (requires gcc with static linking)
./tests/fixtures/build_fixtures.sh
```

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| 1 - Foundation | ELF lift/emit, string encryption, CLI | Done |
| 2 - Obfuscation Suite | CFG flattening, opaque predicates, dead code injection, protection profiles | Planned |
| 3 - Cross-Platform + Source | PE/Mach-O support; JS and Python frontends; source-level IR | Planned |
| 4 - VM Virtualizer | Custom bytecode ISA, bytecode compiler, interpreter generator, ISA randomization | Planned |
| 5 - Packing & Anti-Analysis | Section encryption, import hiding, anti-debug, anti-tamper, integrity checks | Planned |
| 6 - GUI | Tauri v2 + Next.js desktop app with profile editor, IR inspector, protection dashboard | Planned |

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| [goblin](https://crates.io/crates/goblin) | ELF/PE/Mach-O parsing |
| [iced-x86](https://crates.io/crates/iced-x86) | x86/x64 disassembly and assembly |
| [thiserror](https://crates.io/crates/thiserror) | Error types |
| [clap](https://crates.io/crates/clap) | CLI argument parsing |
| [tracing](https://crates.io/crates/tracing) | Structured logging |

## License

MIT
