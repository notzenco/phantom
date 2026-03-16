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

- **Lift** static and dynamic ELF binaries to PhIR (intermediate representation)
- **Transform** with string encryption (XOR + runtime decryptor thunks)
- **Emit** working protected ELF binaries

### What works

- Roundtrip: lift an ELF, emit it back, binary runs identically
- String encryption: protected ET_EXEC and ET_DYN/PIE binaries decrypt strings at runtime via entry-point redirection
- Protection profiles: built-in and file-defined ordered pass lists exposed by the CLI
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

# Apply string encryption directly
phantom-cli protect -i ./my_binary -o ./my_binary_protected -p string_encryption

# Apply the built-in strings profile
phantom-cli protect -i ./my_binary -o ./my_binary_protected --profile strings

# Load a custom profile from TOML
phantom-cli protect -i ./my_binary -o ./my_binary_protected --profile research --profile-file ./phantom.toml

# Merge a profile with explicit passes; duplicate pass names are removed
phantom-cli protect -i ./my_binary -o ./my_binary_protected --profile strings -p string_encryption
```

`--profile-file` is only accepted when `--profile` is present. When both `--profile` and `--passes` are provided, Phantom resolves the profile first, appends the explicit passes, then stable-dedupes the final pass list.

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

### List profiles

```sh
# List built-in profiles
phantom-cli profiles

# Load additional profiles from a TOML file
phantom-cli profiles --profile-file ./phantom.toml
```

Example `phantom.toml`:

```toml
[profiles]
research = ["string_encryption"]
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
    ├── fixtures/              # Fixture manifest, demo sources, build/obfuscation scripts
    └── integration/           # Legacy workspace-root integration tests
```

The authoritative runnable integration matrix lives in `crates/phantom-cli/tests`, backed by the manifest-driven fixture corpus in `tests/fixtures`.

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
4. **Carry fixups**: Store backend-patchable fixups for injected code so final addresses can be resolved after layout is known
5. **Init function**: Generate `__phantom_init` that calls all decryptor thunks, then jumps to the original entry point
6. **Redirect entry**: The backend sets the ELF entry point to `__phantom_init`
7. **Segment setup**: Data segments containing encrypted strings are made writable; new code is loaded via a PT_LOAD segment (replacing a PT_NOTE header)

At runtime, init runs first, decrypts all strings in-place, then transfers control to the original program entry. ET_EXEC binaries can use direct absolute targets, while ET_DYN/PIE binaries resolve runtime addresses from load bias plus link-time virtual offsets.

## Fixture Corpus

The repository includes a manifest-driven demo corpus under `tests/fixtures` for exercising protection against small real programs rather than a single hello-world sample.

- `tests/fixtures/manifest.toml` is the source of truth for demos, expected behavior, and plaintext probes
- `tests/fixtures/build_fixtures.py` builds static and dynamic ELF binaries from the corpus
- `tests/fixtures/run_obfuscation_matrix.py` builds, protects, executes, string-scans, and emits a JSON report
- Generated binaries and reports are written to ignored directories under `tests/fixtures/`

See `tests/fixtures/README.md` for the manifest schema and script usage.

## Testing

```sh
# Run all tests
cargo test --workspace

# Run clippy
cargo clippy --workspace -- -D warnings

# Build the manifest-driven fixture corpus (static + dynamic ELF)
./tests/fixtures/build_fixtures.sh

# Run the fixture obfuscation matrix and write a JSON report
python3 ./tests/fixtures/run_obfuscation_matrix.py --mode all
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
