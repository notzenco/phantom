# Phantom

[![CI](https://github.com/notzenco/phantom/actions/workflows/ci.yml/badge.svg)](https://github.com/notzenco/phantom/actions/workflows/ci.yml)

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
  ELF / PE  ------> |  Frontend         | ----> PhIR Module
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
  Protected bin <-- |  Backend          | <---- (modified)
                    |  (patch-based)    |
                    +-------------------+
```

## Current Status

End-to-end pipeline for x86-64 binaries with string encryption:

| Target | Lift | Protect | Verified by |
|--------|------|---------|-------------|
| Linux ELF, static (ET_EXEC) | Yes | Yes | Fixture matrix on Linux |
| Linux ELF, PIE (ET_DYN) | Yes | Yes | Fixture matrix on Linux |
| Windows PE32+ executable | Yes | Yes | Fixture matrix under Wine on Linux and natively on Windows |
| Windows DLL | No | No | Rejected: `DllMain` runs once per attach/detach, which would re-encrypt strings |
| macOS Mach-O | No | No | Planned; needs a different design (see below) |
| arm64 (any format) | No | No | Planned |

The `phantom-cli` tool itself builds and runs on Linux, macOS and Windows.

### What works

- Roundtrip: lift a binary, emit it back, binary runs identically
- String encryption: protected static ELF, PIE and PE executables decrypt strings at runtime via entry-point redirection, including strings reached only through pointer tables in data
- Protection profiles: built-in and file-defined ordered pass lists exposed by the CLI
- IR inspection: dump the intermediate representation for any function
- Binary metadata display

## Installation

Requires a current stable Rust toolchain (CI builds with the latest stable).

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
│   ├── phantom-frontends/     # Binary lifters (ELF/PE -> PhIR)
│   ├── phantom-backends/      # Binary emitters (PhIR -> ELF/PE)
│   ├── phantom-passes/        # Transform passes (string encryption)
│   └── phantom-cli/           # CLI interface
└── tests/
    └── fixtures/              # Fixture manifest, demo sources, build/obfuscation scripts
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

1. **Scan**: Find printable strings referenced by RIP-relative instructions or by pointers stored in data (static ELF words, PIE `R_X86_64_RELATIVE` relocations, PE base-relocated slots). On PE, anything the Windows loader reads before the entry point (data directories, relocated slots) is left alone
2. **Encrypt**: XOR each string in the data section with a random key
3. **Generate thunks**: Create position-independent x86-64 decryptor functions for each string
4. **Carry fixups**: Store backend-patchable fixups for injected code so final addresses can be resolved after layout is known
5. **Init function**: Generate `__phantom_init` that calls all decryptor thunks, then jumps to the original entry point
6. **Redirect entry**: The backend points the ELF `e_entry` or PE `AddressOfEntryPoint` at `__phantom_init`
7. **Segment setup**: Segments/sections holding encrypted strings are made writable. ELF gets a new PT_LOAD segment (replacing a PT_NOTE header); PE gets a new `.phantom` section, a recomputed checksum, and loses any Authenticode signature, which protection invalidates

At runtime, init runs first, decrypts all strings in-place, then transfers control to the original program entry. The injected code computes the load bias (runtime address minus link-time address) itself, so the same code works for fixed-address executables, PIE and ASLR-relocated PE images.

### Why not Mach-O yet

In-place decryption needs the string pages to be writable at runtime. On macOS, C string literals live in `__TEXT,__cstring`, inside the code-signed `__TEXT` segment, and the kernel refuses to make it writable: `mprotect` fails, and raising the segment's max protection either still fails (x86-64) or stops the binary from launching (arm64). Mach-O support therefore needs a different design: move encrypted strings into a new writable segment and rewrite their references, then re-sign the binary.

## Results

From the fixture matrix (10 C programs, 13 behaviour cases, each built for every target):

| Target | Cases passing after protection | Probe strings hidden | Size overhead (`banner_messages`) |
|--------|-------------------------------|----------------------|-----------------------------------|
| Linux ELF, static | 13/13 | All | +16.5% |
| Linux ELF, PIE | 13/13 | All | +5.4% |
| Windows PE (Wine and native Windows) | 13/13 | All | +1.4% |

Every probe is checked to be present in the unprotected binary first, so "hidden" cannot pass by the compiler having removed the string. Static binaries carry the most overhead because libc's own strings are encrypted too, each with its own ~90-byte decryptor stub.

## Security Model and Limitations

String encryption raises the cost of casual static analysis: `strings`, grep, and quick looks in a disassembler no longer reveal messages, format strings or lookup tables. It is not a defence against a determined analyst:

- **Eager decryption.** `__phantom_init` decrypts every string before the original entry point runs, so a memory dump taken any time after start-up shows all plaintext.
- **Keys ship with the binary.** Each string is XORed with a random per-string key stored next to its decryptor, so the original bytes can be recovered statically or by emulating the init routine.
- **Writable read-only data.** Sections holding encrypted strings (`.rodata`, `.rdata`) stay writable for the life of the process, which weakens the usual hardening of constant data.
- **Coverage is heuristic.** Only printable ASCII strings reached by a RIP-relative instruction or a pointer stored in data are found. UTF-16 strings (`L"..."`) and strings built at runtime are not, and on PE, functions without unwind info (some MSVC leaf functions) are not lifted.
- **Signatures are lost.** Protected PE files have their Authenticode signature removed and must be re-signed.

Planned mitigations: restore read-only protection after decryption, decrypt on first use instead of at start-up, and replace per-string stubs with one table-driven decryptor to cut the static-binary overhead.

## Fixture Corpus

The repository includes a manifest-driven demo corpus under `tests/fixtures` for exercising protection against small real programs rather than a single hello-world sample.

- `tests/fixtures/manifest.toml` is the source of truth for demos, expected behavior, and plaintext probes
- `tests/fixtures/build_fixtures.py` builds the corpus for every target the host can execute (static ELF, PIE, and PE via MinGW)
- `tests/fixtures/run_obfuscation_matrix.py` builds, protects, executes, string-scans, and emits a JSON report
- Generated binaries and reports are written to ignored directories under `tests/fixtures/`

See `tests/fixtures/README.md` for the manifest schema and script usage.

## Testing

Unit tests run anywhere. The integration matrix (Python 3.11+) compiles the fixture corpus for every target the host can execute, protects it, checks that every probe string is present before protection and absent after, and runs each protected binary against the expected output:

- x86-64 Linux: static ELF and PIE with `gcc`; PE too when `x86_64-w64-mingw32-gcc` and Wine are installed
- x86-64 Windows: PE with MinGW `gcc`
- macOS: no executable targets yet, so the matrix is skipped

Set `PHANTOM_REQUIRE_TARGETS=static,dynamic,pe` to fail instead of skipping a target. CI runs formatting, clippy, and the tests on Linux (with Wine), Windows and macOS.

```sh
# Run all tests
cargo test --workspace

# Run clippy
cargo clippy --workspace -- -D warnings

# Build the fixture corpus for every target this host can execute
./tests/fixtures/build_fixtures.sh

# Run the fixture obfuscation matrix and write a JSON report
python3 ./tests/fixtures/run_obfuscation_matrix.py --mode all
```

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| 1 - Foundation | ELF lift/emit, string encryption, protection profiles, CLI | Done |
| 2 - Obfuscation Suite | CFG flattening, opaque predicates, dead code injection | Planned |
| 3a - Windows | PE32+ lift/emit, cross-platform CI | Done |
| 3b - macOS and arm64 | Mach-O via relocated strings and re-signing; arm64 lifting and codegen | Planned |
| 3c - Source frontends | JS and Python frontends; source-level IR | Planned |
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
