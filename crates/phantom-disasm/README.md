# phantom-disasm

Disassembly and encoding engine wrapping [iced-x86](https://crates.io/crates/iced-x86) for Phantom.

## Overview

Provides `IcedDisassembler` for decoding x86/x64 instructions and `IcedEncoder` for re-encoding them. Used by frontends (to lift binaries) and backends (to emit modified instructions).

## Usage

```rust
use phantom_disasm::{IcedDisassembler, IcedEncoder};

// Decode instructions
let disasm = IcedDisassembler::new(64);
let instructions = disasm.decode_all(&bytes, 0x401000)?;

// Re-encode
let encoder = IcedEncoder::new(64);
let encoded = encoder.encode_instruction(&insn, rip)?;
```

The `DecodedInsn` struct preserves the full iced-x86 `Instruction` for lossless roundtripping.
