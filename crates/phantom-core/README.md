# phantom-core

Core IR definitions, pass trait, and pipeline for the Phantom code protector.

## Overview

This crate defines the **Phantom Intermediate Representation (PhIR)** — a register-based IR for representing compiled binary code. All other Phantom crates depend on these types.

## IR Hierarchy

```
Module
├── BinaryMetadata (entry point, program/section headers, PIE flag)
├── DataSection[] (name, vaddr, data bytes, permissions, relocations)
├── Function[]
│   ├── name, address, size, vreg_map
│   └── BasicBlock[]
│       ├── BlockId, start/end addr, Terminator
│       └── Instruction[]
│           ├── address, original_bytes, Opcode, Operand[]
│           ├── DataRef[] (references to data sections)
│           └── InstructionMeta (iced_code, modified flag)
└── raw_binary (original file bytes for patch-based emission)
```

## Key Types

- **`VReg` / `PhysReg`** — Virtual and physical register IDs
- **`Opcode`** — Curated x86-64 instruction set + `RawBytes` catch-all
- **`Operand`** — Register, immediate, memory, or RIP-relative
- **`Terminator`** — Block exit: jump, branch, call, return, etc.
- **`Pass`** trait — Transform passes that mutate a `Module`
- **`Pipeline`** — Ordered execution of passes with tracing

## Usage

```rust
use phantom_core::{Module, Function, Pass, Pipeline, Architecture, BinaryFormat};

// Create a module
let module = Module::new("example".into(), Architecture::X86_64, BinaryFormat::Elf);

// Build a pipeline
let mut pipeline = Pipeline::new();
pipeline.add_pass(my_pass);
pipeline.run(&mut module)?;
```
