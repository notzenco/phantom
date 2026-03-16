# phantom-passes

Transform passes for the Phantom code protector.

## Available Passes

| Pass | Description |
|------|-------------|
| `string_encryption` | XOR-encrypts string literals with runtime decryptor thunks |

## String Encryption

Encrypts all detected string literals in data sections using XOR with random keys. Generates position-independent x86-64 decryptor thunks that run at program startup via entry-point redirection.

**Not cryptographically secure** — uses XOR for obfuscation, not encryption. Sufficient to defeat `strings` and basic static analysis.

### How it works

1. Scan instructions for DataRefs marked as strings
2. XOR-encrypt string bytes in-place in data sections
3. Generate per-string decryptor thunks (self-contained x86-64 machine code)
4. Generate `__phantom_init` function that calls all thunks then jumps to original entry
5. Backend redirects entry point to `__phantom_init`

### Deterministic output

Pass `with_seed(u64)` for reproducible builds:

```rust
use phantom_passes::StringEncryptionPass;
let pass = StringEncryptionPass::with_seed(42);
```

## Pass Registry

```rust
use phantom_passes::{get_pass, available_passes};

let pass = get_pass("string_encryption").unwrap();
let names = available_passes(); // ["string_encryption"]
```
