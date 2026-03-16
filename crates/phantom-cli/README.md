# phantom-cli

Command-line interface for the Phantom code protector.

## Commands

### `protect`

Full pipeline: lift binary, apply transform passes, emit protected binary.

```sh
phantom-cli protect -i <input> -o <output> [-p <pass1,pass2,...>]
```

### `info`

Display binary metadata (architecture, format, entry point, sections, function count).

```sh
phantom-cli info <binary>
```

### `inspect`

Dump the Phantom IR for a binary. Useful for understanding what the lifter produces.

```sh
phantom-cli inspect <binary> [--function <name>] [--json]
```

## Logging

Set `RUST_LOG` for debug output:

```sh
RUST_LOG=debug phantom-cli protect -i input -o output -p string_encryption
```
