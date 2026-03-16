# phantom-cli

Command-line interface for the Phantom code protector.

## Commands

### `protect`

Full pipeline: lift binary, apply transform passes, emit protected binary.

```sh
phantom-cli protect -i <input> -o <output> [--profile <name>] [--profile-file <path>] [-p <pass1,pass2,...>]
```

Examples:

```sh
phantom-cli protect -i input -o output --profile strings
phantom-cli protect -i input -o output -p string_encryption
phantom-cli protect -i input -o output --profile strings -p string_encryption
```

`--profile-file` is only valid together with `--profile`. When both a profile and explicit passes are provided, Phantom resolves the profile first, appends `--passes`, then stable-dedupes pass names while preserving first occurrence.

Profile file:

```toml
[profiles]
research = ["string_encryption"]
```

Custom profile names may not collide with built-in profile names.

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

### `profiles`

List available built-in profiles, optionally merged with profiles from an explicit TOML file.

```sh
phantom-cli profiles [--profile-file <path>]
```

Output format:

```text
strings [built-in]: string_encryption
research [file ./phantom.toml]: string_encryption
```

## Fixture Matrix

The repository includes a manifest-driven demo corpus under `tests/fixtures`:

```sh
./tests/fixtures/build_fixtures.sh
python3 tests/fixtures/run_obfuscation_matrix.py --mode all
```

The authoritative end-to-end integration tests for the CLI live in `crates/phantom-cli/tests` and use the same manifest and fixture builder.

## Logging

Set `RUST_LOG` for debug output:

```sh
RUST_LOG=debug phantom-cli protect -i input -o output --profile strings
```
