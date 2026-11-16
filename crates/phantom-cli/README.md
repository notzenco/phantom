# phantom-cli

Command-line interface for the Phantom code protector.

## Commands

### `protect`

Full pipeline: lift binary, apply transform passes, emit protected binary. Accepts x86-64 Linux ELF (static or PIE) and Windows PE executables; the format is detected from the file.

```sh
phantom-cli protect -i <input> -o <output> [--profile <name>] [--profile-file <path>] [-p <pass1,pass2,...>] [--seed <n>]
```

`--seed` makes the passes' random choices (such as encryption keys) reproducible. On success `protect` prints a summary:

```text
Protected ./banner_messages -> ./banner_messages_protected
  functions lifted: 2
  passes: string_encryption
  data encrypted: 34 bytes in 1 section(s)
  size: 15976 -> 16840 bytes (+5.4%)
```

(Output for the PIE `banner_messages` fixture.)

If the requested passes change nothing (for example, no eligible strings were found), `protect` fails and writes no output.

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

The authoritative end-to-end integration tests for the CLI live in `crates/phantom-cli/tests` and use the same manifest and fixture builder. They run every target the host can execute (`build_fixtures.py --list`); set `PHANTOM_REQUIRE_TARGETS` to make a missing target fail.

## Logging

Warnings, such as strings deliberately left unencrypted, go to stderr by default. `-v` adds progress information, `-vv` debug output and `-vvv` traces; `RUST_LOG` overrides both:

```sh
phantom-cli -vv protect -i input -o output --profile strings
RUST_LOG=phantom_frontends=debug phantom-cli protect -i input -o output --profile strings
```

`phantom-cli --version` prints the version.
