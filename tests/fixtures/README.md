# Fixture Corpus

This directory contains the manifest-driven demo corpus used by Phantom's integration tests and CLI verification scripts.

## Layout

- `manifest.toml`: Source of truth for demos, expected outputs, exit codes, and plaintext probes.
- `src/`: C source files for each demo program.
- `build_fixtures.py`: Builds the demo corpus into `bin/static/` and `bin/dynamic/`.
- `build_fixtures.sh`: Thin compatibility wrapper around the Python builder.
- `run_obfuscation_matrix.py`: Builds, protects, executes, string-scans, and writes a JSON report.
- `bin/`, `protected/`, `reports/`: Generated artifact directories ignored by git.

## Manifest Schema

Each demo is declared as one `[[demo]]` table followed by one or more `[[demo.case]]` tables:

```toml
[[demo]]
name = "banner_messages"
source = "src/banner_messages.c"
string_probes = ["banner:%s|%s|%s"]

[[demo.case]]
name = "default"
args = []
expect_stdout = "banner:alpha|beta|gamma\n"
expect_stderr = ""
expect_exit = 0
```

- `name`: Stable demo identifier used for output paths and reports.
- `source`: Path to the C source, relative to this directory.
- `string_probes`: Plaintext byte sequences that must not appear in the protected binary.
- `case.name`: Stable case identifier.
- `case.args`: Command-line arguments passed when the binary is executed.
- `case.expect_stdout`: Exact expected stdout.
- `case.expect_stderr`: Exact expected stderr.
- `case.expect_exit`: Expected process exit code.

## Build

Build all fixture binaries:

```sh
./tests/fixtures/build_fixtures.sh
```

Build only dynamic binaries:

```sh
python3 tests/fixtures/build_fixtures.py --mode dynamic
```

## Obfuscation Matrix

Run the full matrix with the default `strings` profile:

```sh
python3 tests/fixtures/run_obfuscation_matrix.py --mode all
```

Write the JSON report to a specific path:

```sh
python3 tests/fixtures/run_obfuscation_matrix.py --mode dynamic --json-out /tmp/phantom-matrix.json
```

The report records one entry per demo, case, mode, and stage:

- `build`
- `baseline_run`
- `protect`
- `string_scan`
- `protected_run`

The Rust integration tests in `crates/phantom-cli/tests` consume the same manifest so the fixture corpus stays authoritative.
