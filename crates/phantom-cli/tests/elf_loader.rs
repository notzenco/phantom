//! Integration tests for ELF inputs whose data the dynamic loader touches before
//! the protected entry point runs.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{temp_path, BIN};

/// Compile `source` with `cc`, protect it with the strings profile and run it.
struct Protected {
    input: PathBuf,
    output: PathBuf,
    protect: Output,
}

impl Protected {
    fn build(name: &str, source: &str, flags: &[&str]) -> Self {
        let src = temp_path(name).with_extension("c");
        let input = temp_path(name);
        let output = temp_path(&format!("{name}-protected"));
        std::fs::write(&src, source).expect("write source");

        let compile = Command::new("cc")
            .args(flags)
            .args(["-O2", "-o"])
            .arg(&input)
            .arg(&src)
            .output()
            .expect("run cc");
        assert!(
            compile.status.success(),
            "compile failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let _ = std::fs::remove_file(src);

        let protect = Command::new(BIN)
            .args(["protect", "--profile", "strings", "-i"])
            .arg(&input)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("run phantom-cli protect");
        Self {
            input,
            output,
            protect,
        }
    }

    fn run(&self) -> Output {
        assert!(
            self.protect.status.success(),
            "protect failed: {}",
            String::from_utf8_lossy(&self.protect.stderr)
        );
        common::run_with_timeout(&mut Command::new(&self.output))
    }
}

impl Drop for Protected {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.input);
        let _ = std::fs::remove_file(&self.output);
    }
}

fn assert_runs(output: &Output, stdout: &str) {
    assert!(
        output.status.success(),
        "protected binary failed ({:?}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), stdout);
}

/// A string inside a struct that also holds a pointer lands in `.data.rel.ro`,
/// which the loader makes read-only before entry, so it cannot be decrypted in
/// place and must be left alone.
#[test]
fn string_in_relro_is_left_alone() {
    let source = r#"
#include <stdio.h>
struct entry { const char *next; char name[16]; };
static const struct entry table = { "tail", "relro-probe" };
int main(void) { puts(table.name); puts(table.next); return 0; }
"#;
    let bin = Protected::build("relro", source, &["-fPIE", "-pie"]);
    assert_runs(&bin.run(), "relro-probe\ntail\n");
}

/// `DT_PREINIT_ARRAY` routines run inside the dynamic loader before the entry
/// point, so strings they use must still be plaintext when they run.
#[test]
fn strings_used_before_entry_stay_readable() {
    let source = r#"
#include <stdio.h>
#include <unistd.h>
static void early(int argc, char **argv, char **envp) {
    static const char msg[] = "preinit-probe\n";
    (void)argc; (void)argv; (void)envp;
    write(1, msg, sizeof msg - 1);
}
__attribute__((section(".preinit_array"), used))
static void (*run_early)(int, char **, char **) = early;
int main(void) { puts("main-probe"); return 0; }
"#;
    let bin = Protected::build("preinit", source, &["-fPIE", "-pie"]);
    assert_runs(&bin.run(), "preinit-probe\nmain-probe\n");
    let protected = std::fs::read(&bin.output).expect("read protected binary");
    assert!(
        !protected.windows(10).any(|w| w == b"main-probe"),
        "strings used only after entry should still be encrypted"
    );
}

fn compile(name: &str, source: &str) -> PathBuf {
    let src = temp_path(name).with_extension("c");
    let binary = temp_path(name);
    std::fs::write(&src, source).expect("write source");
    let compile = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&binary)
        .arg(&src)
        .output()
        .expect("run cc");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let _ = std::fs::remove_file(src);
    binary
}

fn protect_with(input: &Path, output: &Path, extra: &[&str]) -> Output {
    Command::new(BIN)
        .args(["protect", "--profile", "strings", "-i"])
        .arg(input)
        .arg("-o")
        .arg(output)
        .args(extra)
        .output()
        .expect("run phantom-cli protect")
}

#[test]
fn seeded_protection_is_reproducible_and_summarised() {
    let input = compile(
        "seeded",
        "#include <stdio.h>\nint main(void) { puts(\"seeded-probe\"); return 0; }\n",
    );
    let (first, second) = (temp_path("seeded-a"), temp_path("seeded-b"));
    let run = protect_with(&input, &first, &["--seed", "7"]);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(protect_with(&input, &second, &["--seed", "7"])
        .status
        .success());

    assert_eq!(
        std::fs::read(&first).unwrap(),
        std::fs::read(&second).unwrap()
    );
    let summary = String::from_utf8_lossy(&run.stdout);
    for line in [
        "functions lifted:",
        "passes: string_encryption",
        "data encrypted:",
        "size:",
    ] {
        assert!(
            summary.contains(line),
            "missing {line:?} in summary:\n{summary}"
        );
    }
    for path in [input, first, second] {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn protection_that_changes_nothing_is_an_error() {
    let input = compile("no-strings", "int main(void) { return 0; }\n");
    let output = temp_path("no-strings-out");
    let run = protect_with(&input, &output, &[]);
    assert_eq!(
        run.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&run.stdout)
    );
    assert!(String::from_utf8_lossy(&run.stderr).contains("found nothing to protect"));
    assert!(!output.exists(), "no output should be written");
    let _ = std::fs::remove_file(input);
}
