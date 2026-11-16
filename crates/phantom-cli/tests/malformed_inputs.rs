//! Robustness: corrupted headers must produce an error, never a panic.
//!
//! Each fixture binary is mutated deterministically (header bytes and
//! boundary values in header fields) and run through lift, string encryption
//! and emit in-process. Set `PHANTOM_MUTATIONS` to change the number of
//! mutations per binary.

mod common;

use std::panic::{self, AssertUnwindSafe};
use std::sync::Mutex;

use phantom_backends::backend_for;
use phantom_core::pass::Pass;
use phantom_frontends::detect_frontend;
use phantom_passes::StringEncryptionPass;

/// Small deterministic generator so failures name a reproducible case.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const BOUNDARY_VALUES: [u64; 7] = [
    0,
    1,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x7fff_ffff_ffff_ffff,
    u64::MAX,
];

/// Offsets worth corrupting: the file header region plus the ELF section
/// header table, where sizes and offsets that drive slicing live.
fn header_spans(data: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = vec![(0, data.len().min(0x400))];
    if data.starts_with(b"\x7fELF") && data.len() >= 64 {
        let shoff = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
        if shoff < data.len() {
            spans.push((shoff, data.len()));
        }
    }
    spans
}

fn mutate(original: &[u8], rng: &mut XorShift) -> Vec<u8> {
    let mut data = original.to_vec();
    let spans = header_spans(&data);
    for _ in 0..1 + rng.below(3) {
        let (start, end) = spans[rng.below(spans.len())];
        let at = start + rng.below(end - start);
        if rng.below(2) == 0 {
            data[at] = rng.next() as u8;
        } else {
            let width = [2, 4, 8][rng.below(3)];
            let value = BOUNDARY_VALUES[rng.below(BOUNDARY_VALUES.len())].to_le_bytes();
            let end = (at + width).min(data.len());
            data[at..end].copy_from_slice(&value[..end - at]);
        }
    }
    data
}

/// Lift, protect and emit; errors are fine, panics are what this test hunts.
fn process(data: &[u8]) {
    let Some(frontend) = detect_frontend(data) else {
        return;
    };
    let Ok(mut module) = frontend.lift(data) else {
        return;
    };
    let _ = StringEncryptionPass::with_seed(1).run(&mut module);
    if let Some(backend) = backend_for(module.format) {
        let _ = backend.emit(&module);
    }
}

#[test]
fn corrupted_headers_do_not_panic() {
    let mutations: usize = std::env::var("PHANTOM_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150);
    let targets = common::targets();
    if targets.is_empty() {
        eprintln!("SKIPPED: no fixture targets on this host");
        return;
    }
    // The smallest demo keeps each in-process run cheap.
    let demo = common::demos()
        .iter()
        .find(|d| d.name == "banner_messages")
        .expect("banner_messages demo");

    // Record each panic's message and location instead of printing it.
    static LAST_PANIC: Mutex<String> = Mutex::new(String::new());
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|info| {
        *LAST_PANIC.lock().unwrap() = info.to_string()
    }));
    let mut failures = Vec::new();
    for target in targets {
        let original = std::fs::read(common::fixture_binary(demo, target)).expect("read fixture");
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
        for case in 0..mutations {
            let data = mutate(&original, &mut rng);
            if panic::catch_unwind(AssertUnwindSafe(|| process(&data))).is_err() {
                let message = LAST_PANIC.lock().unwrap().clone();
                failures.push(format!("{} case {case}: {message}", target.mode));
            }
        }
    }
    panic::set_hook(default_hook);

    assert!(
        failures.is_empty(),
        "{} mutated input(s) panicked:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
