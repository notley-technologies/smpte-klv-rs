//! Fuzzing on the stable toolchain. Replays the saved inputs in
//! `tests/fuzz_regressions/<target>/`, then runs each harness on randomly
//! mutated inputs. Coverage-guided fuzzing of the same harnesses is in
//! `fuzz/` (cargo-fuzz).
//!
//! Longer runs:
//!
//!     SMPTE_KLV_FUZZ_ITERATIONS=200000 cargo test --release --test fuzz
//!
//! `SMPTE_KLV_FUZZ_SEED=<n>` picks a different random sequence. A failing
//! input is saved under `target/fuzz-failures/`; once fixed, copy it into
//! `tests/fuzz_regressions/<target>/` so it is replayed from then on.
// The tests use the encoders and the stream decoder.
#![cfg(feature = "alloc")]
mod harness;

use harness::common::annex;
use harness::common::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

fn iterations(default: usize) -> usize {
    std::env::var("SMPTE_KLV_FUZZ_ITERATIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn seed() -> u64 {
    std::env::var("SMPTE_KLV_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5EED_CAFE)
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Saved inputs for `target`, in name order.
fn regressions(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let dir = root().join("tests/fuzz_regressions").join(target);
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries.map(|e| e.unwrap().path()).filter(|p| p.is_file()).collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();
    files.into_iter().map(|p| (p.clone(), std::fs::read(&p).unwrap())).collect()
}

/// A few byte-level edits, the kind a mutation fuzzer makes. The
/// replacement bytes favour values with meaning in KLV: the key prefix,
/// BER length forms, the indefinite and reserved lengths, OID continuation.
fn mutate(rng: &mut Rng, v: &mut Vec<u8>) {
    const INTERESTING: [u8; 12] = [0x00, 0xFF, 0x80, 0x81, 0x82, 0x88, 0x7F, 0x06, 0x0E, 0x2B, 0x34, 0x01];
    for _ in 0..1 + rng.below(8) {
        let len = v.len();
        match rng.below(9) {
            0 if len > 0 => v[rng.below(len)] ^= 1 << rng.below(8),
            1 if len > 0 => v[rng.below(len)] = INTERESTING[rng.below(INTERESTING.len())],
            2 => {
                let at = rng.below(len + 1);
                let n = 1 + rng.below(16);
                let junk = rng.bytes(n);
                v.splice(at..at, junk);
            }
            3 if len > 0 => {
                let at = rng.below(len);
                let n = 1 + rng.below((len - at).min(64));
                v.drain(at..at + n);
            }
            4 if len > 1 => {
                let from = rng.below(len);
                let n = 1 + rng.below((len - from).min(200));
                let at = rng.below(len + 1);
                let part = v[from..from + n].to_vec();
                v.splice(at..at, part);
            }
            5 => {
                let at = rng.below(len + 1);
                v.splice(at..at, smpte_klv::UniversalLabel::PREFIX);
            }
            6 if len > 0 => v.truncate(rng.below(len)),
            7 => {
                let n = 1 + rng.below(32);
                let junk = rng.bytes(n);
                v.extend(junk);
            }
            _ => {}
        }
    }
}

fn fuzz(target: &str, harness: fn(&[u8]), seeds: Vec<Vec<u8>>, default_iterations: usize) {
    for (path, data) in regressions(target) {
        if catch_unwind(AssertUnwindSafe(|| harness(&data))).is_err() {
            panic!("{target}: saved input {} fails again", path.display());
        }
    }
    for s in &seeds {
        harness(s);
    }
    let mut rng = Rng::seeded(seed(), target);
    let mut corpus = seeds;
    for i in 0..iterations(default_iterations) {
        let mut input = if rng.below(8) == 0 {
            let n = rng.below(600);
            rng.bytes(n)
        } else {
            corpus[rng.below(corpus.len())].clone()
        };
        mutate(&mut rng, &mut input);
        if catch_unwind(AssertUnwindSafe(|| harness(&input))).is_err() {
            let dir = root().join("target/fuzz-failures");
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join(format!("{target}-{i}.bin"));
            std::fs::write(&path, &input).unwrap();
            panic!("{target}: iteration {i} failed; input saved to {}", path.display());
        }
        // Keep some mutants, so edits stack up over the run.
        if i % 8 == 0 && corpus.len() < 512 {
            corpus.push(input);
        }
    }
}

/// Valid KLV to mutate: every Annex example, each behind a few control
/// bytes, and the lot as one stream.
fn klv_seeds() -> Vec<Vec<u8>> {
    let parts = [
        annex::single_item(),
        annex::universal_set(),
        annex::global_set(),
        annex::global_set_2007(),
        annex::local_set(),
        annex::variable_length_pack(),
        annex::defined_length_pack(),
    ];
    let mut seeds = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        seeds.push([&[i as u8][..], p].concat());
    }
    seeds.push([&[0x00][..], &parts.concat()].concat());
    seeds.push([&[0x00, 0x00][..], &parts.concat()].concat());
    seeds.push([&[0x21, 0x07][..], &parts.concat()].concat());
    seeds
}

fn random_seeds(lens: &[usize]) -> Vec<Vec<u8>> {
    let mut rng = Rng::seeded(seed(), "random seeds");
    lens.iter().map(|&n| rng.bytes(n)).collect()
}

#[test]
fn fuzz_parse() {
    fuzz("parse", harness::parse, klv_seeds(), 1500);
}

#[test]
fn fuzz_stream() {
    fuzz("stream", harness::stream, klv_seeds(), 1500);
}

#[test]
fn fuzz_roundtrip() {
    fuzz("roundtrip", harness::roundtrip, random_seeds(&[16, 64, 256, 1024]), 800);
}

/// The generator is only useful if what it asks for gets encoded. Check
/// that most inputs produce packets with items in them.
#[test]
fn generator_reaches_deep_paths() {
    let mut rng = Rng::seeded(seed(), "generator");
    let (mut built, mut with_items, mut nested, runs) = (0, 0, 0, 300);
    for _ in 0..runs {
        let n = 16 + rng.below(400);
        let data = rng.bytes(n);
        let mut input = harness::Input::new(&data);
        if let Some(p) = harness::build_group(&mut input, 0) {
            built += 1;
            let t = smpte_klv::Triplet::parse(&p).unwrap();
            with_items += usize::from(t.value().len() > 2);
            // A group key inside the value: a nested set or pack.
            nested += usize::from(p.windows(5).skip(17).any(|w| w[..4] == smpte_klv::UniversalLabel::PREFIX && w[4] == 2));
        }
    }
    assert!(built * 10 > runs * 8, "only {built}/{runs} inputs built a group");
    assert!(with_items * 2 > runs, "only {with_items}/{runs} groups had items");
    assert!(nested * 20 > runs, "only {nested}/{runs} groups were nested");
}
