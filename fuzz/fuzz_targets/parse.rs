//! Raw bytes as triplets, and as the value of every kind of group.
#![no_main]

#[path = "../../tests/harness/mod.rs"]
mod harness;

libfuzzer_sys::fuzz_target!(|data: &[u8]| harness::parse(data));
