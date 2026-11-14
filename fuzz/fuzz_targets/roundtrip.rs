//! Structure-aware: the input describes groups to encode, which must decode
//! back to the same items.
#![no_main]

#[path = "../../tests/harness/mod.rs"]
mod harness;

libfuzzer_sys::fuzz_target!(|data: &[u8]| harness::roundtrip(data));
