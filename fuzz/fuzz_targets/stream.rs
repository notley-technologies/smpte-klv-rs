//! Raw bytes through the streaming decoder, split two ways; the results
//! must match.
#![no_main]

#[path = "../../tests/harness/mod.rs"]
mod harness;

libfuzzer_sys::fuzz_target!(|data: &[u8]| harness::stream(data));
