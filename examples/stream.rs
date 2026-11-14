//! Decode KLV from standard input as it arrives, in whatever chunks the
//! pipe delivers, printing one line per triplet.
//!
//!     cat capture.klv | cargo run --example stream
//!     cargo run --example stream -- --key 06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00 < capture.klv
//!
//! `--key` keeps only triplets with that key (ignoring the version byte);
//! the others are skipped without being buffered.

use smpte_klv::{Decoder, UniversalLabel};
use std::io::Read;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut decoder = Decoder::new();
    if let Some(i) = args.iter().position(|a| a == "--key") {
        let wanted: UniversalLabel = match args.get(i + 1).map(|s| s.parse()) {
            Some(Ok(k)) => k,
            _ => {
                eprintln!("--key needs a universal label, such as 06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00");
                std::process::exit(2);
            }
        };
        decoder.set_filter(move |h| h.key().eq_ignoring_version(&wanted));
    }

    let mut stdin = std::io::stdin().lock();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = stdin.read(&mut buf)?;
        if n == 0 {
            break;
        }
        decoder.push(&buf[..n]);
        for frame in decoder.frames() {
            println!("@{:<10} {} {} bytes", frame.offset(), frame.key(), frame.value().len());
        }
    }
    decoder.finish();
    eprintln!("{:#?}", decoder.stats());
    Ok(())
}
