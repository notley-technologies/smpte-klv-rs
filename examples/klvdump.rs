//! Print the structure of a KLV file: every triplet, and the items of every
//! set and pack inside it.
//!
//!     cargo run --example klvdump -- capture.klv
//!     cargo run --example klvdump -- capture.klv --lenient --values
//!
//! Damaged input is skipped by resynchronising on the next SMPTE key, as
//! the streaming decoder does.

use smpte_klv::{Config, DecodeOptions, Decoder, Group, Triplet};
use std::process::ExitCode;

struct Opts {
    values: bool,
}

fn hex(bytes: &[u8], max: usize) -> String {
    let mut s: String = bytes.iter().take(max).map(|b| format!("{b:02X} ")).collect();
    if bytes.len() > max {
        s.push_str("...");
    }
    s.trim_end().to_string()
}

fn value(o: &Opts, v: &[u8]) -> String {
    if o.values {
        format!(" = {}", hex(v, 24))
    } else {
        String::new()
    }
}

/// Print a group's items, descending into nested Universal and Global Set
/// items (whose keys say they are groups) up to a fixed depth.
fn group(o: &Opts, g: &Group, depth: usize) {
    let pad = "  ".repeat(depth + 1);
    println!("{pad}{:?}", g.coding());
    let nested = |t: Option<Group>| {
        if let Some(inner) = t.filter(|_| depth < 8) {
            group(o, &inner, depth + 2);
        }
    };
    let report = |e: smpte_klv::Error| println!("{pad}  error: {e}");
    match g {
        Group::Universal(s) => {
            for t in s.iter() {
                match t {
                    Ok(t) => {
                        println!("{pad}  {} len {}{}", t.key(), t.value().len(), value(o, t.value()));
                        nested(t.group());
                    }
                    Err(e) => report(e),
                }
            }
        }
        Group::Global(s) => {
            for i in s.iter() {
                match i {
                    Ok(i) => {
                        println!("{pad}  {} (tag {}) len {}{}", i.key, hex(i.tag, 12), i.value.len(), value(o, i.value));
                        nested(i.group());
                    }
                    Err(e) => report(e),
                }
            }
        }
        Group::Local(s) => {
            for i in s.iter() {
                match i {
                    Ok(i) => println!("{pad}  tag {:>5} len {:>5}{}", i.tag, i.value.len(), value(o, i.value)),
                    Err(e) => report(e),
                }
            }
        }
        Group::VariableLengthPack(p) => {
            for i in p.iter() {
                match i {
                    Ok(i) => println!("{pad}  item {:>3} len {:>5}{}", i.index, i.value.len(), value(o, i.value)),
                    Err(e) => report(e),
                }
            }
        }
        Group::DefinedLengthPack(p) => println!("{pad}  {} bytes{}", p.value().len(), value(o, p.value())),
    }
}

fn triplet(o: &Opts, offset: u64, t: &Triplet) {
    let k = t.key();
    println!("@{offset:<8} {k} {:?} len {}{}", k.category(), t.value().len(), value(o, t.value()));
    if let Some(g) = t.group() {
        group(o, &g, 0);
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: klvdump <file> [--lenient] [--values]");
        return ExitCode::from(2);
    };
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let o = Opts { values: args.iter().any(|a| a == "--values") };
    let mut config = Config::default();
    if args.iter().any(|a| a == "--lenient") {
        config.options = DecodeOptions::lenient();
    }
    config.max_value_len = data.len();
    let mut decoder = Decoder::with_config(config);
    for chunk in data.chunks(64 * 1024) {
        decoder.push(chunk);
        for f in decoder.frames() {
            triplet(&o, f.offset(), &f.triplet());
        }
    }
    decoder.finish();
    let s = decoder.stats();
    eprintln!(
        "{} triplets, {} bytes skipped ({} resyncs, {} malformed, {} truncated)",
        s.frames, s.bytes_skipped, s.resyncs, s.malformed, s.truncated_at_finish
    );
    ExitCode::SUCCESS
}
