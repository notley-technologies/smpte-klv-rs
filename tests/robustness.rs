//! Hostile and damaged input: truncation, corruption, huge lengths, deep
//! nesting. Nothing may panic, allocate by a declared length, or recurse.
// The tests use the encoders and the stream decoder.
#![cfg(feature = "alloc")]

mod common;

use common::annex;
use common::*;
use smpte_klv::*;

fn all_examples() -> Vec<Vec<u8>> {
    vec![
        annex::single_item(),
        annex::universal_set(),
        annex::global_set(),
        annex::global_set_2007(),
        annex::local_set(),
        annex::variable_length_pack(),
        annex::defined_length_pack(),
    ]
}

/// Walk a buffer of triplets and everything inside them, iteratively.
/// Returns the number of items seen and whether any error was reported.
fn walk(buf: &[u8], opts: DecodeOptions) -> (usize, bool) {
    let mut stack: Vec<Group> = Vec::new();
    let (mut items, mut failed) = (0, false);
    for t in Triplets::with_options(buf, opts) {
        match t {
            Ok(t) => stack.extend(t.group()),
            Err(_) => failed = true,
        }
    }
    while let Some(g) = stack.pop() {
        match g {
            Group::Universal(s) => {
                for t in s.iter() {
                    match t {
                        Ok(t) => {
                            items += 1;
                            stack.extend(t.group());
                        }
                        Err(_) => failed = true,
                    }
                }
            }
            Group::Global(s) => {
                for i in s.iter() {
                    match i {
                        Ok(i) => {
                            items += 1;
                            stack.extend(i.group());
                        }
                        Err(_) => failed = true,
                    }
                }
            }
            Group::Local(s) => {
                for i in s.iter() {
                    items += 1;
                    failed |= i.is_err();
                }
            }
            Group::VariableLengthPack(p) => {
                for i in p.iter() {
                    items += 1;
                    failed |= i.is_err();
                }
            }
            Group::DefinedLengthPack(_) => items += 1,
        }
    }
    (items, failed)
}

#[test]
fn every_truncation_is_incomplete() {
    for ex in all_examples() {
        for cut in 0..ex.len() {
            let e = Triplet::parse(&ex[..cut]).unwrap_err();
            assert!(e.is_incomplete(), "cut {cut}: {e}");
            assert!(e.needed().unwrap() > cut);
            assert!(e.needed().unwrap() <= ex.len());
        }
        assert!(Triplet::parse(&ex).is_ok());
    }
}

#[test]
fn truncated_set_values_report_where_they_stop() {
    for ex in all_examples() {
        let t = Triplet::parse(&ex).unwrap();
        let Some(g) = t.group() else { continue };
        for cut in 0..t.value().len() {
            let v = &t.value()[..cut];
            let r = Group::with_coding(t.key(), g.coding(), v, DecodeOptions::default()).validate();
            if let Err(e) = r {
                assert!(e.offset() <= cut, "{e} beyond {cut}");
                if let ErrorKind::UnexpectedEnd { available, .. } = e.kind() {
                    assert_eq!(available, cut);
                }
            }
        }
    }
}

#[test]
fn every_byte_mutation_is_handled() {
    let replacements = [0x00, 0x01, 0x06, 0x7F, 0x80, 0x81, 0x84, 0x88, 0xFE, 0xFF];
    let mut seen_errors = 0;
    for ex in all_examples() {
        for at in 0..ex.len() {
            for &b in &replacements {
                let mut m = ex.clone();
                m[at] = b;
                for opts in [DecodeOptions::strict(), DecodeOptions::lenient()] {
                    let (_, failed) = walk(&m, opts);
                    seen_errors += usize::from(failed);
                }
                let mut d = Decoder::new();
                d.push(&m);
                d.finish();
                let s = d.stats();
                assert_eq!(s.bytes, s.frame_bytes + s.bytes_skipped);
            }
        }
    }
    assert!(seen_errors > 1000, "mutations should be noticed: {seen_errors}");
}

#[test]
fn huge_declared_lengths_are_not_trusted() {
    let key = annex::main_title_key();
    // 2^60-byte value, nothing behind it.
    let mut buf = key.as_bytes().to_vec();
    buf.extend([0x88, 0x10, 0, 0, 0, 0, 0, 0, 0]);
    let e = Triplet::parse(&buf).unwrap_err();
    let total = (1u64 << 60) + 25;
    if let Ok(needed) = usize::try_from(total) {
        assert_eq!(e.kind(), ErrorKind::UnexpectedEnd { needed, available: 25 });
    } else {
        assert_eq!(e.kind(), ErrorKind::LengthOverflow);
    }
    assert_eq!(Header::parse(&buf).unwrap().total_len(), Some(total));

    // The decoder skips it without buffering, then finds the next item.
    let mut stream = buf.clone();
    stream.extend(klv(key, b"after"));
    let mut d = Decoder::new();
    for c in stream.chunks(3) {
        d.push(c);
        assert!(d.buffered() <= 25);
    }
    // "after" is inside the skipped value; nothing is delivered.
    assert_eq!(d.frames().count(), 0);
    assert_eq!(d.stats().oversized, 1);

    // Inside sets, too.
    let set = [0x01, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0xAA];
    let err = LocalSet::new(&set, TagEncoding::U8, LengthEncoding::Ber).iter().next().unwrap().unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::LengthOverflow | ErrorKind::Overrun { .. }), "{err}");
    assert!(!err.is_incomplete(), "nothing inside a set is incomplete");
}

#[test]
fn deep_nesting_does_not_recurse() {
    // 20,000 Universal Sets, each holding the next.
    let set_key = annex::universal_set_key();
    let mut packet = klv(annex::main_title_key(), b"core");
    for _ in 0..20_000 {
        packet = klv(set_key, &packet);
    }
    let mut depth = 0;
    let mut current = Triplet::parse(&packet).unwrap();
    while let Some(Group::Universal(s)) = current.group() {
        current = s.iter().next().unwrap().unwrap();
        depth += 1;
    }
    assert_eq!(depth, 20_000);
    assert_eq!(current.value(), b"core");
    assert_eq!(walk(&packet, DecodeOptions::default()), (20_000, false));
}

#[test]
fn every_item_takes_at_least_one_byte() {
    // Zero-length values: item count is bounded by the set length.
    let set = vec![0x05, 0x00].repeat(1000);
    assert_eq!(LocalSet::new(&set, TagEncoding::U8, LengthEncoding::Ber).iter().count(), 1000);
    let pack = vec![0x00; 1000];
    assert_eq!(VariableLengthPack::new(&pack, LengthEncoding::U8).iter().count(), 1000);
    let pack = vec![0x00; 1000];
    assert_eq!(VariableLengthPack::new(&pack, LengthEncoding::U16).iter().count(), 500);
}

#[test]
fn non_minimal_lengths_decode_like_minimal_ones() {
    let key = annex::local_set_key();
    let mut value = Vec::new();
    for (tag, v) in [(1u8, annex::MAIN_TITLE), (2, annex::VERSION_TITLE)] {
        value.push(tag);
        value.extend([0x84, 0, 0, 0, v.len() as u8]);
        value.extend(v);
    }
    let packet = klv_with(key, &value, BerForm::Long(8));
    let t = Triplet::parse(&packet).unwrap();
    assert_eq!(t.length_bytes().len(), 9);
    let Some(Group::Local(s)) = t.group() else { panic!() };
    let got: Vec<(u64, &[u8])> = s.iter().map(|i| i.unwrap()).map(|i| (i.tag, i.value)).collect();
    assert_eq!(got, [(1, annex::MAIN_TITLE), (2, annex::VERSION_TITLE)]);
}

#[test]
fn random_garbage_never_panics() {
    let mut rng = Rng(0xBAD_5EED);
    for _ in 0..3000 {
        let n = rng.below(300);
        let mut buf = rng.bytes(n);
        if rng.below(2) == 0 && n >= 4 {
            buf[..4].copy_from_slice(&UniversalLabel::PREFIX);
        }
        for opts in [DecodeOptions::strict(), DecodeOptions::lenient()] {
            walk(&buf, opts);
        }
        for &b6 in &[0x01u8, 0x02, 0x0B, 0x53, 0x7B, 0x04, 0x64, 0x05] {
            let key = annex::local_set_key().with_group_coding(GroupCoding::from_registry_designator(b6).unwrap());
            let _ = Group::new(key, &buf, DecodeOptions::default()).unwrap().validate();
        }
    }
}
