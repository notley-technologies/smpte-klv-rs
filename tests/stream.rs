//! The streaming decoder on realistic streams: many triplets, damage, and
//! every way of splitting the input.
// The tests use the encoders and the stream decoder.
#![cfg(feature = "alloc")]

mod common;

use common::annex;
use common::*;
use smpte_klv::*;

fn frames(d: &mut Decoder) -> Vec<(u64, Vec<u8>)> {
    d.frames().map(|f| (f.offset(), f.into_bytes())).collect()
}

fn decode(stream: &[u8], cfg: &Config, chunks: &mut dyn FnMut() -> usize) -> (Vec<(u64, Vec<u8>)>, Stats) {
    let mut d = Decoder::with_config(cfg.clone());
    let mut pos = 0;
    while pos < stream.len() {
        let end = (pos + chunks()).min(stream.len());
        d.push(&stream[pos..end]);
        pos = end;
    }
    d.finish();
    (frames(&mut d), d.stats().clone())
}

/// A stream of `n` triplets of varied sizes and length forms, with the
/// expected frames.
fn build(rng: &mut Rng, n: usize, garbage: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut stream = Vec::new();
    let mut expected = Vec::new();
    for i in 0..n {
        if garbage && rng.below(4) == 0 {
            // Bytes with no 0x06 in them cannot be mistaken for a key.
            let n = 1 + rng.below(30);
            let junk: Vec<u8> = rng.bytes(n).into_iter().map(|b| b | 0x80).collect();
            stream.extend(junk);
        }
        let mut key = *annex::main_title_key().as_bytes();
        key[13] = i as u8;
        let len = match rng.below(10) {
            0 => 1000 + rng.below(5000),
            1 => 0,
            _ => rng.below(200),
        };
        let form = if rng.below(3) == 0 { BerForm::Long(1 + rng.below(8) as u8) } else { BerForm::Minimal };
        let form = if len > 255 && form == BerForm::Long(1) { BerForm::Minimal } else { form };
        let value = rng.bytes(len);
        let t = klv_with(UniversalLabel::from_bytes(key), &value, form);
        stream.extend(&t);
        expected.push(t);
    }
    (stream, expected)
}

#[test]
fn split_independence_on_long_streams() {
    let mut rng = Rng(42);
    for round in 0..20 {
        let (stream, expected) = build(&mut rng, 60, round % 2 == 1);
        let cfg = Config::default();
        let (whole, whole_stats) = decode(&stream, &cfg, &mut || usize::MAX);
        let got: Vec<Vec<u8>> = whole.iter().map(|(_, b)| b.clone()).collect();
        assert_eq!(got, expected);
        for max in [1, 2, 7, 16, 17, 64, 188, 1500] {
            let mut r = Rng(round as u64 * 31 + max as u64);
            let (split, split_stats) = decode(&stream, &cfg, &mut || 1 + r.below(max));
            assert_eq!(split, whole, "round {round} max chunk {max}");
            assert_eq!(split_stats, whole_stats);
        }
    }
}

#[test]
fn offsets_point_into_the_stream() {
    let mut rng = Rng(7);
    let (stream, _) = build(&mut rng, 40, true);
    let (frames, stats) = decode(&stream, &Config::default(), &mut || 100);
    for (off, bytes) in &frames {
        let at = *off as usize;
        assert_eq!(&stream[at..at + bytes.len()], &bytes[..]);
    }
    assert_eq!(stats.bytes, stream.len() as u64);
    assert_eq!(stats.bytes, stats.frame_bytes + stats.bytes_skipped);
}

#[test]
fn filter_by_key_ignoring_version() {
    let wanted = annex::local_set_key();
    let mut stream = annex::local_set();
    stream.extend(annex::universal_set());
    let mut v2 = annex::local_set();
    v2[7] = 0x0D; // same set, different register version
    stream.extend(&v2);

    let mut d = Decoder::new();
    d.set_filter(move |h| h.key().eq_ignoring_version(&wanted));
    d.push(&stream);
    let got: Vec<u8> = d.frames().map(|f| f.key().version()).collect();
    assert_eq!(got, [0x01, 0x0D]);
    assert_eq!(d.stats().filtered, 1);
}

#[test]
fn frames_decode_as_groups() {
    let mut d = Decoder::new();
    d.push(&annex::global_set());
    let f = d.next_frame().unwrap();
    let Some(Group::Global(s)) = f.group() else { panic!("not a global set") };
    assert_eq!(s.iter().count(), 3);
}

#[test]
fn reset_forgets_position() {
    let mut d = Decoder::new();
    d.push(&[0xAA; 10]);
    d.push(&annex::single_item());
    assert_eq!(d.next_frame().unwrap().offset(), 10);
    d.reset();
    d.push(&annex::single_item());
    assert_eq!(d.next_frame().unwrap().offset(), 0);
}
