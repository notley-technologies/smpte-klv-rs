//! Fuzz harnesses, shared by the coverage-guided targets in `fuzz/` and the
//! stable-toolchain fuzz test `tests/fuzz.rs`.
//!
//! Each harness accepts any bytes, must never panic, and checks properties
//! that hold for every input:
//!
//! - errors carry consistent positions, "incomplete" really means a prefix
//!   of something longer, and nothing inside a set or pack is incomplete;
//! - decoded items tile their set exactly, with nothing skipped or reused;
//! - the encoders either refuse an item, for a reason an independent check
//!   agrees with, or write it so that strict decoding gives it back;
//! - the streaming decoder's frames and counters do not depend on how the
//!   input is split, every input byte is accounted for, memory stays within
//!   the configured limits, and a bounded skip recovers from a damaged
//!   length.
#![allow(dead_code)]

#[path = "../common/mod.rs"]
pub mod common;

use common::*;
use smpte_klv::*;

/// Every byte 6 value SMPTE ST 336:2017 defines for groups.
pub const REGISTRY_DESIGNATORS: [u8; 26] = [
    0x01, 0x02, 0x22, 0x42, 0x62, 0x03, 0x0B, 0x13, 0x1B, 0x23, 0x2B, 0x33, 0x3B, 0x43, 0x4B, 0x53, 0x5B, 0x63,
    0x6B, 0x73, 0x7B, 0x04, 0x24, 0x44, 0x64, 0x05,
];

/// Reads control values from fuzz input, yielding zeros once it runs out.
pub struct Input<'a> {
    data: &'a [u8],
}

impl<'a> Input<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Input { data }
    }

    pub fn byte(&mut self) -> u8 {
        match self.data.split_first() {
            Some((&b, rest)) => {
                self.data = rest;
                b
            }
            None => 0,
        }
    }

    pub fn below(&mut self, n: usize) -> usize {
        let v = usize::from(self.byte()) | usize::from(self.byte()) << 8;
        if n == 0 {
            0
        } else {
            v % n
        }
    }

    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.data.len());
        let (a, b) = self.data.split_at(n);
        self.data = b;
        a
    }

    pub fn rest(&mut self) -> &'a [u8] {
        self.bytes(self.data.len())
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

fn options_from(control: u8) -> DecodeOptions {
    let mut o = if control & 1 == 0 { DecodeOptions::strict() } else { DecodeOptions::lenient() };
    if control & 2 != 0 {
        o.indefinite_length = IndefiniteLength::ToEnd;
    }
    o.skip_fill = control & 4 != 0;
    o.require_smpte_key = control & 8 == 0;
    o
}

// ---------------------------------------------------------------- targets

/// Raw bytes: the first byte picks options, the rest is decoded as a
/// sequence of triplets, and also as the value of every kind of group.
pub fn parse(data: &[u8]) {
    let (control, body) = data.split_first().map_or((0, &[][..]), |(c, rest)| (*c, rest));
    let opts = options_from(control);
    check_triplets(body, opts, 0);

    // The body as a group value, under a key whose designator bytes come
    // from the input (exercising malformed Global Set designators) and
    // under one with a valid designator.
    let mut key = [0x06, 0x0E, 0x2B, 0x34, 0x02, 0x00, 0x05, 0x01, 0x06, 0x0E, 0x2B, 0x34, 0, 0, 0, 0];
    let (designator, value) = body.split_at(body.len().min(8));
    let fixed = UniversalLabel::from_bytes(key);
    key[8..8 + designator.len()].copy_from_slice(designator);
    let from_input = UniversalLabel::from_bytes(key);
    for &b6 in &REGISTRY_DESIGNATORS {
        let coding = GroupCoding::from_registry_designator(b6).unwrap();
        for (k, v) in [(fixed, body), (from_input, value)] {
            let k = k.with_group_coding(coding);
            let group = Group::new(k, v, opts).expect("a defined coding");
            assert_eq!(group.coding(), coding);
            check_group(&group, 0);
        }
    }

    // Header and BER primitives on their own.
    let _ = Header::parse_with(body, &opts);
    let _ = ber::decode_length(body);
    let _ = ber::decode_oid(body, control & 0x10 != 0);
    if let Some(ul) = UniversalLabel::from_slice(body) {
        let _ = ul.is_well_formed();
        assert!(ul.arcs().count() <= 16);
        assert_eq!(ul.to_string().parse::<UniversalLabel>(), Ok(ul));
        assert_eq!(ul.urn().to_string().parse::<UniversalLabel>(), Ok(ul));
    }
}

/// Structured: the bytes describe groups to build with the encoders. Each
/// is decoded again and compared item by item, then streamed through a
/// decoder in chunks.
pub fn roundtrip(data: &[u8]) {
    let mut input = Input::new(data);
    let mut packets = Vec::new();
    while !input.is_empty() && packets.len() < 8 {
        if let Some(p) = build_group(&mut input, 0) {
            packets.push(p);
        }
    }
    let stream = packets.concat();
    let mut d = Decoder::new();
    let mut pos = 0;
    while pos < stream.len() {
        let n = 1 + input.below(64);
        let end = (pos + n).min(stream.len());
        d.push(&stream[pos..end]);
        pos = end;
    }
    d.finish();
    let frames: Vec<Vec<u8>> = d.frames().map(Frame::into_bytes).collect();
    assert_eq!(frames, packets);
    assert_eq!(d.stats().bytes_skipped, 0);

    // Liveness: a damaged length declaring an enormous value, between two
    // packets, costs only its own header when skips are bounded.
    if !packets.is_empty() {
        let cut = input.below(packets.len() + 1);
        let mut damaged = packets[..cut].concat();
        let header_at = damaged.len();
        damaged.extend(UniversalLabel::PREFIX);
        damaged.extend([1, 1, 1, 1, 1, 5, 2, 0, 0, 0, 0, 0]);
        damaged.extend([0x88, 0x10 | (input.byte() & 0x0F), 0, 0, 0, 0, 0, 0, 0]);
        let header_len = damaged.len() - header_at;
        damaged.extend(packets[cut..].concat());
        let mut cfg = Config::default();
        cfg.max_skip_len = 1 << 24;
        let mut d = Decoder::with_config(cfg);
        let chunk = 1 + input.below(300);
        for c in damaged.chunks(chunk) {
            d.push(c);
        }
        d.finish();
        let frames: Vec<Vec<u8>> = d.frames().map(Frame::into_bytes).collect();
        assert_eq!(frames, packets, "a damaged length cost more than its header");
        assert_eq!(d.stats().bytes_skipped, header_len as u64);
        assert_eq!(d.stats().malformed, 1);
    }
}

/// Raw bytes as a stream: the first bytes pick the configuration and how
/// the rest is split into pushes. The frames and stats must equal those of
/// one whole push.
pub fn stream(data: &[u8]) {
    let mut input = Input::new(data);
    let control = input.byte();
    let split = input.byte();
    let mut cfg = Config::default();
    cfg.max_value_len = [0, 5, 64, 1 << 20][usize::from(control & 3)];
    cfg.max_queue_bytes = [64, 1 << 20][usize::from((control >> 2) & 1)];
    cfg.options.skip_fill = control & 8 != 0;
    cfg.options.require_smpte_key = control & 0x10 == 0;
    let filter = control & 0x20 != 0;
    cfg.resync_on_reserved_category = control & 0x40 != 0;
    cfg.options.reject_label_keys = control & 0x80 == 0;
    cfg.max_skip_len = [u64::MAX, 40, 300, 1 << 16][usize::from((split >> 1) & 3)];
    let body = input.rest();

    let whole = run_decoder(body, &cfg, filter, &[body.len().max(1)]);
    let mut rng = Rng(u64::from(split) * 0x9E37_79B9 + body.len() as u64 + 1);
    let sizes: Vec<usize> = (0..32).map(|_| 1 + rng.below(if split & 1 == 0 { 8 } else { 200 })).collect();
    let chunked = run_decoder(body, &cfg, filter, &sizes);
    assert_eq!(whole, chunked, "results depend on how the input is split");

    let (frames, stats) = whole;
    let mut last_end = 0u64;
    for (offset, bytes) in &frames {
        assert!(*offset >= last_end, "frames overlap");
        last_end = offset + bytes.len() as u64;
        let at = usize::try_from(*offset).unwrap();
        assert_eq!(&body[at..at + bytes.len()], &bytes[..], "a frame is not the input at its offset");
        let t = Triplet::parse_exact_with(bytes, &cfg.options).expect("frames are whole triplets");
        assert!(t.value().len() <= cfg.max_value_len);
        assert!(!t.is_indefinite());
        if cfg.resync_on_reserved_category && t.key().is_smpte() {
            assert!(!matches!(t.key().category(), Category::Reserved(_)), "reserved category delivered");
        }
    }
    assert_eq!(stats.bytes, body.len() as u64);
    assert_eq!(stats.frames, frames.len() as u64);
}

// ---------------------------------------------------------------- helpers

type Run = (Vec<(u64, Vec<u8>)>, Stats);

/// Push `body` in chunks of `sizes` (cycled), then finish. Returns the
/// frames with offsets and the stats.
fn run_decoder(body: &[u8], cfg: &Config, filter: bool, sizes: &[usize]) -> Run {
    let mut d = Decoder::with_config(cfg.clone());
    if filter {
        d.set_filter(|h| h.key().as_bytes()[8] % 2 == 0);
    }
    let mut pos = 0;
    for &n in sizes.iter().cycle() {
        if pos >= body.len() {
            break;
        }
        let end = (pos + n).min(body.len());
        d.push(&body[pos..end]);
        pos = end;
        let s = d.stats();
        assert_eq!(s.bytes, s.frame_bytes + s.bytes_skipped + d.buffered() as u64, "bytes unaccounted for");
        // A buffered triplet never exceeds its header plus the value limit.
        assert!(d.buffered() <= 16 + 127 + cfg.max_value_len, "buffer above limit");
    }
    d.finish();
    assert_eq!(d.buffered(), 0);
    let s = d.stats().clone();
    assert_eq!(s.bytes, s.frame_bytes + s.bytes_skipped);
    let mut queued = 0;
    let frames: Vec<(u64, Vec<u8>)> = d
        .frames()
        .map(|f| {
            queued += f.encoded_len();
            (f.offset(), f.into_bytes())
        })
        .collect();
    assert!(frames.len() <= 1 || queued <= cfg.max_queue_bytes, "queue above limit");
    (frames, s)
}

/// Check every triplet in `buf`, descending into groups.
fn check_triplets(buf: &[u8], opts: DecodeOptions, depth: usize) {
    let mut it = Triplets::with_options(buf, opts);
    let mut pos = 0;
    while let Some(r) = it.next() {
        match r {
            Ok(t) => {
                let start = it.offset() - t.encoded_len();
                assert!(start >= pos, "triplets overlap");
                assert!(opts.skip_fill || start == pos, "bytes skipped between triplets");
                pos = it.offset();
                check_triplet(&t, &buf[start..], opts, depth);
            }
            Err(e) => {
                assert_eq!(it.offset(), pos);
                check_error(e, buf.len(), pos, false);
            }
        }
    }
}

fn check_triplet(t: &Triplet, at: &[u8], opts: DecodeOptions, depth: usize) {
    assert_eq!(&at[..t.encoded_len()], t.as_bytes());
    assert_eq!(t.header_len() + t.value().len(), t.encoded_len());
    assert_eq!(Triplet::parse_with(t.as_bytes(), &opts).unwrap(), *t);
    let h = Header::parse_with(at, &opts).unwrap();
    assert_eq!(h.key(), t.key());
    assert_eq!(h.header_len(), t.header_len());
    if !t.is_indefinite() {
        assert_eq!(h.total_len(), Some(t.encoded_len() as u64));
        assert_eq!(Triplet::parse_exact_with(t.as_bytes(), &opts).unwrap(), *t);
        // Any cut through a triplet is incomplete, never "malformed"; in a
        // buffer that is meant to be exact it is an overrun.
        for cut in [0, t.header_len() - 1, t.header_len(), t.encoded_len() - 1] {
            if cut < t.encoded_len() {
                let e = Triplet::parse_with(&t.as_bytes()[..cut], &opts).unwrap_err();
                assert!(e.is_incomplete(), "cut at {cut}: {e}");
                assert!(e.needed().unwrap() > cut);
                let e = Triplet::parse_exact_with(&t.as_bytes()[..cut], &opts).unwrap_err();
                assert!(matches!(e.kind(), ErrorKind::Overrun { .. }), "cut at {cut}: {e}");
            }
        }
    }
    if depth < 4 {
        if let Some(g) = t.group() {
            check_group(&g, depth + 1);
        }
    }
}

/// `bounded`: the buffer is a set or pack value, whose size is fixed, so no
/// error may claim that more input would help.
fn check_error(e: Error, len: usize, start: usize, bounded: bool) {
    assert!(e.offset() >= start, "{e} before the item that failed at {start}");
    assert!(e.offset() <= len, "{e} past the end ({len})");
    assert!(!(bounded && e.is_incomplete()), "{e} inside a set or pack claims to be incomplete");
    if let ErrorKind::UnexpectedEnd { needed, available } | ErrorKind::Overrun { needed, available } = e.kind() {
        assert_eq!(available, len, "{e}");
        assert!(needed > available, "{e}");
        assert!(needed <= isize::MAX as usize, "{e}");
        assert_eq!(e.needed().is_some(), !bounded);
    }
}

/// Items must tile the value: each starts where the last ended, and
/// iteration either covers every byte or ends with one error.
fn check_group(g: &Group, depth: usize) {
    let value = g.value();
    let mut pos = 0;
    let mut failed = false;
    let mut items: Vec<(Option<u64>, Option<UniversalLabel>, Vec<u8>)> = Vec::new();
    let mut step = |r: Result<(usize, &[u8], &[u8]), Error>, pos: &mut usize| match r {
        Ok((offset, raw, item_value)) => {
            assert_eq!(offset, *pos, "items do not tile the set");
            assert_eq!(&value[offset..offset + raw.len()], raw);
            assert!(raw.ends_with(item_value));
            assert!(!raw.is_empty(), "an item took no bytes");
            *pos += raw.len();
        }
        Err(e) => {
            check_error(e, value.len(), *pos, true);
            failed = true;
        }
    };
    match g {
        Group::Universal(s) => {
            let mut it = s.iter();
            while let Some(r) = it.next() {
                if let Ok(t) = &r {
                    let offset = it.offset() - t.encoded_len();
                    if offset > pos {
                        // Only skipped Fill items may leave a gap.
                        assert!(Triplets::new(&value[pos..offset]).all(|f| f.unwrap().is_fill()));
                        pos = offset;
                    }
                }
                let offset = it.offset();
                step(r.map(|t| (offset - t.encoded_len(), t.as_bytes(), t.value())), &mut pos);
            }
            if !failed && pos < value.len() {
                // Fill items skipped at the end of the set.
                assert!(s.options().skip_fill && Triplets::new(&value[pos..]).all(|f| f.unwrap().is_fill()));
                pos = value.len();
            }
            if !failed {
                for t in s.iter() {
                    let t = t.unwrap();
                    items.push((None, Some(t.key()), t.value().to_vec()));
                    if depth < 4 {
                        if let Some(inner) = t.group() {
                            check_group(&inner, depth + 1);
                        }
                    }
                }
            }
        }
        Group::Global(s) => {
            for r in s.iter() {
                if let Ok(i) = &r {
                    if i.offset > pos {
                        // Only skipped Fill items may leave a gap.
                        let mut all = *s.options();
                        all.skip_fill = false;
                        let gap = GlobalSet::new(s.key(), &value[pos..i.offset], s.length_encoding()).with_options(all);
                        assert!(s.options().skip_fill && gap.iter().all(|f| f.unwrap().key.is_fill()));
                        pos = i.offset;
                    }
                }
                step(r.map(|i| (i.offset, i.raw, i.value)), &mut pos);
            }
            if !failed && pos < value.len() {
                // Fill items skipped at the end of the set.
                let mut all = *s.options();
                all.skip_fill = false;
                let gap = GlobalSet::new(s.key(), &value[pos..], s.length_encoding()).with_options(all);
                assert!(s.options().skip_fill && gap.iter().all(|f| f.unwrap().key.is_fill()));
                pos = value.len();
            }
            if !failed {
                for i in s.iter() {
                    let i = i.unwrap();
                    assert_eq!(&i.key.as_bytes()[..s.designator().len()], s.designator());
                    items.push((None, Some(i.key), i.value.to_vec()));
                    if depth < 4 {
                        if let Some(inner) = i.group() {
                            check_group(&inner, depth + 1);
                        }
                    }
                }
            }
        }
        Group::Local(s) => {
            for r in s.iter() {
                step(r.map(|i| (i.offset, i.raw, i.value)), &mut pos);
            }
            if !failed {
                items.extend(s.iter().map(|i| i.unwrap()).map(|i| (Some(i.tag), None, i.value.to_vec())));
            }
        }
        Group::VariableLengthPack(p) => {
            for (n, r) in p.iter().enumerate() {
                if let Ok(i) = &r {
                    assert_eq!(i.index, n);
                }
                step(r.map(|i| (i.offset, i.raw, i.value)), &mut pos);
            }
            if !failed {
                items.extend(p.iter().map(|i| (None, None, i.unwrap().value.to_vec())));
            }
        }
        Group::DefinedLengthPack(p) => {
            let mut r = p.reader();
            while !r.remaining().is_empty() {
                let n = 1 + r.remaining()[0] as usize % 7;
                if let Err(e) = r.take(n) {
                    assert!(matches!(e.kind(), ErrorKind::Overrun { .. }), "{e}");
                    assert!(r.remaining().len() < n);
                    r.take_rest();
                }
            }
            r.finish().unwrap();
            check_split(value);
            pos = value.len();
        }
    }
    if !failed {
        assert_eq!(pos, value.len(), "items do not cover the set");
        assert_eq!(g.validate(), Ok(()));
        reencode(g, &items);
    } else {
        assert!(g.validate().is_err());
    }
}

/// Split a Defined-Length Pack by lengths taken from its own bytes and check
/// the result against what ST 336:2017 section 7.6 implies.
fn check_split(value: &[u8]) {
    let lengths: Vec<usize> = value.iter().take(8).map(|b| usize::from(b % 9)).collect();
    let sum: usize = lengths.iter().sum();
    let results: Vec<_> = DefinedLengthPack::new(value).split(&lengths).collect();
    let ok: Vec<&[u8]> = results.iter().filter_map(|r| r.as_ref().ok().map(|i| i.value)).collect();
    let consumed: usize = ok.iter().map(|v| v.len()).sum();
    assert_eq!(ok.concat(), &value[..consumed]);
    let errors: Vec<Error> = results.iter().filter_map(|r| r.as_ref().err().copied()).collect();
    assert!(errors.len() <= 1 && results.last().map_or(true, |r| r.is_err() == !errors.is_empty()));
    if sum <= value.len() {
        assert_eq!(ok.len(), lengths.len());
        match value.len() - sum {
            0 => assert!(errors.is_empty()),
            count => assert_eq!(errors[0].kind(), ErrorKind::TrailingBytes { count }),
        }
    } else {
        assert!(matches!(errors[0].kind(), ErrorKind::Overrun { .. }), "{:?}", errors[0]);
        assert!(!errors[0].is_incomplete());
    }
}

/// Whether the Global Set encoder must accept `key` under a designator of
/// `d` bytes, worked out independently of the encoder: the key is a SMPTE
/// key but not a Label, and the rest of it is a tag of 2 to 12
/// shortest-form words, then only zeros.
pub fn global_key_encodable(key: &UniversalLabel, d: usize) -> bool {
    let k = key.as_bytes();
    if k[..4] != UniversalLabel::PREFIX || k[4] == 0x04 {
        return false;
    }
    let rest = &k[d..];
    let (mut end, mut continued, mut words) = (rest.len(), false, 0);
    for (i, &b) in rest.iter().enumerate() {
        if b == 0 && !continued {
            end = i;
            break;
        }
        if b == 0x80 && !continued {
            return false;
        }
        continued = b & 0x80 != 0;
        words += usize::from(!continued);
    }
    !continued && rest[end..].iter().all(|&b| b == 0) && (2..=12).contains(&words)
}

/// Encode decoded items again with the group's own coding, and check they
/// decode, under the strict options, to the same items. Byte equality is not
/// expected: the input may use non-minimal lengths. The encoders may refuse
/// only what the input's options let through but strict decoding would not.
fn reencode(g: &Group, items: &[(Option<u64>, Option<UniversalLabel>, Vec<u8>)]) {
    let set_key = UniversalLabel::from_bytes([0x06, 0x0E, 0x2B, 0x34, 2, 0, 1, 1, 0x0F, 1, 1, 1, 0, 0, 0, 0])
        .with_group_coding(g.coding());
    let strict_key = |k: &UniversalLabel| k.is_smpte() && k.category() != Category::Label;
    let encoded = match g {
        Group::Universal(_) => {
            let mut e = UniversalSetEncoder::new(set_key).unwrap();
            for (_, k, v) in items {
                let k = k.unwrap();
                match e.item(k, v) {
                    Ok(_) => {}
                    Err(err) => {
                        assert!(!strict_key(&k), "refused {k}: {err}");
                        return;
                    }
                }
            }
            e.finish().unwrap()
        }
        Group::Global(s) => {
            // The designator alone, without anything lenient decoding let
            // through after its terminator.
            let mut key = set_key.to_bytes();
            key[8..].fill(0);
            key[8..8 + s.designator().len()].copy_from_slice(s.designator());
            let key = UniversalLabel::from_bytes(key);
            let d = s.designator();
            let all_labels = d.len() >= 5 && d[4] == 0x04;
            let valid = GlobalSet::new(key, &[], LengthEncoding::Ber).is_designator_valid() && !all_labels;
            let mut e = match GlobalSetEncoder::new(key) {
                Ok(e) => e,
                Err(err) => {
                    assert!(!valid, "refused designator {key}: {err}");
                    return;
                }
            };
            assert!(valid, "accepted designator {key}");
            for (_, k, v) in items {
                let k = k.unwrap();
                let encodable = global_key_encodable(&k, s.designator().len());
                match e.item(k, v) {
                    Ok(_) => assert!(encodable, "accepted {k}"),
                    Err(err) => {
                        assert!(!encodable, "refused {k}: {err}");
                        return;
                    }
                }
            }
            e.finish().unwrap()
        }
        Group::Local(s) => {
            let mut e = LocalSetEncoder::with_coding(set_key, s.tag_encoding(), s.length_encoding()).unwrap();
            for (t, _, v) in items {
                e.item(t.unwrap(), v).unwrap();
            }
            e.finish().unwrap()
        }
        Group::VariableLengthPack(_) => {
            let mut e = VariableLengthPackEncoder::new(set_key).unwrap();
            for (_, _, v) in items {
                e.item(v).unwrap();
            }
            e.finish().unwrap()
        }
        Group::DefinedLengthPack(_) => return,
    };
    let t = Triplet::parse_exact(&encoded).unwrap();
    let again = t.group().unwrap();
    let decoded: Vec<(Option<u64>, Option<UniversalLabel>, Vec<u8>)> = match again {
        Group::Universal(s) => s.iter().map(|t| t.unwrap()).map(|t| (None, Some(t.key()), t.value().to_vec())).collect(),
        Group::Global(s) => s.iter().map(|i| i.unwrap()).map(|i| (None, Some(i.key), i.value.to_vec())).collect(),
        Group::Local(s) => s.iter().map(|i| i.unwrap()).map(|i| (Some(i.tag), None, i.value.to_vec())).collect(),
        Group::VariableLengthPack(p) => p.iter().map(|i| (None, None, i.unwrap().value.to_vec())).collect(),
        Group::DefinedLengthPack(_) => unreachable!(),
    };
    assert_eq!(decoded, items, "re-encoded items differ");
}

// ---------------------------------------------------------------- generator

/// Build one group from the input with the encoders, checking each item
/// against what decoding returns. Returns the encoded packet, or `None` when
/// the input asked for something the encoders correctly refused.
pub fn build_group(input: &mut Input, depth: usize) -> Option<Vec<u8>> {
    let b6 = REGISTRY_DESIGNATORS[input.below(REGISTRY_DESIGNATORS.len())];
    let coding = GroupCoding::from_registry_designator(b6).unwrap();
    let form = match input.byte() % 4 {
        0 => BerForm::Long(1 + input.byte() % 9),
        _ => BerForm::Minimal,
    };
    let mut key = [0x06, 0x0E, 0x2B, 0x34, 0x02, b6, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    // A designator starts with as much of the UL prefix as it covers.
    let designator_len = 2 + input.below(7);
    for (i, b) in key[8..8 + designator_len].iter_mut().enumerate() {
        *b = match UniversalLabel::PREFIX.get(i) {
            Some(&p) => p,
            // Byte 5 of every item key: not 0x04, which would make them all
            // Labels (the encoder refuses such a designator).
            None if i == 4 => 1 + (input.byte() % 0x7E + 4) % 0x7F,
            None => 1 + input.byte() % 0x7F,
        };
    }
    let key = UniversalLabel::from_bytes(key);
    let n = input.below(6);

    enum Expect {
        Key(UniversalLabel, Vec<u8>),
        Tag(u64, Vec<u8>),
        Value(Vec<u8>),
    }
    let mut expect = Vec::new();
    let value_of = |input: &mut Input, depth: usize| -> Vec<u8> {
        if depth < 2 && input.byte() % 5 == 0 {
            if let Some(nested) = build_group(input, depth + 1) {
                return nested;
            }
        }
        let len = match input.byte() % 8 {
            0 => 256 + input.below(400),
            1 => 0,
            _ => input.below(40),
        };
        (0..len).map(|i| i as u8 ^ 0x5A).collect()
    };

    let packet = match coding {
        GroupCoding::UniversalSet => {
            let mut e = UniversalSetEncoder::new(key).unwrap().length_form(form);
            for _ in 0..n {
                let mut k = *key.as_bytes();
                k[4] = 1;
                k[12] = input.byte();
                let k = UniversalLabel::from_bytes(k);
                let v = value_of(input, depth);
                if e.item(k, &v).is_ok() {
                    expect.push(Expect::Key(k, v));
                }
            }
            e.finish()
        }
        GroupCoding::GlobalSet { .. } => {
            let mut e = GlobalSetEncoder::new(key).unwrap().length_form(form);
            for _ in 0..n {
                // Up to the whole rest of the key: 14 bytes after a 2-byte
                // designator. Bytes may continue a word (top bit set), and
                // now and then are zero, which only a word in progress may
                // contain.
                let mut k = [0u8; 16];
                k[..designator_len].copy_from_slice(&key.item_designator()[..designator_len]);
                let len = input.below(16 - designator_len + 1);
                for b in &mut k[designator_len..designator_len + len] {
                    let r = input.byte();
                    *b = if r % 23 == 0 { 0 } else { (1 + r % 0x7F) | (input.byte() & 0x80) };
                }
                if len > 0 && input.byte() % 4 != 0 {
                    k[designator_len + len - 1] &= 0x7F;
                }
                // Usually finish the SMPTE prefix a short designator leaves
                // to the tag.
                if designator_len < 4 && input.byte() % 8 != 0 {
                    k[designator_len..4].copy_from_slice(&UniversalLabel::PREFIX[designator_len..]);
                }
                let k = UniversalLabel::from_bytes(k);
                let encodable = global_key_encodable(&k, designator_len);
                let v = value_of(input, depth);
                let before = e.len();
                match e.item(k, &v) {
                    Ok(_) => {
                        assert!(encodable, "accepted {k}");
                        expect.push(Expect::Key(k, v));
                    }
                    Err(err) => {
                        assert_eq!(e.len(), before, "a refused item was partly written");
                        match err.kind() {
                            ErrorKind::LengthNotRepresentable { .. } => {}
                            ErrorKind::InvalidGlobalTag | ErrorKind::LabelKey | ErrorKind::InvalidKey => {
                                assert!(!encodable, "refused {k}: {err}")
                            }
                            _ => panic!("{err}"),
                        }
                    }
                }
            }
            e.finish()
        }
        GroupCoding::LocalSet { .. } => {
            let mut e = LocalSetEncoder::new(key).unwrap().length_form(form);
            for _ in 0..n {
                let tag = match input.byte() % 4 {
                    0 => u64::from(input.byte()),
                    1 => input.below(70_000) as u64,
                    2 => u64::MAX >> input.below(64),
                    _ => input.below(128) as u64,
                };
                let v = value_of(input, depth);
                let before = e.len();
                match e.item(tag, &v) {
                    Ok(_) => expect.push(Expect::Tag(tag, v)),
                    Err(_) => assert_eq!(e.len(), before, "a refused item was partly written"),
                }
            }
            e.finish()
        }
        GroupCoding::VariableLengthPack { .. } => {
            let mut e = VariableLengthPackEncoder::new(key).unwrap().length_form(form);
            for _ in 0..n {
                let v = value_of(input, depth);
                if e.item(&v).is_ok() {
                    expect.push(Expect::Value(v));
                }
            }
            e.finish()
        }
        GroupCoding::DefinedLengthPack => {
            let mut e = DefinedLengthPackEncoder::new(key).unwrap().length_form(form);
            for _ in 0..n {
                let v = value_of(input, depth);
                e.item(&v);
                expect.push(Expect::Value(v));
            }
            e.finish()
        }
    };
    let packet = match packet {
        Ok(p) => p,
        Err(e) => {
            // Only a fixed-size outer length can refuse.
            assert!(matches!(e.kind(), ErrorKind::LengthNotRepresentable { .. }), "{e}");
            assert!(matches!(form, BerForm::Long(_)));
            return None;
        }
    };

    let t = Triplet::parse_exact(&packet).expect("encoded packets decode");
    assert_eq!(t.key(), key);
    let group = t.group().expect("a group key");
    assert_eq!(group.coding(), coding);
    match group {
        Group::Universal(s) => {
            let got: Vec<_> = s.iter().map(|t| t.unwrap()).collect();
            assert_eq!(got.len(), expect.len());
            for (t, e) in got.iter().zip(&expect) {
                let Expect::Key(k, v) = e else { unreachable!() };
                assert_eq!((t.key(), t.value()), (*k, &v[..]));
            }
        }
        Group::Global(s) => {
            let got: Vec<_> = s.iter().map(|i| i.unwrap()).collect();
            assert_eq!(got.len(), expect.len());
            for (i, e) in got.iter().zip(&expect) {
                let Expect::Key(k, v) = e else { unreachable!() };
                assert_eq!((i.key, i.value), (*k, &v[..]));
            }
        }
        Group::Local(s) => {
            let got: Vec<_> = s.iter().map(|i| i.unwrap()).collect();
            assert_eq!(got.len(), expect.len());
            for (i, e) in got.iter().zip(&expect) {
                let Expect::Tag(tag, v) = e else { unreachable!() };
                assert_eq!((i.tag, i.value), (*tag, &v[..]));
            }
        }
        Group::VariableLengthPack(p) => {
            let got: Vec<_> = p.iter().map(|i| i.unwrap()).collect();
            assert_eq!(got.len(), expect.len());
            for (i, e) in got.iter().zip(&expect) {
                let Expect::Value(v) = e else { unreachable!() };
                assert_eq!(i.value, &v[..]);
            }
        }
        Group::DefinedLengthPack(p) => {
            let lengths: Vec<usize> = expect.iter().map(|e| if let Expect::Value(v) = e { v.len() } else { 0 }).collect();
            let got: Vec<_> = p.split(&lengths).map(|i| i.unwrap().value).collect();
            assert_eq!(got.len(), expect.len());
            for (g, e) in got.iter().zip(&expect) {
                let Expect::Value(v) = e else { unreachable!() };
                assert_eq!(*g, &v[..]);
            }
            // Leaving out the last length leaves its bytes over.
            if let Some((&last, rest)) = lengths.split_last() {
                let tail = p.split(rest).last();
                if last == 0 {
                    assert!(tail.map_or(true, |r| r.is_ok()));
                } else {
                    assert_eq!(tail.unwrap().unwrap_err().kind(), ErrorKind::TrailingBytes { count: last });
                }
            }
        }
    }
    Some(packet)
}
