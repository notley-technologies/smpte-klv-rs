//! The crate used the way a downstream format library uses it: a MISB ST
//! 0601-style local set with a checksum, nested local sets, private keys,
//! fixed-buffer encoding without allocation.
// The tests use the encoders and the stream decoder.
#![cfg(feature = "alloc")]

mod common;

use common::*;
use smpte_klv::*;

/// UAS Datalink Local Set key (MISB ST 0601), used here only as an example
/// of a Local Set key with BER-OID tags and BER lengths.
fn uas_key() -> UniversalLabel {
    ul("06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00")
}

/// A 16-bit running sum over bytes, the shape of checksum several KLV
/// formats append as their last item.
fn sum16(bytes: &[u8]) -> u16 {
    bytes.iter().enumerate().fold(0u16, |s, (i, &b)| s.wrapping_add(u16::from(b) << (8 * ((i + 1) % 2))))
}

#[test]
fn checksummed_local_set() {
    // Build: items, then a checksum item covering everything before its
    // value, including the key and outer length.
    let mut set = LocalSetEncoder::new(uas_key()).unwrap();
    set.item(2, &[0, 4, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8]).unwrap();
    set.item(65, &[19]).unwrap();
    let mut value = set.into_value();
    value.extend([0x01, 0x02]); // tag 1, length 2
    let mut packet = Vec::new();
    encode::write_header(uas_key(), value.len() as u64 + 2, BerForm::Minimal, &mut packet).unwrap();
    packet.extend(&value);
    let sum = sum16(&packet);
    packet.extend(sum.to_be_bytes());

    // Decode and verify: the checksum item's raw bytes locate the region.
    let t = Triplet::parse_exact(&packet).unwrap();
    let Some(Group::Local(s)) = t.group() else { panic!() };
    let checksum = s.iter().map(|i| i.unwrap()).find(|i| i.tag == 1).unwrap();
    let covered = t.header_len() + checksum.offset + checksum.raw.len() - checksum.value.len();
    assert_eq!(sum16(&packet[..covered]).to_be_bytes(), checksum.value);
    assert_eq!(s.get(65).unwrap().unwrap().value, &[19]);
}

#[test]
fn nested_local_set_inside_an_item() {
    // The outer document says tag 48 holds a local set with 1-byte tags
    // and BER lengths; only it knows that, so the caller decodes it.
    let mut inner = LocalSetEncoder::with_coding(uas_key(), TagEncoding::BerOid, LengthEncoding::Ber).unwrap();
    inner.item(1, &[1]).unwrap().item(2, &[0xAB, 0xCD]).unwrap();
    let mut outer = LocalSetEncoder::new(uas_key()).unwrap();
    outer.item(48, inner.value()).unwrap();
    let packet = outer.finish().unwrap();

    let t = Triplet::parse(&packet).unwrap();
    let Some(Group::Local(s)) = t.group() else { panic!() };
    let item = s.get(48).unwrap().unwrap();
    let nested = LocalSet::new(item.value, TagEncoding::BerOid, LengthEncoding::Ber);
    assert_eq!(nested.get(2).unwrap().unwrap().value, &[0xAB, 0xCD]);
}

#[test]
fn unknown_keys_pass_through() {
    // ST 336:2017 section 5.2.1: an unrecognised key is handed on with its
    // length and value, and decoding continues after it.
    let private = ul("06.0E.2B.34.05.01.01.01.0E.0B.01.02.03.04.00.00");
    let reserved = ul("06.0E.2B.34.7E.01.01.01.01.02.03.04.00.00.00.00");
    let unknown_group = ul("06.0E.2B.34.02.06.01.01.01.02.03.04.00.00.00.00");
    let mut stream = klv(private, b"secret");
    stream.extend(klv(reserved, b"r"));
    stream.extend(klv(unknown_group, b"g"));
    stream.extend(common::annex::single_item());
    let ts: Vec<Triplet> = Triplets::new(&stream).map(Result::unwrap).collect();
    assert_eq!(ts.len(), 4);
    assert_eq!(ts[0].key().category(), Category::RegisteredPrivate);
    assert_eq!(ts[1].key().category(), Category::Reserved(0x7E));
    assert!(ts[2].group().is_none());
    assert_eq!(ts[0].value(), b"secret");
    let mut forwarded = Vec::new();
    for t in &ts {
        t.write_to(&mut forwarded).unwrap();
    }
    assert_eq!(forwarded, stream);
}

#[test]
fn encoding_without_allocation() {
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    let key = uas_key();
    // Header with a fixed 4-byte length field, so the value can be written
    // after it without knowing its size in advance.
    encode::write_header(key, 5, BerForm::Long(3), &mut out).unwrap();
    TagEncoding::BerOid.encode(65, &mut out).unwrap();
    LengthEncoding::Ber.encode(3, BerForm::Minimal, &mut out).unwrap();
    out.write_bytes(&[1, 2, 3]).unwrap();
    let n = out.position();
    let t = Triplet::parse_exact(&buf[..n]).unwrap();
    assert_eq!(t.header_len(), 20);
    let Some(Group::Local(s)) = t.group() else { panic!() };
    assert_eq!(s.get(65).unwrap().unwrap().value, &[1, 2, 3]);

    // A triplet that does not fit writes nothing, and the error gives its
    // whole size.
    let mut tiny = [0u8; 10];
    let mut out = SliceSink::new(&mut tiny);
    let e = encode::write_triplet(key, &[], BerForm::Minimal, &mut out).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::BufferTooSmall { needed: 17, available: 10 });
    assert_eq!(out.position(), 0);
}

#[test]
fn encoders_check_the_key_and_the_fields() {
    let local = uas_key();
    assert_eq!(
        UniversalSetEncoder::new(local).unwrap_err().kind(),
        ErrorKind::UnexpectedGroupCoding { registry_designator: 0x0B }
    );
    assert!(GlobalSetEncoder::new(local).is_err());
    assert!(VariableLengthPackEncoder::new(local).is_err());
    assert!(DefinedLengthPackEncoder::new(local).is_err());
    assert!(LocalSetEncoder::new(common::annex::main_title_key()).is_err());

    // 1-byte tags, 1-byte lengths.
    let small = local.with_group_coding(GroupCoding::LocalSet { tag: TagEncoding::U8, length: LengthEncoding::U8 });
    let mut e = LocalSetEncoder::new(small).unwrap();
    assert_eq!(e.tag_encoding(), TagEncoding::U8);
    assert_eq!(e.length_encoding(), LengthEncoding::U8);
    assert_eq!(e.item(256, &[]).unwrap_err().kind(), ErrorKind::TagNotRepresentable { tag: 256 });
    assert_eq!(e.item(1, &[0; 256]).unwrap_err().kind(), ErrorKind::LengthNotRepresentable { length: 256 });
    assert!(e.is_empty());
    e.item(255, &[0; 255]).unwrap();
    assert_eq!(e.len(), 257);
    assert_eq!(e.key(), small);

    // Global Sets: keys must share the designator, and tags need 2 words.
    let g = common::annex::global_set_key();
    let mut e = GlobalSetEncoder::new(g).unwrap();
    assert_eq!(e.item(ul("06.0E.2B.35.01.01.01.01.01.00.00.00.00.00.00.00"), &[]).unwrap_err().kind(), ErrorKind::KeyOutsideDesignator);
    assert_eq!(e.item(ul("06.0E.2B.34.01.01.01.01.00.00.00.00.00.00.00.00"), &[]).unwrap_err().kind(), ErrorKind::InvalidGlobalTag);
    assert!(e.is_empty());
    let mut bad = g.to_bytes();
    bad[9] = 0;
    assert_eq!(GlobalSetEncoder::new(UniversalLabel::from_bytes(bad)).unwrap_err().kind(), ErrorKind::InvalidGlobalSetDesignator);

    // A Long(1) outer length cannot hold a 300-byte value.
    let mut e = VariableLengthPackEncoder::new(local.with_group_coding(GroupCoding::VariableLengthPack {
        length: LengthEncoding::U16,
    }))
    .unwrap()
    .length_form(BerForm::Long(1));
    e.item(&[0; 300]).unwrap();
    assert_eq!(e.finish().unwrap_err().kind(), ErrorKind::LengthNotRepresentable { length: 302 });
}

#[test]
fn universal_set_with_nested_set() {
    let us = common::annex::universal_set_key();
    let mut inner = LocalSetEncoder::new(common::annex::local_set_key()).unwrap();
    inner.item(1, b"x").unwrap();
    let mut outer = UniversalSetEncoder::new(us).unwrap();
    outer.raw(&inner.finish().unwrap()).item(common::annex::main_title_key(), b"t").unwrap();
    let packet = outer.finish().unwrap();
    let t = Triplet::parse(&packet).unwrap();
    let Some(Group::Universal(s)) = t.group() else { panic!() };
    let first = s.iter().next().unwrap().unwrap();
    let Some(Group::Local(l)) = first.group() else { panic!() };
    assert_eq!(l.get(1).unwrap().unwrap().value, b"x");
}

#[test]
fn lenient_options_reach_nested_groups() {
    // A Local Set with a non-minimal BER-OID tag, inside a Universal Set.
    let inner = klv(common::annex::local_set_key().with_group_coding(GroupCoding::LocalSet {
        tag: TagEncoding::BerOid,
        length: LengthEncoding::Ber,
    }), &[0x80, 0x05, 0x00]);
    let packet = klv(common::annex::universal_set_key(), &inner);
    for (opts, ok) in [(DecodeOptions::strict(), false), (DecodeOptions::lenient(), true)] {
        let t = Triplet::parse_with(&packet, &opts).unwrap();
        let Some(Group::Universal(s)) = t.group() else { panic!() };
        let item = s.iter().next().unwrap().unwrap();
        assert_eq!(item.options(), &opts);
        let Some(Group::Local(l)) = item.group() else { panic!() };
        assert_eq!(l.iter().next().unwrap().is_ok(), ok);
    }
}

#[cfg(feature = "serde")]
#[test]
fn serde() {
    assert_eq!(serde_json::to_string(&uas_key()).unwrap(), "\"06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00\"");
    let coding = uas_key().group_coding().unwrap();
    assert_eq!(serde_json::to_string(&coding).unwrap(), r#"{"LocalSet":{"tag":"BerOid","length":"Ber"}}"#);
    let e = Triplet::parse(&[6]).unwrap_err();
    assert_eq!(
        serde_json::to_string(&e).unwrap(),
        r#"{"kind":{"UnexpectedEnd":{"needed":17,"available":1}},"offset":1}"#
    );
    assert!(serde_json::to_string(Decoder::new().stats()).unwrap().contains("\"frames\":0"));
    assert!(serde_json::to_string(&Config::default()).unwrap().contains("max_value_len"));
}
