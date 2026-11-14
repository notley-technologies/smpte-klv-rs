//! The worked examples of SMPTE ST 336:2017 Annexes A to H (and the Global
//! Set example of ST 336M-2007), decoded and re-encoded byte for byte.
// The tests use the encoders and the stream decoder.
#![cfg(feature = "alloc")]

mod common;

use common::annex::*;
use smpte_klv::*;

fn group(buf: &[u8]) -> Group<'_> {
    Triplet::parse_exact(buf).unwrap().group().expect("a group")
}

#[test]
fn annex_a_key_fields() {
    let k = isan_metadata_key();
    assert!(k.is_smpte() && k.is_well_formed());
    assert_eq!(k.category(), Category::Dictionary);
    assert_eq!(k.registry_designator(), 0x01); // metadata dictionary
    assert_eq!(k.structure_designator(), 0x01);
    assert_eq!(k.version(), 0x01);
    assert_eq!(k.item_designator(), &[0x01, 0x01, 0x11, 0x01, 0, 0, 0, 0]);
    assert_eq!(k.arcs().collect::<Vec<_>>(), [1, 3, 52, 1, 1, 1, 1, 1, 1, 17, 1]);
    assert_eq!(k.group_coding(), None);
}

#[test]
fn annex_b_single_item() {
    let buf = single_item();
    let t = Triplet::parse_exact(&buf).unwrap();
    assert_eq!(t.key(), main_title_key());
    assert_eq!(t.value(), MAIN_TITLE);
    assert!(t.group().is_none());
    let mut out = Vec::new();
    encode::write_triplet(main_title_key(), MAIN_TITLE, BerForm::Minimal, &mut out).unwrap();
    assert_eq!(out, buf);
}

fn expected_items() -> [(UniversalLabel, &'static [u8]); 3] {
    [(main_title_key(), MAIN_TITLE), (version_title_key(), VERSION_TITLE), (source_org_key(), SOURCE_ORG)]
}

#[test]
fn annex_c_universal_set() {
    let buf = universal_set();
    let Group::Universal(set) = group(&buf) else { panic!("wrong group kind") };
    let items: Vec<_> = set.iter().map(|t| t.map(|t| (t.key(), t.value()))).collect::<Result<_, _>>().unwrap();
    assert_eq!(items, expected_items());

    let mut enc = UniversalSetEncoder::new(universal_set_key()).unwrap();
    for (k, v) in expected_items() {
        enc.item(k, v).unwrap();
    }
    assert_eq!(enc.finish().unwrap(), buf);
}

#[test]
fn annex_d_global_set() {
    let buf = global_set();
    let Group::Global(set) = group(&buf) else { panic!("wrong group kind") };
    assert_eq!(set.designator(), &[0x06, 0x0E, 0x2B, 0x34, 0x01, 0x01, 0x01]);
    assert!(set.is_designator_valid());
    let items: Vec<_> = set.iter().map(|i| i.map(|i| (i.key, i.value))).collect::<Result<_, _>>().unwrap();
    assert_eq!(items, expected_items());
    let tags: Vec<&[u8]> = set.iter().map(|i| i.unwrap().tag).collect();
    assert_eq!(tags, [&[1, 1, 5, 2][..], &[2, 1, 5, 8], &[1, 2, 1, 1]]);

    let mut enc = GlobalSetEncoder::new(global_set_key()).unwrap();
    for (k, v) in expected_items() {
        enc.item(k, v).unwrap();
    }
    assert_eq!(enc.finish().unwrap(), buf);
}

#[test]
fn st336_2007_global_set_with_full_designator() {
    let buf = global_set_2007();
    let Group::Global(set) = group(&buf) else { panic!("wrong group kind") };
    assert_eq!(set.designator().len(), 8);
    let expected = [(main_title_key(), MAIN_TITLE), (isan_key(), &ISAN[..]), (source_org_key(), SOURCE_ORG)];
    let items: Vec<_> = set.iter().map(|i| i.map(|i| (i.key, i.value))).collect::<Result<_, _>>().unwrap();
    assert_eq!(items, expected);

    let mut enc = GlobalSetEncoder::new(global_set_2007_key()).unwrap();
    for (k, v) in expected {
        enc.item(k, v).unwrap();
    }
    assert_eq!(enc.finish().unwrap(), buf);
}

#[test]
fn annex_e_local_set() {
    let buf = local_set();
    let Group::Local(set) = group(&buf) else { panic!("wrong group kind") };
    assert_eq!(set.tag_encoding(), TagEncoding::U8);
    assert_eq!(set.length_encoding(), LengthEncoding::Ber);
    let items: Vec<_> = set.iter().map(|i| i.map(|i| (i.tag, i.value))).collect::<Result<_, _>>().unwrap();
    assert_eq!(items, [(1, MAIN_TITLE), (2, VERSION_TITLE), (3, SOURCE_ORG)]);

    let mut enc = LocalSetEncoder::new(local_set_key()).unwrap();
    enc.item(1, MAIN_TITLE).unwrap().item(2, VERSION_TITLE).unwrap().item(3, SOURCE_ORG).unwrap();
    assert_eq!(enc.finish().unwrap(), buf);
}

#[test]
fn annex_f_variable_length_pack() {
    let buf = variable_length_pack();
    let Group::VariableLengthPack(pack) = group(&buf) else { panic!("wrong group kind") };
    let values: Vec<&[u8]> = pack.iter().map(|i| i.unwrap().value).collect();
    assert_eq!(values, [MAIN_TITLE, VERSION_TITLE, SOURCE_ORG]);

    let mut enc = VariableLengthPackEncoder::new(vl_pack_key()).unwrap();
    enc.item(MAIN_TITLE).unwrap().item(VERSION_TITLE).unwrap().item(SOURCE_ORG).unwrap();
    assert_eq!(enc.finish().unwrap(), buf);
}

#[test]
fn annex_g_defined_length_pack() {
    let buf = defined_length_pack();
    let Group::DefinedLengthPack(pack) = group(&buf) else { panic!("wrong group kind") };
    let mut r = pack.reader();
    assert_eq!(r.take_array::<1>().unwrap(), [3]);
    assert_eq!(r.take_rest(), MAIN_TITLE);
    r.finish().unwrap();

    let mut enc = DefinedLengthPackEncoder::new(dl_pack_key()).unwrap();
    enc.item(&[3]).item(MAIN_TITLE);
    assert_eq!(enc.finish().unwrap(), buf);
}

#[test]
fn annex_h_label() {
    let l = label();
    assert_eq!(l.category(), Category::Label);
    assert!(l.is_well_formed());
    assert_eq!(l.group_coding(), None);
}

/// ST 336:2017 section 7.6 note: a group can switch codings by changing only
/// byte 6, the item values staying the same.
#[test]
fn same_group_in_every_coding() {
    let items = [(1u64, MAIN_TITLE), (2, VERSION_TITLE), (3, SOURCE_ORG)];
    let base = local_set_key();

    let local = {
        let mut e = LocalSetEncoder::new(base.with_group_coding(GroupCoding::LocalSet {
            tag: TagEncoding::U16,
            length: LengthEncoding::U32,
        }))
        .unwrap();
        for (t, v) in items {
            e.item(t, v).unwrap();
        }
        e.finish().unwrap()
    };
    let vl = {
        let mut e = VariableLengthPackEncoder::new(
            base.with_group_coding(GroupCoding::VariableLengthPack { length: LengthEncoding::U8 }),
        )
        .unwrap();
        for (_, v) in items {
            e.item(v).unwrap();
        }
        e.finish().unwrap()
    };
    for buf in [&local, &vl] {
        let t = Triplet::parse(buf).unwrap();
        assert_eq!(t.key().item_designator(), base.item_designator());
        let values: Vec<&[u8]> = match t.group().unwrap() {
            Group::Local(s) => s.iter().map(|i| i.unwrap().value).collect(),
            Group::VariableLengthPack(p) => p.iter().map(|i| i.unwrap().value).collect(),
            g => panic!("{g:?}"),
        };
        assert_eq!(values, [MAIN_TITLE, VERSION_TITLE, SOURCE_ORG]);
    }
}

#[test]
fn whole_annex_stream() {
    // All the examples back to back, as a .klv file would hold them.
    let parts = [single_item(), universal_set(), global_set(), local_set(), variable_length_pack(), defined_length_pack()];
    let stream = parts.concat();
    let keys: Vec<UniversalLabel> = Triplets::new(&stream).map(|t| t.unwrap().key()).collect();
    assert_eq!(keys.len(), 6);
    for (t, part) in Triplets::new(&stream).zip(&parts) {
        let t = t.unwrap();
        assert_eq!(t.as_bytes(), &part[..]);
        if let Some(g) = t.group() {
            g.validate().unwrap();
        }
    }
    let mut d = Decoder::new();
    for c in stream.chunks(5) {
        d.push(c);
    }
    let frames: Vec<Vec<u8>> = d.frames().map(Frame::into_bytes).collect();
    assert_eq!(frames, parts);
}
