//! Sets and packs (SMPTE ST 336:2017 section 7).
//!
//! A group is a triplet whose key has byte 5 set to `0x02`. Byte 6 says how
//! the items in its value are coded ([`GroupCoding`]); [`Group::new`] and
//! [`Triplet::group`](crate::Triplet::group) pick the right decoder from it.
//! Every decoder is a cheap view over the value: items are decoded lazily by
//! iterators that borrow from the input and allocate nothing.
//!
//! Sets and packs may contain further sets and packs (ST 336 "recursive
//! coding"). For Universal and Global Sets each item's key says whether it is
//! a group, so [`Triplet::group`](crate::Triplet::group) and
//! [`GlobalItem::group`] descend; for Local Sets and packs only the defining
//! document knows, so decode an item's value with the matching type
//! yourself. Nothing here recurses on its own, so hostile nesting depth
//! cannot exhaust the stack.

pub(crate) mod global;
mod local;
mod pack;
mod universal;

pub use global::{GlobalItem, GlobalItems, GlobalSet};
pub use local::{LocalItem, LocalItems, LocalSet};
pub use pack::{DefinedItems, DefinedLengthPack, PackItem, PackItems, PackReader, VariableLengthPack};
pub use universal::UniversalSet;

use crate::error::MAX_LEN;
use crate::{DecodeOptions, Error, ErrorKind, GroupCoding, UniversalLabel};

/// A set or pack, decoded according to byte 6 of its key.
///
/// Every view is cheap and borrows the value; items are decoded lazily by
/// iterators that allocate nothing. Sets and packs may contain further sets
/// and packs (ST 336 "recursive coding"). For Universal and Global Sets each
/// item's key says whether it is a group, so
/// [`Triplet::group`](crate::Triplet::group) and [`GlobalItem::group`]
/// descend one level; for Local Sets and packs only the defining document
/// knows, so decode an item's value with the matching type yourself.
/// Nothing here recurses on its own: a caller walking nested groups should
/// bound the depth it follows, so that hostile nesting cannot exhaust its
/// stack.
///
/// ```
/// use smpte_klv::{Group, Triplet};
///
/// // SMPTE ST 336:2017 Annex E: a Local Set with 1-byte tags, BER lengths.
/// let mut buf = vec![0x06, 0x0E, 0x2B, 0x34, 0x02, 0x03, 1, 1, 0x0F, 1, 1, 1, 0, 0, 0, 0, 0x31];
/// for (tag, text) in [(1, &b"Yesterdays World"[..]), (2, b"International Edition"), (3, b"WXYZ15")] {
///     buf.extend([tag, text.len() as u8]);
///     buf.extend(text);
/// }
/// let packet = Triplet::parse(&buf).unwrap();
/// let Some(Group::Local(set)) = packet.group() else { panic!("not a local set") };
/// let tags: Vec<u64> = set.iter().map(|item| item.unwrap().tag).collect();
/// assert_eq!(tags, [1, 2, 3]);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group<'a> {
    /// Section 7.2.
    Universal(UniversalSet<'a>),
    /// Section 7.3.
    Global(GlobalSet<'a>),
    /// Section 7.4.
    Local(LocalSet<'a>),
    /// Section 7.5.
    VariableLengthPack(VariableLengthPack<'a>),
    /// Section 7.6.
    DefinedLengthPack(DefinedLengthPack<'a>),
}

impl<'a> Group<'a> {
    /// The group `key` declares, over `value`. `None` when the key is not a
    /// SMPTE group key or declares a coding ST 336 does not define; ST
    /// 336:2017 section 5.2.1 says to hand such values to the application
    /// uninterpreted. Use [`with_coding`](Self::with_coding) for a key that
    /// is not a SMPTE universal label.
    pub fn new(key: UniversalLabel, value: &'a [u8], opts: DecodeOptions) -> Option<Group<'a>> {
        Some(Group::with_coding(key, key.group_coding()?, value, opts))
    }

    /// The group over `value`, decoded with `coding` whatever the key's byte
    /// 6 says. For data whose key misstates its own coding, which the
    /// defining document then has to say.
    pub fn with_coding(key: UniversalLabel, coding: GroupCoding, value: &'a [u8], opts: DecodeOptions) -> Group<'a> {
        match coding {
            GroupCoding::UniversalSet => Group::Universal(UniversalSet::new(value).with_options(opts)),
            GroupCoding::GlobalSet { length } => Group::Global(GlobalSet::new(key, value, length).with_options(opts)),
            GroupCoding::LocalSet { tag, length } => Group::Local(LocalSet::new(value, tag, length).with_options(opts)),
            GroupCoding::VariableLengthPack { length } => {
                Group::VariableLengthPack(VariableLengthPack::new(value, length).with_options(opts))
            }
            GroupCoding::DefinedLengthPack => Group::DefinedLengthPack(DefinedLengthPack::new(value).with_options(opts)),
        }
    }

    /// The group's value bytes.
    pub fn value(&self) -> &'a [u8] {
        match self {
            Group::Universal(g) => g.value(),
            Group::Global(g) => g.value(),
            Group::Local(g) => g.value(),
            Group::VariableLengthPack(g) => g.value(),
            Group::DefinedLengthPack(g) => g.value(),
        }
    }

    /// The coding the group is decoded with.
    pub fn coding(&self) -> GroupCoding {
        match self {
            Group::Universal(_) => GroupCoding::UniversalSet,
            Group::Global(g) => GroupCoding::GlobalSet { length: g.length_encoding() },
            Group::Local(g) => GroupCoding::LocalSet { tag: g.tag_encoding(), length: g.length_encoding() },
            Group::VariableLengthPack(g) => GroupCoding::VariableLengthPack { length: g.length_encoding() },
            Group::DefinedLengthPack(_) => GroupCoding::DefinedLengthPack,
        }
    }

    /// Check that every item of the group decodes, without looking at the
    /// values. Packs are checked as far as ST 336 allows: a Variable-Length
    /// Pack's items must fill its value exactly, and a Defined-Length Pack
    /// cannot be checked without its definition.
    pub fn validate(&self) -> Result<(), Error> {
        fn all<T>(it: impl Iterator<Item = Result<T, Error>>) -> Result<(), Error> {
            it.map(|r| r.map(|_| ())).collect()
        }
        match self {
            Group::Universal(g) => all(g.iter()),
            Group::Global(g) => all(g.iter()),
            Group::Local(g) => all(g.iter()),
            Group::VariableLengthPack(g) => all(g.iter()),
            Group::DefinedLengthPack(_) => Ok(()),
        }
    }
}

/// End offset of a value of `len` bytes starting at `start` in `buf`, or the
/// error for a length that does not fit. `field` is the offset of the length
/// field, where overflow is reported.
/// `buf` is a whole set or pack value (or what is left of it), so running
/// past its end is an [`ErrorKind::Overrun`].
pub(crate) fn value_end(buf: &[u8], start: usize, len: u64, field: usize) -> Result<usize, Error> {
    let end = usize::try_from(len)
        .ok()
        .and_then(|n| start.checked_add(n))
        .filter(|&end| end <= MAX_LEN)
        .ok_or(Error::new(ErrorKind::LengthOverflow, field))?;
    if buf.len() < end {
        return Err(Error::overrun(end, buf.len()));
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LengthEncoding, TagEncoding};

    fn key(b6: u8) -> UniversalLabel {
        UniversalLabel::from_bytes([6, 0x0E, 0x2B, 0x34, 2, b6, 1, 1, 0x0F, 1, 1, 1, 0, 0, 0, 0])
    }

    #[test]
    fn dispatch_follows_byte_6() {
        let o = DecodeOptions::default();
        assert!(matches!(Group::new(key(0x01), &[], o), Some(Group::Universal(_))));
        assert!(matches!(Group::new(key(0x22), &[], o), Some(Group::Global(_))));
        assert!(matches!(Group::new(key(0x53), &[], o), Some(Group::Local(_))));
        assert!(matches!(Group::new(key(0x44), &[], o), Some(Group::VariableLengthPack(_))));
        assert!(matches!(Group::new(key(0x05), &[], o), Some(Group::DefinedLengthPack(_))));
        assert_eq!(Group::new(key(0x06), &[], o), None);
        let rewritten = key(0x0B).with_group_coding(GroupCoding::UniversalSet).with_version(1);
        assert_eq!(Group::new(rewritten, &[], o).map(|g| g.coding()), Some(GroupCoding::UniversalSet));
        let mut dict = key(0x03).to_bytes();
        dict[4] = 1;
        assert_eq!(Group::new(UniversalLabel::from_bytes(dict), &[], o), None);
        for b in 0..=255u8 {
            if let Some(g) = Group::new(key(b), &[1, 2], o) {
                assert_eq!(g.coding().registry_designator(), b);
                assert_eq!(g.value(), &[1, 2]);
            }
        }
    }

    #[test]
    fn with_coding_overrides_the_key() {
        let g = Group::with_coding(
            key(0x03),
            GroupCoding::LocalSet { tag: TagEncoding::BerOid, length: LengthEncoding::Ber },
            &[0x81, 0x01, 0x00],
            DecodeOptions::default(),
        );
        let Group::Local(set) = g else { panic!() };
        assert_eq!(set.iter().next().unwrap().unwrap().tag, 129);
    }

    #[test]
    fn validate() {
        let o = DecodeOptions::default();
        assert_eq!(Group::new(key(0x03), &[1, 1, 0xAA, 2, 0], o).unwrap().validate(), Ok(()));
        let overrun = Group::new(key(0x03), &[1, 2, 0xAA], o).unwrap().validate().unwrap_err();
        assert_eq!(overrun, Error::overrun(4, 3));
        assert!(!overrun.is_incomplete(), "a set's size is fixed, so more input cannot help");
        assert_eq!(Group::new(key(0x05), &[1, 2, 3], o).unwrap().validate(), Ok(()));
        // Only SMPTE keys declare groups.
        let mut private = key(0x03).to_bytes();
        private[3] = 0x35;
        assert_eq!(Group::new(UniversalLabel::from_bytes(private), &[], o), None);
    }

    #[test]
    fn value_end_bounds() {
        assert_eq!(value_end(&[0; 4], 1, 3, 0), Ok(4));
        assert_eq!(value_end(&[0; 4], 1, 4, 0), Err(Error::overrun(5, 4)));
        assert_eq!(value_end(&[0; 4], 1, u64::MAX, 0), Err(Error::new(ErrorKind::LengthOverflow, 0)));
        assert_eq!(value_end(&[0; 4], 1, MAX_LEN as u64, 2), Err(Error::new(ErrorKind::LengthOverflow, 2)));
        assert_eq!(value_end(&[0; 4], 0, MAX_LEN as u64, 2), Err(Error::overrun(MAX_LEN, 4)));
    }
}
