//! Global Sets (SMPTE ST 336:2017 section 7.3).

use super::{value_end, Group};
use crate::{DecodeOptions, Error, ErrorKind, LengthEncoding, UniversalLabel};

/// Most words (BER-OID sub-identifiers) in a Global Tag.
pub(crate) const MAX_TAG_WORDS: usize = 12;

/// A Global Set: items are keyed by Global Tags that leave out the key bytes
/// every item shares, so every item's full key can be rebuilt from the set
/// alone.
///
/// Bytes 9 to 16 of the set's key are the Global Set Designator: the shared
/// leading bytes of every item key, ended by a zero sub-identifier unless all
/// 8 are used. Each item's Global Tag holds the rest of its key and ends with
/// a zero sub-identifier unless it is 12 words long. An item key is the
/// designator's significant bytes followed by the tag, padded with zeros to
/// 16 bytes. Words are BER-OID sub-identifiers (ST 336:2017 section 5.2.4),
/// so a zero byte that completes a multi-byte word (`81 00` is 128) is part
/// of the designator or tag, not its end.
///
/// The Structure Designator, byte 7 of the set key, is not used: ST 336
/// defines it as 1 plus the number of designator bytes, but the 2007 and
/// 2017 Annex examples disagree on it, and the designator's own zero
/// terminator already gives its length.
///
/// ```
/// use smpte_klv::{GlobalSet, LengthEncoding, UniversalLabel};
///
/// // SMPTE ST 336:2017 Annex D: the designator is 06 0E 2B 34 01 01 01.
/// let key: UniversalLabel = "06.0E.2B.34.02.02.08.01.06.0E.2B.34.01.01.01.00".parse().unwrap();
/// let mut value = vec![0x01, 0x01, 0x05, 0x02, 0x00, 0x10];
/// value.extend(b"Yesterdays World");
/// let set = GlobalSet::new(key, &value, LengthEncoding::Ber);
/// let item = set.iter().next().unwrap().unwrap();
/// assert_eq!(item.key.to_string(), "06.0E.2B.34.01.01.01.01.01.05.02.00.00.00.00.00");
/// assert_eq!(item.tag, &[0x01, 0x01, 0x05, 0x02]);
/// assert_eq!(item.value, b"Yesterdays World");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GlobalSet<'a> {
    value: &'a [u8],
    key: UniversalLabel,
    length: LengthEncoding,
    opts: DecodeOptions,
}

/// One Global Set item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GlobalItem<'a> {
    /// The Global Tag as coded, without its terminating zero.
    pub tag: &'a [u8],
    /// The item's full key, rebuilt from the designator and the tag.
    pub key: UniversalLabel,
    /// The value bytes.
    pub value: &'a [u8],
    /// Offset of the tag's first byte within the set value.
    pub offset: usize,
    /// The whole item as coded: tag, terminator, length field and value.
    pub raw: &'a [u8],
    opts: DecodeOptions,
}

impl<'a> GlobalItem<'a> {
    /// The value as a set or pack, if the rebuilt key declares one.
    pub fn group(&self) -> Option<Group<'a>> {
        Group::new(self.key, self.value, self.opts)
    }
}

/// Significant length of a designator, and whether it is well formed: 2 to 8
/// bytes before its zero sub-identifier, only zeros after it, not ending
/// inside a multi-byte word, and starting with as much of the UL prefix
/// `06 0E 2B 34` as it covers (ST 336:2017 section 7.3: the designator "shall
/// include the UL Header fields").
pub(crate) fn designator_len(d: &[u8; 8]) -> (usize, bool) {
    let n = significant_len(d);
    let shape = n >= 2 && d[n..].iter().all(|&b| b == 0) && d[n - 1] & 0x80 == 0;
    let header = n.min(4);
    (n, shape && d[..header] == UniversalLabel::PREFIX[..header])
}

/// Bytes before the first zero sub-identifier: the first zero byte that does
/// not complete a multi-byte word.
pub(crate) fn significant_len(bytes: &[u8]) -> usize {
    let mut continued = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == 0 && !continued {
            return i;
        }
        continued = b & 0x80 != 0;
    }
    bytes.len()
}

impl<'a> GlobalSet<'a> {
    /// A view of a Global Set value. `key` is the set's key, which carries
    /// the designator; `length` is the item length coding, normally taken
    /// from the key's byte 6 (see [`Group::new`]).
    pub fn new(key: UniversalLabel, value: &'a [u8], length: LengthEncoding) -> Self {
        GlobalSet { value, key, length, opts: DecodeOptions::default() }
    }

    /// The same view with different options.
    #[must_use]
    pub fn with_options(self, opts: DecodeOptions) -> Self {
        GlobalSet { opts, ..self }
    }

    /// The set's value bytes.
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// The options the view was given.
    pub const fn options(&self) -> &DecodeOptions {
        &self.opts
    }

    /// The set's key.
    pub const fn key(&self) -> UniversalLabel {
        self.key
    }

    /// The item length coding.
    pub const fn length_encoding(&self) -> LengthEncoding {
        self.length
    }

    /// The significant bytes of the Global Set Designator.
    pub fn designator(&self) -> &[u8] {
        let d = self.key.item_designator();
        &d[..designator_len(d).0]
    }

    /// True when the designator has 2 to 8 significant bytes followed only
    /// by zeros, does not end inside a multi-byte word, and starts with the
    /// UL header, as ST 336:2017 section 7.3 requires.
    pub fn is_designator_valid(&self) -> bool {
        designator_len(self.key.item_designator()).1
    }

    /// The items in order. With
    /// [`DecodeOptions::strict_global_set`], a malformed designator is
    /// reported as the first item. With [`DecodeOptions::skip_fill`], items
    /// whose rebuilt key is the KLV Fill key are left out.
    pub fn iter(&self) -> GlobalItems<'a> {
        let (len, ok) = designator_len(self.key.item_designator());
        let mut prefix = [0u8; 8];
        prefix[..len].copy_from_slice(&self.key.item_designator()[..len]);
        GlobalItems {
            buf: self.value,
            pos: 0,
            prefix,
            prefix_len: len,
            length: self.length,
            opts: self.opts,
            state: if ok || !self.opts.strict_global_set { State::Items } else { State::BadDesignator },
        }
    }

    /// The first item whose rebuilt key equals `key`, ignoring the version
    /// byte when `ignore_version` is set. Errors before the item is found are
    /// returned.
    pub fn get(&self, key: &UniversalLabel, ignore_version: bool) -> Result<Option<GlobalItem<'a>>, Error> {
        for item in self.iter() {
            let item = item?;
            if item.key == *key || (ignore_version && item.key.eq_ignoring_version(key)) {
                return Ok(Some(item));
            }
        }
        Ok(None)
    }
}

impl<'a> IntoIterator for GlobalSet<'a> {
    type Item = Result<GlobalItem<'a>, Error>;
    type IntoIter = GlobalItems<'a>;

    fn into_iter(self) -> GlobalItems<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &GlobalSet<'a> {
    type Item = Result<GlobalItem<'a>, Error>;
    type IntoIter = GlobalItems<'a>;

    fn into_iter(self) -> GlobalItems<'a> {
        self.iter()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    BadDesignator,
    Items,
    Done,
}

/// Iterator over the items of a [`GlobalSet`]. Yields `Err` once and then
/// stops if an item is malformed or runs past the end of the set.
#[derive(Clone, Debug)]
pub struct GlobalItems<'a> {
    buf: &'a [u8],
    pos: usize,
    prefix: [u8; 8],
    prefix_len: usize,
    length: LengthEncoding,
    opts: DecodeOptions,
    state: State,
}

impl<'a> GlobalItems<'a> {
    /// Offset of the next item, or of the one that failed.
    pub const fn offset(&self) -> usize {
        self.pos
    }

    /// Bytes not yet decoded, starting at [`offset`](Self::offset).
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos.min(self.buf.len())..]
    }

    fn item(&self, rest: &'a [u8]) -> Result<GlobalItem<'a>, Error> {
        let max_tag = 16 - self.prefix_len;
        let (mut i, mut words, mut continued) = (0usize, 0usize, false);
        let (tag_len, consumed) = loop {
            if words == MAX_TAG_WORDS {
                break (i, i);
            }
            let b = *rest.get(i).ok_or(Error::end(i + 1, rest.len()))?;
            if b == 0 && !continued {
                break (i, i + 1);
            }
            if i == max_tag {
                return Err(Error::new(ErrorKind::InvalidGlobalTag, 0));
            }
            // A word may not start with 0x80 (ISO/IEC 8825-1 8.19.2).
            if b == 0x80 && !continued && self.opts.strict_oid {
                return Err(Error::new(ErrorKind::NonMinimalOid, i));
            }
            continued = b & 0x80 != 0;
            words += usize::from(!continued);
            i += 1;
        };
        if tag_len == 0 || (self.opts.strict_global_set && words < 2) {
            return Err(Error::new(ErrorKind::InvalidGlobalTag, 0));
        }
        let mut key = [0u8; 16];
        key[..self.prefix_len].copy_from_slice(&self.prefix[..self.prefix_len]);
        key[self.prefix_len..self.prefix_len + tag_len].copy_from_slice(&rest[..tag_len]);
        let key = UniversalLabel::from_bytes(key);
        // The rebuilt key is a key like any other (ST 336:2017 section 7.3).
        if self.opts.require_smpte_key && !key.is_smpte() {
            return Err(Error::new(ErrorKind::InvalidKey, 0));
        }
        if self.opts.reject_label_keys && key.is_smpte() && key.as_bytes()[4] == 0x04 {
            // Byte 5 came from the tag, or from a designator of 5 or more
            // bytes; report it where the item starts in that case.
            return Err(Error::new(ErrorKind::LabelKey, 4usize.saturating_sub(self.prefix_len)));
        }

        let (len, l) = self.length.decode(&rest[consumed..]).map_err(|e| e.shift(consumed))?;
        let start = consumed + l;
        let end = value_end(rest, start, len, consumed)?;
        Ok(GlobalItem {
            tag: &rest[..tag_len],
            key,
            value: &rest[start..end],
            offset: self.pos,
            raw: &rest[..end],
            opts: self.opts,
        })
    }
}

impl<'a> Iterator for GlobalItems<'a> {
    type Item = Result<GlobalItem<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.state {
                State::Done => return None,
                State::BadDesignator => {
                    self.state = State::Done;
                    return Some(Err(Error::new(ErrorKind::InvalidGlobalSetDesignator, 0)));
                }
                State::Items if self.pos >= self.buf.len() => return None,
                State::Items => {}
            }
            let rest = &self.buf[self.pos..];
            match self.item(rest) {
                Ok(item) => {
                    self.pos += item.raw.len();
                    if self.opts.skip_fill && item.key.is_fill() {
                        continue;
                    }
                    return Some(Ok(item));
                }
                Err(e) => {
                    self.state = State::Done;
                    return Some(Err(e.shift(self.pos).bounded()));
                }
            }
        }
    }
}

impl core::iter::FusedIterator for GlobalItems<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_key(designator: [u8; 8]) -> UniversalLabel {
        let mut k = [0x06, 0x0E, 0x2B, 0x34, 0x02, 0x02, 0x05, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        k[8..].copy_from_slice(&designator);
        UniversalLabel::from_bytes(k)
    }

    const D4: [u8; 8] = [0x06, 0x0E, 0x2B, 0x34, 0, 0, 0, 0];
    const D8: [u8; 8] = [0x06, 0x0E, 0x2B, 0x34, 0x01, 0x01, 0x01, 0x01];

    #[test]
    fn designators() {
        assert_eq!(designator_len(&D4), (4, true));
        assert_eq!(designator_len(&D8), (8, true));
        assert_eq!(designator_len(&[1, 0, 0, 0, 0, 0, 0, 0]), (1, false));
        assert_eq!(designator_len(&[0; 8]), (0, false));
        assert_eq!(designator_len(&[1, 2, 0, 3, 0, 0, 0, 0]), (2, false));
        // Without the UL header.
        assert_eq!(designator_len(&[1, 2, 0, 0, 0, 0, 0, 0]), (2, false));
        assert_eq!(designator_len(&[0x06, 0x0E, 0x2B, 0x35, 0, 0, 0, 0]), (4, false));
        assert_eq!(designator_len(&[0x06, 0x0E, 0, 0, 0, 0, 0, 0]), (2, true));
        // A zero completing a multi-byte word is part of the designator.
        assert_eq!(designator_len(&[0x06, 0x0E, 0x2B, 0x34, 0x81, 0x00, 0x00, 0x00]), (6, true));
        // Ending inside a word.
        assert_eq!(designator_len(&[0x06, 0x0E, 0x2B, 0x34, 0x01, 0x01, 0x01, 0x81]), (8, false));
        let set = GlobalSet::new(set_key(D4), &[], LengthEncoding::Ber);
        assert_eq!(set.iter().remaining(), &[]);
        assert_eq!(set.designator(), &D4[..4]);
        assert!(set.is_designator_valid());
        assert_eq!(set.key(), set_key(D4));
    }

    #[test]
    fn bad_designator_is_reported_unless_lenient() {
        let key = set_key([0x06, 0, 0, 0, 0, 0, 0, 0]);
        let value = [0x0E, 0x2B, 0x34, 0x01, 0x00, 0x01, 0xAA];
        let set = GlobalSet::new(key, &value, LengthEncoding::Ber);
        let mut it = set.iter();
        assert_eq!(it.next(), Some(Err(Error::new(ErrorKind::InvalidGlobalSetDesignator, 0))));
        assert_eq!(it.next(), None);
        let item = set.with_options(DecodeOptions::lenient()).iter().next().unwrap().unwrap();
        assert_eq!(item.key.as_bytes()[..5], [0x06, 0x0E, 0x2B, 0x34, 0x01]);
    }

    #[test]
    fn tags_with_and_without_terminator() {
        // 12 single-byte words fill the key after a 4-byte designator: no
        // terminator, and the next item follows directly.
        let mut value = [0u8; 40];
        let tag12 = [1, 1, 1, 1, 1, 2, 3, 4, 5, 6, 7, 8];
        value[..12].copy_from_slice(&tag12);
        value[12] = 0x01; // length
        value[13] = 0xAA;
        value[14..19].copy_from_slice(&[1, 2, 0, 0x01, 0x22]); // tag 01 02, terminator, length 1
        let set = GlobalSet::new(set_key(D4), &value[..19], LengthEncoding::Ber);
        let items: [_; 2] = {
            let mut it = set.iter();
            [it.next().unwrap().unwrap(), it.next().unwrap().unwrap()]
        };
        assert_eq!(items[0].tag, &tag12);
        assert_eq!(items[0].key.as_bytes()[4..], tag12);
        assert_eq!(items[0].value, &[0xAA]);
        assert_eq!(items[1].offset, 14);
        assert_eq!(items[1].tag, &[1, 2]);
        assert_eq!(items[1].value, &[0x22]);
        assert_eq!(items[1].raw, &value[14..19]);
        assert_eq!(set.iter().count(), 2);
    }

    #[test]
    fn multi_byte_words_keep_their_zero_bytes() {
        // Word 128 is coded 81 00; the 00 is part of it, not a terminator.
        let value = [0x01, 0x81, 0x00, 0x00, 0x01, 0x55];
        let item = GlobalSet::new(set_key(D4), &value, LengthEncoding::Ber).iter().next().unwrap().unwrap();
        assert_eq!(item.tag, &[0x01, 0x81, 0x00]);
        assert_eq!(item.key.as_bytes()[4..8], [0x01, 0x81, 0x00, 0x00]);
        assert_eq!(item.value, &[0x55]);
    }

    #[test]
    fn tag_errors() {
        let set = |v| GlobalSet::new(set_key(D4), v, LengthEncoding::Ber);
        // Empty tag.
        assert_eq!(set(&[0x00, 0x00]).iter().next(), Some(Err(Error::new(ErrorKind::InvalidGlobalTag, 0))));
        // One word: too short when strict, fine when lenient.
        assert_eq!(set(&[0x01, 0x00, 0x00]).iter().next(), Some(Err(Error::new(ErrorKind::InvalidGlobalTag, 0))));
        let lenient = set(&[0x01, 0x00, 0x00]).with_options(DecodeOptions::lenient());
        assert_eq!(lenient.iter().next().unwrap().unwrap().tag, &[1]);
        // Longer than the key has room for (12 bytes after a 4-byte
        // designator, the 12th byte not ending a word).
        let mut long = [0x81u8; 14];
        long[13] = 0;
        assert_eq!(set(&long).iter().next(), Some(Err(Error::new(ErrorKind::InvalidGlobalTag, 0))));
        // An 8-byte designator leaves room for 8 tag bytes, then a terminator.
        let s8 = GlobalSet::new(set_key(D8), &[1, 2, 3, 4, 5, 6, 7, 8, 9], LengthEncoding::Ber);
        assert_eq!(s8.iter().next(), Some(Err(Error::new(ErrorKind::InvalidGlobalTag, 0))));
        let ok = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0];
        let s8 = GlobalSet::new(set_key(D8), &ok, LengthEncoding::Ber);
        assert_eq!(s8.iter().next().unwrap().unwrap().key.as_bytes()[8..], [1, 2, 3, 4, 5, 6, 7, 8]);
        // Cut off by the end of the set inside the tag, the length and the
        // value: not something more input could fix.
        assert_eq!(set(&[0x01, 0x02]).iter().next(), Some(Err(Error::overrun(3, 2))));
        assert_eq!(set(&[0x01, 0x02, 0x00]).iter().next(), Some(Err(Error::overrun(4, 3))));
        assert_eq!(set(&[0x01, 0x02, 0x00, 0x02, 0x00]).iter().next(), Some(Err(Error::overrun(6, 5))));
        let mut it = set(&[0x01, 0x02, 0x00, 0x00, 0x01, 0x02]).iter();
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.remaining(), &[0x01, 0x02]);
        assert_eq!(it.next(), Some(Err(Error::overrun(7, 6))));
        // A word padded with 0x80 is rejected when strict.
        assert_eq!(set(&[0x01, 0x80, 0x05, 0x00, 0x00]).iter().next(), Some(Err(Error::new(ErrorKind::NonMinimalOid, 1))));
        let lenient = set(&[0x01, 0x80, 0x05, 0x00, 0x00]).with_options(DecodeOptions::lenient());
        assert_eq!(lenient.iter().next().unwrap().unwrap().tag, &[0x01, 0x80, 0x05]);
    }

    #[test]
    fn rebuilt_keys_must_be_smpte() {
        // A 2-byte designator leaves the rest of the prefix to the tag.
        let d2 = [0x06, 0x0E, 0, 0, 0, 0, 0, 0];
        let value = [0x2B, 0x35, 0x01, 0x00, 0x00];
        let set = GlobalSet::new(set_key(d2), &value, LengthEncoding::Ber);
        assert_eq!(set.iter().next(), Some(Err(Error::new(ErrorKind::InvalidKey, 0))));
        let opts = DecodeOptions { require_smpte_key: false, ..DecodeOptions::strict() };
        assert!(set.with_options(opts).iter().next().unwrap().is_ok());
        let value = [0x2B, 0x34, 0x01, 0x00, 0x00];
        let item = GlobalSet::new(set_key(d2), &value, LengthEncoding::Ber).iter().next().unwrap().unwrap();
        assert!(item.key.is_smpte());
    }

    #[test]
    fn labels_are_not_item_keys() {
        // Designator 06 0E 2B 34; the tag rebuilds the Annex H label.
        let value = [0x04, 1, 1, 1, 0x04, 1, 1, 1, 1, 1, 0x00, 0x01, 0xAA];
        let set = GlobalSet::new(set_key(D4), &value, LengthEncoding::Ber);
        assert_eq!(set.iter().next(), Some(Err(Error::new(ErrorKind::LabelKey, 0))));
        let item = set.with_options(DecodeOptions::lenient()).iter().next().unwrap().unwrap();
        assert_eq!(item.key.category(), crate::Category::Label);
    }

    #[test]
    fn fill_items_can_be_skipped() {
        // Designator 06 0E 2B 34 01 01 01; the Fill key's tail is 02 03 01 02 10 01.
        let d = [0x06, 0x0E, 0x2B, 0x34, 0x01, 0x01, 0x01, 0];
        let value = [0x02, 0x03, 0x01, 0x02, 0x10, 0x01, 0x00, 0x02, 0, 0, 0x01, 0x05, 0x02, 0x00, 0x01, 0xAA];
        let set = GlobalSet::new(set_key(d), &value, LengthEncoding::Ber);
        let first = set.iter().next().unwrap().unwrap();
        assert!(first.key.is_fill());
        let mut opts = DecodeOptions::default();
        opts.skip_fill = true;
        let mut it = set.with_options(opts).iter();
        assert_eq!(it.next().unwrap().unwrap().value, &[0xAA]);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn fixed_lengths_and_lookup() {
        let value = [0x01, 0x02, 0x00, 0x00, 0x02, 0xA, 0xB, 0x03, 0x04, 0x00, 0x00, 0x00];
        let set = GlobalSet::new(set_key(D4), &value, LengthEncoding::U16);
        let items: usize = set.into_iter().map(|i| i.unwrap().value.len()).sum();
        assert_eq!(items, 2);
        let mut k = [0u8; 16];
        k[..4].copy_from_slice(&D4[..4]);
        k[4..6].copy_from_slice(&[3, 4]);
        let key = UniversalLabel::from_bytes(k);
        assert_eq!(set.get(&key, false).unwrap().unwrap().offset, 7);
        assert_eq!(set.get(&key.with_version(9), false).unwrap(), None);
        assert!(set.get(&UniversalLabel::from_bytes([0; 16]), true).unwrap().is_none());
        // An error before the item is found is returned.
        let broken = GlobalSet::new(set_key(D4), &value[..6], LengthEncoding::U16);
        assert!(broken.get(&key, false).is_err());
        assert_eq!((&set).into_iter().count(), 2);
    }

    #[test]
    fn nested_groups() {
        // An item whose rebuilt key is a Local Set key.
        let d = [0x06, 0x0E, 0x2B, 0x34, 0x02, 0x03, 0, 0];
        let value = [0x01, 0x01, 0x00, 0x03, 0x07, 0x01, 0xEE];
        let item = GlobalSet::new(set_key(d), &value, LengthEncoding::Ber).iter().next().unwrap().unwrap();
        let Some(Group::Local(inner)) = item.group() else { panic!("not a local set") };
        assert_eq!(inner.iter().next().unwrap().unwrap().tag, 7);
    }
}
