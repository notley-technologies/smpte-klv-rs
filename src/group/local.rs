//! Local Sets (SMPTE ST 336:2017 section 7.4).

use super::value_end;
use crate::{DecodeOptions, Error, LengthEncoding, TagEncoding};

/// A Local Set: items are keyed by short local tags, whose meaning a defining
/// document gives, in any order.
///
/// Tags and lengths are coded as byte 6 of the set's key declares (SMPTE ST
/// 336:2017 Table 5): MISB ST 0601 uses BER-OID tags with BER lengths
/// (`0x0B`), MXF header metadata 2-byte tags with 2-byte lengths (`0x53`).
///
/// ```
/// use smpte_klv::{LengthEncoding, LocalSet, TagEncoding};
///
/// let value = [0x02, 0x01, 0xAA, 0x81, 0x01, 0x02, 0xBB, 0xCC];
/// let set = LocalSet::new(&value, TagEncoding::BerOid, LengthEncoding::Ber);
/// let items: Vec<(u64, &[u8])> = set.iter().map(|i| i.map(|i| (i.tag, i.value))).collect::<Result<_, _>>().unwrap();
/// assert_eq!(items, [(2, &[0xAA][..]), (129, &[0xBB, 0xCC][..])]);
/// assert_eq!(set.get(129).unwrap().unwrap().offset, 3);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LocalSet<'a> {
    value: &'a [u8],
    tag: TagEncoding,
    length: LengthEncoding,
    opts: DecodeOptions,
}

/// One Local Set item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct LocalItem<'a> {
    /// The local tag.
    pub tag: u64,
    /// The value bytes.
    pub value: &'a [u8],
    /// Offset of the tag's first byte within the set value.
    pub offset: usize,
    /// The whole item as coded: tag, length field and value. Checksums such
    /// as MISB ST 0601's cover these bytes.
    pub raw: &'a [u8],
}

impl<'a> LocalSet<'a> {
    /// A view of a Local Set value with the given tag and length codings.
    pub fn new(value: &'a [u8], tag: TagEncoding, length: LengthEncoding) -> Self {
        LocalSet { value, tag, length, opts: DecodeOptions::default() }
    }

    /// The same view with different options.
    #[must_use]
    pub fn with_options(self, opts: DecodeOptions) -> Self {
        LocalSet { opts, ..self }
    }

    /// The set's value bytes.
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// The options the view was given.
    pub const fn options(&self) -> &DecodeOptions {
        &self.opts
    }

    /// The tag coding.
    pub const fn tag_encoding(&self) -> TagEncoding {
        self.tag
    }

    /// The item length coding.
    pub const fn length_encoding(&self) -> LengthEncoding {
        self.length
    }

    /// The items in order.
    pub fn iter(&self) -> LocalItems<'a> {
        LocalItems { set: *self, pos: 0, done: false }
    }

    /// The first item with `tag`. Errors before the item is found are
    /// returned. ST 336 leaves repeated tags to the defining document; use
    /// [`iter`](Self::iter) to see them all.
    pub fn get(&self, tag: u64) -> Result<Option<LocalItem<'a>>, Error> {
        for item in self.iter() {
            let item = item?;
            if item.tag == tag {
                return Ok(Some(item));
            }
        }
        Ok(None)
    }
}

impl<'a> IntoIterator for LocalSet<'a> {
    type Item = Result<LocalItem<'a>, Error>;
    type IntoIter = LocalItems<'a>;

    fn into_iter(self) -> LocalItems<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &LocalSet<'a> {
    type Item = Result<LocalItem<'a>, Error>;
    type IntoIter = LocalItems<'a>;

    fn into_iter(self) -> LocalItems<'a> {
        self.iter()
    }
}

/// Iterator over the items of a [`LocalSet`]. Yields `Err` once and then
/// stops if an item is malformed or runs past the end of the set
/// ([`ErrorKind::Overrun`](crate::ErrorKind::Overrun)).
#[derive(Clone, Debug)]
pub struct LocalItems<'a> {
    set: LocalSet<'a>,
    pos: usize,
    done: bool,
}

impl<'a> LocalItems<'a> {
    /// Offset of the next item, or of the one that failed.
    pub const fn offset(&self) -> usize {
        self.pos
    }

    /// Bytes not yet decoded, starting at [`offset`](Self::offset).
    pub fn remaining(&self) -> &'a [u8] {
        &self.set.value[self.pos..]
    }

    fn item(&self, rest: &'a [u8]) -> Result<LocalItem<'a>, Error> {
        // Fast path for the common case of a one-byte tag and a short-form
        // BER length (MISB ST 0601 and most Local Sets); it decodes exactly
        // as the general path below would.
        if let [t, l, ..] = *rest {
            let one_byte_tag = matches!(self.set.tag, TagEncoding::BerOid | TagEncoding::U8);
            if one_byte_tag && t < 0x80 && l < 0x80 && self.set.length == LengthEncoding::Ber {
                let end = 2 + usize::from(l);
                if let (Some(value), Some(raw)) = (rest.get(2..end), rest.get(..end)) {
                    return Ok(LocalItem { tag: u64::from(t), value, offset: self.pos, raw });
                }
            }
        }
        let (tag, t) = self.set.tag.decode(rest, self.set.opts.strict_oid)?;
        let (len, l) = self.set.length.decode(&rest[t..]).map_err(|e| e.shift(t))?;
        let start = t + l;
        let end = value_end(rest, start, len, t)?;
        Ok(LocalItem { tag, value: &rest[start..end], offset: self.pos, raw: &rest[..end] })
    }
}

impl<'a> Iterator for LocalItems<'a> {
    type Item = Result<LocalItem<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.pos >= self.set.value.len() {
            return None;
        }
        match self.item(&self.set.value[self.pos..]) {
            Ok(item) => {
                self.pos += item.raw.len();
                Some(Ok(item))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e.shift(self.pos).bounded()))
            }
        }
    }
}

impl core::iter::FusedIterator for LocalItems<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    fn every_coding_decodes() {
        // Tag 0x0102 / length 3 in each fixed coding, then BER.
        let cases: [(TagEncoding, LengthEncoding, &[u8]); 4] = [
            (TagEncoding::U16, LengthEncoding::U16, &[0x01, 0x02, 0x00, 0x03, 7, 8, 9]),
            (TagEncoding::U32, LengthEncoding::U32, &[0, 0, 0x01, 0x02, 0, 0, 0, 3, 7, 8, 9]),
            (TagEncoding::BerOid, LengthEncoding::U8, &[0x82, 0x02, 0x03, 7, 8, 9]),
            (TagEncoding::U16, LengthEncoding::Ber, &[0x01, 0x02, 0x83, 0, 0, 3, 7, 8, 9]),
        ];
        for (tag, length, value) in cases {
            let set = LocalSet::new(value, tag, length);
            assert_eq!(set.tag_encoding(), tag);
            assert_eq!(set.length_encoding(), length);
            let item = set.iter().next().unwrap().unwrap();
            assert_eq!((item.tag, item.value, item.raw), (0x0102, &[7u8, 8, 9][..], value), "{tag:?} {length:?}");
            assert_eq!(set.iter().count(), 1);
        }
    }

    #[test]
    fn stops_after_an_error() {
        let value = [0x02, 0x01, 0xAA, 0x03, 0x05, 0x01];
        let set = LocalSet::new(&value, TagEncoding::U8, LengthEncoding::Ber);
        let mut it = set.iter();
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.remaining(), &[0x03, 0x05, 0x01]);
        assert_eq!(it.next(), Some(Err(Error::overrun(10, 6))));
        assert_eq!(it.offset(), 3);
        assert_eq!(it.next(), None);
        assert!(set.get(9).is_err());
        assert_eq!(set.get(2).unwrap().unwrap().value, &[0xAA]);

        let ber = |v| LocalSet::new(v, TagEncoding::BerOid, LengthEncoding::Ber).iter().next();
        assert_eq!(ber(&[0x02, 0x80]), Some(Err(Error::new(ErrorKind::IndefiniteLength, 1))));
        assert_eq!(ber(&[0x02, 0xFF]), Some(Err(Error::new(ErrorKind::ReservedLength, 1))));
        assert_eq!(ber(&[0x82]), Some(Err(Error::overrun(2, 1))));
        assert_eq!(ber(&[0x02, 0x82, 0x01]), Some(Err(Error::overrun(4, 3))));
        assert_eq!(ber(&[0x80, 0x02, 0x00]), Some(Err(Error::new(ErrorKind::NonMinimalOid, 0))));
        let huge = [0x02, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(ber(&huge), Some(Err(Error::new(ErrorKind::LengthOverflow, 1))));
    }

    #[test]
    fn empty_and_zero_length_items() {
        assert_eq!(LocalSet::new(&[], TagEncoding::U8, LengthEncoding::Ber).iter().count(), 0);
        let set = LocalSet::new(&[0x05, 0x00, 0x06, 0x00], TagEncoding::U8, LengthEncoding::Ber);
        let tags: usize = set.into_iter().map(|i| i.unwrap().tag as usize).sum();
        assert_eq!(tags, 11);
        assert_eq!((&set).into_iter().count(), 2);
        assert_eq!(set.get(7), Ok(None));
    }
}
