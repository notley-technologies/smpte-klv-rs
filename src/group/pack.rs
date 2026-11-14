//! Variable-Length Packs and Defined-Length Packs (SMPTE ST 336:2017
//! sections 7.5 and 7.6).

use super::value_end;
use crate::error::MAX_LEN;
use crate::{DecodeOptions, Error, ErrorKind, LengthEncoding};

/// A Variable-Length Pack: items are a length and a value, with no key or
/// tag, in the order the defining document gives.
///
/// ```
/// use smpte_klv::{LengthEncoding, VariableLengthPack};
///
/// let value = [0x02, b'h', b'i', 0x00, 0x01, b'!'];
/// let pack = VariableLengthPack::new(&value, LengthEncoding::Ber);
/// let items: Vec<&[u8]> = pack.iter().map(|i| i.unwrap().value).collect();
/// assert_eq!(items, [&b"hi"[..], b"", b"!"]);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VariableLengthPack<'a> {
    value: &'a [u8],
    length: LengthEncoding,
    opts: DecodeOptions,
}

/// One pack item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PackItem<'a> {
    /// Position of the item in the pack, from 0.
    pub index: usize,
    /// The value bytes.
    pub value: &'a [u8],
    /// Offset of the item's first byte within the pack value.
    pub offset: usize,
    /// The whole item as coded: length field (if any) and value.
    pub raw: &'a [u8],
}

impl<'a> VariableLengthPack<'a> {
    /// A view of a Variable-Length Pack value with the given length coding.
    pub fn new(value: &'a [u8], length: LengthEncoding) -> Self {
        VariableLengthPack { value, length, opts: DecodeOptions::default() }
    }

    /// The same view with different options. No option changes how a pack
    /// decodes; they are carried so that code decoding the items further can
    /// read them back with [`options`](Self::options).
    #[must_use]
    pub fn with_options(self, opts: DecodeOptions) -> Self {
        VariableLengthPack { opts, ..self }
    }

    /// The pack's value bytes.
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// The item length coding.
    pub const fn length_encoding(&self) -> LengthEncoding {
        self.length
    }

    /// The options the view was given.
    pub const fn options(&self) -> &DecodeOptions {
        &self.opts
    }

    /// The items in order.
    pub fn iter(&self) -> PackItems<'a> {
        PackItems { buf: self.value, length: self.length, pos: 0, index: 0, done: false }
    }

    /// Item number `index`, counting from 0. Errors before it are returned.
    pub fn get(&self, index: usize) -> Result<Option<PackItem<'a>>, Error> {
        for item in self.iter() {
            let item = item?;
            if item.index == index {
                return Ok(Some(item));
            }
        }
        Ok(None)
    }
}

impl<'a> IntoIterator for VariableLengthPack<'a> {
    type Item = Result<PackItem<'a>, Error>;
    type IntoIter = PackItems<'a>;

    fn into_iter(self) -> PackItems<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &VariableLengthPack<'a> {
    type Item = Result<PackItem<'a>, Error>;
    type IntoIter = PackItems<'a>;

    fn into_iter(self) -> PackItems<'a> {
        self.iter()
    }
}

/// Iterator over the items of a [`VariableLengthPack`]. Yields `Err` once and
/// then stops if an item is malformed or runs past the end of the pack
/// ([`ErrorKind::Overrun`]).
#[derive(Clone, Debug)]
pub struct PackItems<'a> {
    buf: &'a [u8],
    length: LengthEncoding,
    pos: usize,
    index: usize,
    done: bool,
}

impl<'a> PackItems<'a> {
    /// Offset of the next item, or of the one that failed.
    pub const fn offset(&self) -> usize {
        self.pos
    }

    /// Bytes not yet decoded, starting at [`offset`](Self::offset).
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos.min(self.buf.len())..]
    }

    fn item(&self, rest: &'a [u8]) -> Result<PackItem<'a>, Error> {
        let (len, l) = self.length.decode(rest)?;
        let end = value_end(rest, l, len, 0)?;
        Ok(PackItem { index: self.index, value: &rest[l..end], offset: self.pos, raw: &rest[..end] })
    }
}

impl<'a> Iterator for PackItems<'a> {
    type Item = Result<PackItem<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.pos >= self.buf.len() {
            return None;
        }
        match self.item(&self.buf[self.pos..]) {
            Ok(item) => {
                self.pos += item.raw.len();
                self.index += 1;
                Some(Ok(item))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e.shift(self.pos).bounded()))
            }
        }
    }
}

impl core::iter::FusedIterator for PackItems<'_> {}

/// A Defined-Length Pack: items are bare values whose order and lengths the
/// defining document gives. Only the pack's overall length is coded.
///
/// ST 336:2017 section 7.6 allows items whose length is found by parsing
/// them, so a pack is read with a [`PackReader`] that takes items one at a
/// time, or with [`split`](Self::split) when every length is known:
///
/// ```
/// use smpte_klv::DefinedLengthPack;
///
/// // SMPTE ST 336:2017 Annex G: Copy Count (UInt8) then Main Title, which
/// // runs to the end of the pack.
/// let mut value = vec![0x03];
/// value.extend(b"Yesterdays World");
/// let mut r = DefinedLengthPack::new(&value).reader();
/// let [copy_count] = r.take_array::<1>().unwrap();
/// let title = r.take_rest();
/// assert_eq!((copy_count, title), (3, &b"Yesterdays World"[..]));
/// r.finish().unwrap();
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DefinedLengthPack<'a> {
    value: &'a [u8],
    opts: DecodeOptions,
}

impl<'a> DefinedLengthPack<'a> {
    /// A view of a Defined-Length Pack value.
    pub const fn new(value: &'a [u8]) -> Self {
        DefinedLengthPack { value, opts: DecodeOptions::strict() }
    }

    /// The same view with different options. As for
    /// [`VariableLengthPack::with_options`], no option changes how a pack
    /// decodes; they are carried for code that decodes the items further.
    #[must_use]
    pub const fn with_options(self, opts: DecodeOptions) -> Self {
        DefinedLengthPack { value: self.value, opts }
    }

    /// The options the view was given.
    pub const fn options(&self) -> &DecodeOptions {
        &self.opts
    }

    /// The pack's value bytes.
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// A reader positioned at the first item.
    pub const fn reader(&self) -> PackReader<'a> {
        PackReader { buf: self.value, pos: 0 }
    }

    /// The items, given each one's length in order. ST 336:2017 section 7.6
    /// says the items make up the whole pack, so the iterator ends with an
    /// `Err` if the pack is too short for an item ([`ErrorKind::Overrun`])
    /// or has bytes left after the last length
    /// ([`ErrorKind::TrailingBytes`]).
    ///
    /// ```
    /// use smpte_klv::{DefinedLengthPack, ErrorKind};
    ///
    /// let pack = DefinedLengthPack::new(&[1, 2, 3, 4, 5]);
    /// let items: Vec<&[u8]> = pack.split(&[1, 4]).map(|i| i.unwrap().value).collect();
    /// assert_eq!(items, [&[1][..], &[2, 3, 4, 5]]);
    ///
    /// let last = pack.split(&[1, 3]).last().unwrap();
    /// assert_eq!(last.unwrap_err().kind(), ErrorKind::TrailingBytes { count: 1 });
    /// ```
    pub fn split<'l>(&self, lengths: &'l [usize]) -> DefinedItems<'a, 'l> {
        DefinedItems { reader: self.reader(), lengths, index: 0, done: false }
    }
}

/// Reads the items of a [`DefinedLengthPack`] in order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PackReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PackReader<'a> {
    /// The next `n` bytes as one item. Fails with [`ErrorKind::Overrun`]
    /// if the pack does not have them, and takes nothing.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= MAX_LEN)
            .ok_or(Error::new(ErrorKind::LengthOverflow, self.pos))?;
        let item = self.buf.get(self.pos..end).ok_or(Error::overrun(end, self.buf.len()))?;
        self.pos = end;
        Ok(item)
    }

    /// The next `N` bytes as an array, for fixed-size items.
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    /// Everything that is left, as one item.
    pub fn take_rest(&mut self) -> &'a [u8] {
        let rest = &self.buf[self.pos..];
        self.pos = self.buf.len();
        rest
    }

    /// Bytes not yet taken.
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Offset of the next item within the pack value.
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Check that every byte was taken; leftovers are
    /// [`ErrorKind::TrailingBytes`].
    pub fn finish(&self) -> Result<(), Error> {
        match self.buf.len() - self.pos {
            0 => Ok(()),
            count => Err(Error::new(ErrorKind::TrailingBytes { count }, self.pos)),
        }
    }
}

/// Iterator returned by [`DefinedLengthPack::split`].
#[derive(Clone, Debug)]
pub struct DefinedItems<'a, 'l> {
    reader: PackReader<'a>,
    lengths: &'l [usize],
    index: usize,
    done: bool,
}

impl<'a> DefinedItems<'a, '_> {
    /// Offset of the next item within the pack value.
    pub const fn position(&self) -> usize {
        self.reader.position()
    }

    /// Bytes not yet taken.
    pub fn remaining(&self) -> &'a [u8] {
        self.reader.remaining()
    }
}

impl<'a> Iterator for DefinedItems<'a, '_> {
    type Item = Result<PackItem<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let Some(&n) = self.lengths.get(self.index) else {
            self.done = true;
            return self.reader.finish().err().map(Err);
        };
        let offset = self.reader.position();
        match self.reader.take(n) {
            Ok(value) => {
                let item = PackItem { index: self.index, value, offset, raw: value };
                self.index += 1;
                Some(Ok(item))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

impl core::iter::FusedIterator for DefinedItems<'_, '_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_length_pack_items() {
        let value = [0x00, 0x02, 0xAA, 0xBB, 0x01, 0xCC];
        let pack = VariableLengthPack::new(&value, LengthEncoding::U16);
        assert_eq!(pack.length_encoding(), LengthEncoding::U16);
        assert_eq!(pack.value(), &value);
        let items: [PackItem; 1] = [pack.iter().next().unwrap().unwrap()];
        assert_eq!(items[0].index, 0);
        assert_eq!(items[0].value, &[0xAA, 0xBB]);
        let mut it = pack.iter();
        it.next();
        assert_eq!(it.offset(), 4);
        assert_eq!(it.remaining(), &[0x01, 0xCC]);
        // 0x01CC is far longer than what is left.
        assert_eq!(it.next(), Some(Err(Error::overrun(4 + 2 + 0x01CC, 6))));
        assert_eq!(it.next(), None);
        assert_eq!(pack.get(0).unwrap().unwrap().value, &[0xAA, 0xBB]);
        assert!(pack.get(1).is_err());

        let ber = VariableLengthPack::new(&[0x01, 9, 0x00, 0x01, 8], LengthEncoding::Ber);
        let idx: usize = ber.into_iter().map(|i| i.unwrap().index).sum();
        assert_eq!(idx, 3);
        assert_eq!(ber.get(2).unwrap().unwrap().offset, 3);
        assert_eq!(ber.get(3), Ok(None));
        assert_eq!((&ber).into_iter().count(), 3);
        let indefinite = VariableLengthPack::new(&[0x80], LengthEncoding::Ber).iter().next();
        assert_eq!(indefinite, Some(Err(Error::new(ErrorKind::IndefiniteLength, 0))));
        let opts = DecodeOptions::lenient();
        assert_eq!(ber.with_options(opts).options(), &opts);
    }

    #[test]
    fn reader() {
        let pack = DefinedLengthPack::new(&[1, 2, 3, 4]);
        let mut r = pack.reader();
        assert_eq!(r.take(1), Ok(&[1u8][..]));
        assert_eq!(r.take_array::<2>(), Ok([2, 3]));
        assert_eq!(r.position(), 3);
        assert_eq!(r.remaining(), &[4]);
        assert_eq!(r.finish(), Err(Error::new(ErrorKind::TrailingBytes { count: 1 }, 3)));
        assert_eq!(r.take(2), Err(Error::overrun(5, 4)));
        assert_eq!(r.position(), 3);
        assert_eq!(r.take(usize::MAX), Err(Error::new(ErrorKind::LengthOverflow, 3)));
        assert_eq!(r.take_rest(), &[4]);
        assert_eq!(r.take_rest(), &[] as &[u8]);
        assert_eq!(r.finish(), Ok(()));
        assert_eq!(r.take(0), Ok(&[][..]));
    }

    #[test]
    fn split() {
        let pack = DefinedLengthPack::new(&[1, 2, 3]);
        let mut it = pack.split(&[2, 2, 1]);
        let first = it.next().unwrap().unwrap();
        assert_eq!((first.index, first.offset, first.value), (0, 0, &[1u8, 2][..]));
        assert_eq!(it.position(), 2);
        assert_eq!(it.remaining(), &[3]);
        assert_eq!(it.next(), Some(Err(Error::overrun(4, 3))));
        assert_eq!(it.next(), None);
        assert_eq!(pack.split(&[0, 3]).count(), 2);
        // Leftover bytes are reported once, at the end.
        let mut it = pack.split(&[1]);
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.next(), Some(Err(Error::new(ErrorKind::TrailingBytes { count: 2 }, 1))));
        assert_eq!(it.next(), None);
        assert_eq!(pack.split(&[]).next(), Some(Err(Error::new(ErrorKind::TrailingBytes { count: 3 }, 0))));
        assert_eq!(DefinedLengthPack::new(&[]).split(&[]).next(), None);
        let opts = DecodeOptions::lenient();
        assert_eq!(pack.with_options(opts).options(), &opts);
    }
}
