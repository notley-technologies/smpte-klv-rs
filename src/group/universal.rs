//! Universal Sets (SMPTE ST 336:2017 section 7.2).

use crate::{DecodeOptions, IndefiniteLength, Triplets};

/// A Universal Set: items are complete KLV triplets, each with its full
/// 16-byte key and a BER length, in any order.
///
/// Iterating yields [`Triplet`](crate::Triplet)s; a nested group is one call
/// to [`Triplet::group`](crate::Triplet::group) away. A `0x80` length inside
/// a set is always an error, whatever
/// [`DecodeOptions::indefinite_length`] says, because the set's own length
/// must account for every item.
///
/// ```
/// use smpte_klv::UniversalSet;
///
/// let item_key = [0x06, 0x0E, 0x2B, 0x34, 1, 1, 1, 1, 2, 1, 1, 0, 0, 0, 0, 0];
/// let mut value = item_key.to_vec();
/// value.push(6);
/// value.extend(b"WXYZ15");
/// let set = UniversalSet::new(&value);
/// let item = set.iter().next().unwrap().unwrap();
/// assert_eq!(item.value(), b"WXYZ15");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UniversalSet<'a> {
    value: &'a [u8],
    opts: DecodeOptions,
}

impl<'a> UniversalSet<'a> {
    /// A view of a Universal Set value, decoded with the default options.
    pub fn new(value: &'a [u8]) -> Self {
        UniversalSet { value, opts: DecodeOptions::default() }
    }

    /// The same view with different options.
    #[must_use]
    pub fn with_options(self, opts: DecodeOptions) -> Self {
        UniversalSet { opts, ..self }
    }

    /// The set's value bytes.
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// The options the view was given.
    pub const fn options(&self) -> &DecodeOptions {
        &self.opts
    }

    /// The items in order. An item cut off by the end of the set is
    /// [`ErrorKind::Overrun`](crate::ErrorKind::Overrun).
    pub fn iter(&self) -> Triplets<'a> {
        let opts = DecodeOptions { indefinite_length: IndefiniteLength::Reject, ..self.opts };
        Triplets::within(self.value, opts)
    }
}

impl<'a> IntoIterator for UniversalSet<'a> {
    type Item = <Triplets<'a> as Iterator>::Item;
    type IntoIter = Triplets<'a>;

    fn into_iter(self) -> Triplets<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &UniversalSet<'a> {
    type Item = <Triplets<'a> as Iterator>::Item;
    type IntoIter = Triplets<'a>;

    fn into_iter(self) -> Triplets<'a> {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, ErrorKind, UniversalLabel};

    const K: [u8; 16] = [6, 0x0E, 0x2B, 0x34, 1, 1, 1, 1, 1, 5, 2, 0, 0, 0, 0, 0];

    #[test]
    fn items_and_errors() {
        let mut v = [0u8; 64];
        v[..16].copy_from_slice(&K);
        v[16] = 2;
        v[17..19].copy_from_slice(&[1, 2]);
        v[19..35].copy_from_slice(UniversalLabel::FILL.as_bytes());
        v[35] = 0;
        let set = UniversalSet::new(&v[..36]);
        assert_eq!(set.iter().count(), 2);
        let opts = DecodeOptions { skip_fill: true, ..DecodeOptions::strict() };
        assert_eq!(set.with_options(opts).into_iter().count(), 1);
        assert_eq!((&set).into_iter().next().unwrap().unwrap().value(), &[1, 2]);

        // A second item cut off by the end of the set.
        let mut it = UniversalSet::new(&v[..30]).iter();
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.next(), Some(Err(Error::overrun(36, 30))));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn indefinite_items_are_rejected() {
        let mut v = [0u8; 20];
        v[..16].copy_from_slice(&K);
        v[16] = 0x80;
        let opts = DecodeOptions { indefinite_length: IndefiniteLength::ToEnd, ..DecodeOptions::strict() };
        let mut it = UniversalSet::new(&v[..19]).with_options(opts).iter();
        assert_eq!(it.next(), Some(Err(Error::new(ErrorKind::IndefiniteLength, 16))));
    }
}
