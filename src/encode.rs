//! Encoding: triplets, headers, and (with `alloc`) sets and packs.
//!
//! The low-level writers take any [`Sink`]: a `Vec<u8>` (with `alloc`), or a
//! [`SliceSink`] over a fixed buffer for allocation-free use. Each
//! `*_size` function says how many bytes the matching writer needs.
//!
//! The group encoders build a set or pack value item by item, with every
//! key, tag and length checked so that the output decodes, under the strict
//! default options, to exactly the items given, and produce the finished
//! triplet:
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # fn main() -> Result<(), smpte_klv::Error> {
//! use smpte_klv::{LocalSetEncoder, Triplet, Group, UniversalLabel};
//!
//! let key: UniversalLabel = "06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00".parse().unwrap();
//! let mut set = LocalSetEncoder::new(key)?;   // byte 6 0x0B: BER-OID tags, BER lengths
//! set.item(2, &[0x00, 0x04, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8])?.item(65, &[19])?;
//! let packet = set.finish()?;
//!
//! let Some(Group::Local(decoded)) = Triplet::parse(&packet)?.group() else { unreachable!() };
//! assert_eq!(decoded.get(65)?.unwrap().value, &[19]);
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "alloc"))]
//! # fn main() {}
//! ```

use crate::ber::{self, BerForm};
use crate::triplet::KEY_LEN;
use crate::{Error, ErrorKind, UniversalLabel};

/// Somewhere to write encoded bytes.
///
/// A write either stores every byte or fails; implementations must not store
/// part of a write and then report an error. A sink with its own failure
/// modes can report [`ErrorKind::SinkFailed`].
pub trait Sink {
    /// Append `bytes`.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error>;

    /// How many more bytes the sink can take, if it knows. Writers that make
    /// several writes check this first, so that a triplet that cannot fit
    /// leaves nothing behind. The default is `None`: no limit is known.
    fn available(&self) -> Option<usize> {
        None
    }
}

impl<S: Sink + ?Sized> Sink for &mut S {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        (**self).write_bytes(bytes)
    }

    fn available(&self) -> Option<usize> {
        (**self).available()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Sink for alloc::vec::Vec<u8> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// A [`Sink`] that fills a caller-provided buffer and fails with
/// [`ErrorKind::BufferTooSmall`] when it is full.
///
/// ```
/// use smpte_klv::{encode, ber::BerForm, SliceSink, UniversalLabel};
///
/// let mut buf = [0u8; 32];
/// let mut out = SliceSink::new(&mut buf);
/// encode::write_triplet(UniversalLabel::FILL, &[0; 4], BerForm::Minimal, &mut out).unwrap();
/// assert_eq!(out.position(), 21);
/// ```
#[derive(Debug)]
pub struct SliceSink<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SliceSink<'a> {
    /// A sink writing from the start of `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        SliceSink { buf, pos: 0 }
    }

    /// Bytes written so far.
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Bytes still free.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The bytes written so far.
    pub fn written(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// The bytes written so far, keeping the buffer's lifetime.
    pub fn into_written(self) -> &'a mut [u8] {
        &mut self.buf[..self.pos]
    }
}

impl Sink for SliceSink<'_> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let available = self.remaining();
        if bytes.len() > available {
            return Err(Error::new(ErrorKind::BufferTooSmall { needed: bytes.len(), available }, self.pos));
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    fn available(&self) -> Option<usize> {
        Some(self.remaining())
    }
}

/// Fail with [`ErrorKind::BufferTooSmall`] if `out` knows it cannot take
/// `needed` bytes.
fn check_room<S: Sink + ?Sized>(out: &S, needed: usize) -> Result<(), Error> {
    match out.available() {
        Some(available) if available < needed => {
            Err(Error::new(ErrorKind::BufferTooSmall { needed, available }, 0))
        }
        _ => Ok(()),
    }
}

/// Size of the key and length field for a value of `value_len` bytes.
pub fn header_size(value_len: u64, form: BerForm) -> Result<usize, Error> {
    Ok(KEY_LEN + ber::length_size(value_len, form)?)
}

/// Size of a whole triplet with a value of `value_len` bytes.
pub fn triplet_size(value_len: usize, form: BerForm) -> Result<usize, Error> {
    header_size(value_len as u64, form)?
        .checked_add(value_len)
        .ok_or(Error::new(ErrorKind::LengthOverflow, 0))
}

/// Write a key and the BER length for a value of `value_len` bytes, leaving
/// the value to the caller. Useful when the value is produced in pieces, or
/// when a checksum must cover the header before the value is complete.
/// Returns the bytes written.
///
/// The header goes to the sink in one write, so nothing is written on
/// error. The key is not checked: this is the low-level writer, and the
/// group encoders are the checked ones.
pub fn write_header<S: Sink + ?Sized>(
    key: UniversalLabel,
    value_len: u64,
    form: BerForm,
    out: &mut S,
) -> Result<usize, Error> {
    let mut buf = [0u8; KEY_LEN + 1 + ber::MAX_LONG_FORM_BYTES as usize];
    buf[..KEY_LEN].copy_from_slice(key.as_bytes());
    let mut len = [0u8; 1 + ber::MAX_LONG_FORM_BYTES as usize];
    let n = KEY_LEN + ber::put_length(value_len, form, &mut len)?;
    buf[KEY_LEN..n].copy_from_slice(&len[..n - KEY_LEN]);
    out.write_bytes(&buf[..n])?;
    Ok(n)
}

/// Write a whole triplet. Returns the bytes written.
///
/// A sink that knows its [`available`](Sink::available) space (such as
/// [`SliceSink`]) gets nothing if the whole triplet does not fit, and the
/// error gives the triplet's full size. A sink that does not know can fail
/// at the value after taking the header. The key is not checked.
pub fn write_triplet<S: Sink + ?Sized>(
    key: UniversalLabel,
    value: &[u8],
    form: BerForm,
    out: &mut S,
) -> Result<usize, Error> {
    check_room(out, triplet_size(value.len(), form)?)?;
    let n = write_header(key, value.len() as u64, form, out)?;
    out.write_bytes(value)?;
    Ok(n + value.len())
}

#[cfg(feature = "alloc")]
pub use encoders::*;

#[cfg(feature = "alloc")]
mod encoders {
    use super::*;
    use crate::group::global::{designator_len, significant_len, MAX_TAG_WORDS};
    use crate::{Category, GroupCoding, GroupKind, LengthEncoding, TagEncoding};
    use alloc::vec::Vec;

    /// Methods every group encoder shares.
    macro_rules! common {
        ($name:ident) => {
            impl $name {
                /// Use `form` for BER length fields: the set's own length and,
                /// when the coding uses BER, each item's. Default
                /// [`BerForm::Minimal`].
                #[must_use]
                pub fn length_form(mut self, form: BerForm) -> Self {
                    self.form = form;
                    self
                }

                /// The set or pack key.
                pub fn key(&self) -> UniversalLabel {
                    self.key
                }

                /// The value encoded so far.
                pub fn value(&self) -> &[u8] {
                    &self.buf
                }

                /// Bytes in the value so far.
                pub fn len(&self) -> usize {
                    self.buf.len()
                }

                /// True before the first item.
                pub fn is_empty(&self) -> bool {
                    self.buf.is_empty()
                }

                /// The finished triplet: key, BER length and value.
                pub fn finish(&self) -> Result<Vec<u8>, Error> {
                    let mut out = Vec::with_capacity(triplet_size(self.buf.len(), self.form)?);
                    write_triplet(self.key, &self.buf, self.form, &mut out)?;
                    Ok(out)
                }

                /// The value alone, for a caller that writes the header
                /// itself (see [`write_header`]).
                pub fn into_value(self) -> Vec<u8> {
                    self.buf
                }
            }
        };
    }

    /// A key the strict decoder accepts as a key: SMPTE, and not a Label.
    fn check_key(key: UniversalLabel) -> Result<(), Error> {
        if !key.is_smpte() {
            return Err(Error::new(ErrorKind::InvalidKey, 0));
        }
        if key.category() == Category::Label {
            return Err(Error::new(ErrorKind::LabelKey, 4));
        }
        Ok(())
    }

    fn check_kind(key: UniversalLabel, kind: GroupKind) -> Result<GroupCoding, Error> {
        check_key(key)?;
        match key.group_coding() {
            Some(c) if c.kind() == kind => Ok(c),
            _ => Err(Error::new(
                ErrorKind::UnexpectedGroupCoding { registry_designator: key.registry_designator() },
                5,
            )),
        }
    }

    /// Append a length field and value, after checking the length fits.
    fn length_and_value(buf: &mut Vec<u8>, length: LengthEncoding, form: BerForm, value: &[u8]) -> Result<(), Error> {
        length.encoded_size(value.len() as u64, form)?;
        length.encode(value.len() as u64, form, buf)?;
        buf.extend_from_slice(value);
        Ok(())
    }

    /// Builds a Universal Set (SMPTE ST 336:2017 section 7.2).
    ///
    /// ```
    /// use smpte_klv::{UniversalLabel, UniversalSetEncoder};
    ///
    /// let set_key: UniversalLabel = "06.0E.2B.34.02.01.01.01.0F.01.01.01.00.00.00.00".parse().unwrap();
    /// let title: UniversalLabel = "06.0E.2B.34.01.01.01.01.01.05.02.00.00.00.00.00".parse().unwrap();
    /// let mut set = UniversalSetEncoder::new(set_key)?;
    /// set.item(title, b"Yesterdays World")?;
    /// assert_eq!(set.finish()?.len(), 16 + 1 + 16 + 1 + 16);
    /// # Ok::<(), smpte_klv::Error>(())
    /// ```
    #[derive(Clone, Debug)]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub struct UniversalSetEncoder {
        key: UniversalLabel,
        buf: Vec<u8>,
        form: BerForm,
    }

    common!(UniversalSetEncoder);

    impl UniversalSetEncoder {
        /// An encoder for a set with this key, whose byte 6 must declare a
        /// Universal Set.
        pub fn new(key: UniversalLabel) -> Result<Self, Error> {
            check_kind(key, GroupKind::UniversalSet)?;
            Ok(UniversalSetEncoder { key, buf: Vec::new(), form: BerForm::Minimal })
        }

        /// Append an item. Its key must be a SMPTE universal label and not a
        /// Label ([`ErrorKind::InvalidKey`], [`ErrorKind::LabelKey`]).
        pub fn item(&mut self, key: UniversalLabel, value: &[u8]) -> Result<&mut Self, Error> {
            check_key(key)?;
            write_triplet(key, value, self.form, &mut self.buf)?;
            Ok(self)
        }

        /// Append an already encoded triplet, such as a nested set's
        /// [`finish`](Self::finish) output, unaltered. It is not checked.
        pub fn raw(&mut self, triplet: &[u8]) -> &mut Self {
            self.buf.extend_from_slice(triplet);
            self
        }
    }

    /// Builds a Global Set (SMPTE ST 336:2017 section 7.3). Each item's key
    /// must start with the set's Global Set Designator, and is written as the
    /// Global Tag that rebuilds it.
    ///
    /// ```
    /// use smpte_klv::{GlobalSetEncoder, UniversalLabel};
    ///
    /// // Annex D: designator 06 0E 2B 34 01 01 01.
    /// let set_key: UniversalLabel = "06.0E.2B.34.02.02.08.01.06.0E.2B.34.01.01.01.00".parse().unwrap();
    /// let title: UniversalLabel = "06.0E.2B.34.01.01.01.01.01.05.02.00.00.00.00.00".parse().unwrap();
    /// let mut set = GlobalSetEncoder::new(set_key)?;
    /// set.item(title, b"Yesterdays World")?;
    /// assert_eq!(&set.value()[..6], &[0x01, 0x01, 0x05, 0x02, 0x00, 0x10]);
    /// # Ok::<(), smpte_klv::Error>(())
    /// ```
    #[derive(Clone, Debug)]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub struct GlobalSetEncoder {
        key: UniversalLabel,
        buf: Vec<u8>,
        form: BerForm,
        length: LengthEncoding,
        designator_len: usize,
    }

    common!(GlobalSetEncoder);

    impl GlobalSetEncoder {
        /// An encoder for a set with this key, whose byte 6 must declare a
        /// Global Set and whose bytes 9 to 16 must be a designator the strict
        /// decoder accepts (see [`GlobalSet::is_designator_valid`]).
        ///
        /// [`GlobalSet::is_designator_valid`]: crate::GlobalSet::is_designator_valid
        pub fn new(key: UniversalLabel) -> Result<Self, Error> {
            let length = check_kind(key, GroupKind::GlobalSet)?.length_encoding().unwrap_or_default();
            let (designator_len, ok) = designator_len(key.item_designator());
            if !ok {
                return Err(Error::new(ErrorKind::InvalidGlobalSetDesignator, 8));
            }
            // Every item key would be a Label.
            if designator_len >= 5 && key.item_designator()[4] == 0x04 {
                return Err(Error::new(ErrorKind::LabelKey, 12));
            }
            Ok(GlobalSetEncoder { key, buf: Vec::new(), form: BerForm::Minimal, length, designator_len })
        }

        /// The Global Tag for `key`, with its terminator when it has one.
        /// The tag is the rest of the key after the designator, up to its
        /// zero sub-identifier: at most 14 bytes (after a 2-byte
        /// designator), plus the terminator.
        fn tag_for(&self, key: &UniversalLabel) -> Result<([u8; 16], usize), Error> {
            let d = self.designator_len;
            if key.as_bytes()[..d] != self.key.item_designator()[..d] {
                return Err(Error::new(ErrorKind::KeyOutsideDesignator, 0));
            }
            let rest = &key.as_bytes()[d..];
            let n = significant_len(rest);
            let bad = Error::new(ErrorKind::InvalidGlobalTag, d);
            // After the zero sub-identifier, the key must be all zeros (ST
            // 336:2017 section 5.2.1): the decoder rebuilds it that way.
            if rest[n..].iter().any(|&b| b != 0) || (n > 0 && rest[n - 1] & 0x80 != 0) {
                return Err(bad);
            }
            // Every word in its shortest form, as the strict decoder wants.
            let mut words = 0;
            for (i, &b) in rest[..n].iter().enumerate() {
                let starts_word = i == 0 || rest[i - 1] & 0x80 == 0;
                if starts_word && b == 0x80 {
                    return Err(Error::new(ErrorKind::NonMinimalOid, d + i));
                }
                words += usize::from(b & 0x80 == 0);
            }
            if !(2..=MAX_TAG_WORDS).contains(&words) {
                return Err(bad);
            }
            let mut tag = [0u8; 16];
            tag[..n].copy_from_slice(&rest[..n]);
            Ok((tag, if words < MAX_TAG_WORDS { n + 1 } else { n }))
        }

        /// Append an item. Its key must start with the set's designator
        /// ([`ErrorKind::KeyOutsideDesignator`]), its remaining bytes must
        /// form a Global Tag of 2 to 12 words followed only by zeros
        /// ([`ErrorKind::InvalidGlobalTag`]) each in its shortest form
        /// ([`ErrorKind::NonMinimalOid`]), and it must be a SMPTE
        /// universal label ([`ErrorKind::InvalidKey`]) and not a Label
        /// ([`ErrorKind::LabelKey`]). Fails without appending anything.
        pub fn item(&mut self, key: UniversalLabel, value: &[u8]) -> Result<&mut Self, Error> {
            let (tag, n) = self.tag_for(&key)?;
            check_key(key)?;
            self.length.encoded_size(value.len() as u64, self.form)?;
            self.buf.extend_from_slice(&tag[..n]);
            length_and_value(&mut self.buf, self.length, self.form, value)?;
            Ok(self)
        }
    }

    /// Builds a Local Set (SMPTE ST 336:2017 section 7.4) with the tag and
    /// length codings its key declares.
    #[derive(Clone, Debug)]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub struct LocalSetEncoder {
        key: UniversalLabel,
        buf: Vec<u8>,
        form: BerForm,
        tag: TagEncoding,
        length: LengthEncoding,
    }

    common!(LocalSetEncoder);

    impl LocalSetEncoder {
        /// An encoder for a set with this key, whose byte 6 must declare a
        /// Local Set.
        pub fn new(key: UniversalLabel) -> Result<Self, Error> {
            match check_kind(key, GroupKind::LocalSet)? {
                GroupCoding::LocalSet { tag, length } => Self::with_coding(key, tag, length),
                _ => unreachable!("check_kind returned a local set coding"),
            }
        }

        /// An encoder that uses `tag` and `length` whatever the key's byte 6
        /// says. The key must still be a SMPTE universal label and not a
        /// Label.
        pub fn with_coding(key: UniversalLabel, tag: TagEncoding, length: LengthEncoding) -> Result<Self, Error> {
            check_key(key)?;
            Ok(LocalSetEncoder { key, buf: Vec::new(), form: BerForm::Minimal, tag, length })
        }

        /// The tag coding.
        pub fn tag_encoding(&self) -> TagEncoding {
            self.tag
        }

        /// The item length coding.
        pub fn length_encoding(&self) -> LengthEncoding {
            self.length
        }

        /// Append an item. Fails without appending anything if the tag or
        /// length does not fit its field.
        pub fn item(&mut self, tag: u64, value: &[u8]) -> Result<&mut Self, Error> {
            self.tag.encoded_size(tag)?;
            self.length.encoded_size(value.len() as u64, self.form)?;
            self.tag.encode(tag, &mut self.buf)?;
            length_and_value(&mut self.buf, self.length, self.form, value)?;
            Ok(self)
        }
    }

    /// Builds a Variable-Length Pack (SMPTE ST 336:2017 section 7.5).
    #[derive(Clone, Debug)]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub struct VariableLengthPackEncoder {
        key: UniversalLabel,
        buf: Vec<u8>,
        form: BerForm,
        length: LengthEncoding,
    }

    common!(VariableLengthPackEncoder);

    impl VariableLengthPackEncoder {
        /// An encoder for a pack with this key, whose byte 6 must declare a
        /// Variable-Length Pack.
        pub fn new(key: UniversalLabel) -> Result<Self, Error> {
            let length = check_kind(key, GroupKind::VariableLengthPack)?.length_encoding().unwrap_or_default();
            Ok(VariableLengthPackEncoder { key, buf: Vec::new(), form: BerForm::Minimal, length })
        }

        /// Append the next item.
        pub fn item(&mut self, value: &[u8]) -> Result<&mut Self, Error> {
            length_and_value(&mut self.buf, self.length, self.form, value)?;
            Ok(self)
        }
    }

    /// Builds a Defined-Length Pack (SMPTE ST 336:2017 section 7.6). Items
    /// are concatenated; their lengths are the defining document's business.
    #[derive(Clone, Debug)]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub struct DefinedLengthPackEncoder {
        key: UniversalLabel,
        buf: Vec<u8>,
        form: BerForm,
    }

    common!(DefinedLengthPackEncoder);

    impl DefinedLengthPackEncoder {
        /// An encoder for a pack with this key, whose byte 6 must declare a
        /// Defined-Length Pack.
        pub fn new(key: UniversalLabel) -> Result<Self, Error> {
            check_kind(key, GroupKind::DefinedLengthPack)?;
            Ok(DefinedLengthPackEncoder { key, buf: Vec::new(), form: BerForm::Minimal })
        }

        /// Append the next item.
        pub fn item(&mut self, value: &[u8]) -> &mut Self {
            self.buf.extend_from_slice(value);
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_sink() {
        let mut buf = [0u8; 4];
        let mut s = SliceSink::new(&mut buf);
        s.write_bytes(&[1, 2]).unwrap();
        assert_eq!(s.remaining(), 2);
        assert_eq!(
            s.write_bytes(&[3, 4, 5]),
            Err(Error::new(ErrorKind::BufferTooSmall { needed: 3, available: 2 }, 2))
        );
        assert_eq!(s.written(), &[1, 2]);
        (&mut s).write_bytes(&[3]).unwrap();
        assert_eq!(s.into_written(), &[1, 2, 3]);
    }

    #[test]
    fn header_and_triplet() {
        let mut buf = [0u8; 64];
        let mut s = SliceSink::new(&mut buf);
        assert_eq!(write_triplet(UniversalLabel::FILL, &[9; 3], BerForm::Long(3), &mut s), Ok(23));
        assert_eq!(&s.written()[16..20], &[0x83, 0, 0, 3]);
        assert_eq!(triplet_size(3, BerForm::Long(3)), Ok(23));
        assert_eq!(header_size(200, BerForm::Minimal), Ok(18));
        let mut tiny = [0u8; 4];
        assert!(write_header(UniversalLabel::FILL, 1, BerForm::Minimal, &mut SliceSink::new(&mut tiny)).is_err());
        // A length form that cannot hold the length fails before writing.
        let mut s = SliceSink::new(&mut buf);
        assert!(write_header(UniversalLabel::FILL, 300, BerForm::Long(1), &mut s).is_err());
        assert_eq!(s.position(), 0);
    }

    #[test]
    fn failed_writes_leave_nothing_behind() {
        // Room for the key and part of a long length field.
        let mut buf = [0u8; 20];
        let mut s = SliceSink::new(&mut buf);
        let e = write_header(UniversalLabel::FILL, 1, BerForm::Long(8), &mut s).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::BufferTooSmall { needed: 25, available: 20 });
        assert_eq!(s.position(), 0);
        // Room for the header but not the value: the whole size is reported.
        let mut s = SliceSink::new(&mut buf);
        let e = write_triplet(UniversalLabel::FILL, &[0; 4], BerForm::Minimal, &mut s).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::BufferTooSmall { needed: 21, available: 20 });
        assert_eq!(s.position(), 0);
        assert_eq!((&mut s).available(), Some(20));
        assert_eq!(write_triplet(UniversalLabel::FILL, &[0; 3], BerForm::Minimal, &mut s), Ok(20));
        assert_eq!(s.available(), Some(0));
        // Long forms with padding beyond 8 bytes.
        let mut big = [0u8; 160];
        let mut s = SliceSink::new(&mut big);
        assert_eq!(write_header(UniversalLabel::FILL, 0x0102, BerForm::Long(126), &mut s), Ok(16 + 127));
        let w = s.written();
        assert_eq!(w[16], 0xFE);
        assert!(w[17..141].iter().all(|&b| b == 0));
        assert_eq!(&w[141..143], &[0x01, 0x02]);
    }
}

#[cfg(all(test, feature = "alloc"))]
mod encoder_tests {
    use super::*;
    use crate::{DecodeOptions, GlobalSet, Group, LengthEncoding, TagEncoding, Triplet};
    use alloc::vec::Vec;

    fn ul(s: &str) -> UniversalLabel {
        s.parse().unwrap()
    }

    /// Decode a finished Global Set strictly and return its items' keys and
    /// values.
    fn global_items(packet: &[u8]) -> Vec<(UniversalLabel, Vec<u8>)> {
        let t = Triplet::parse_exact(packet).unwrap();
        let Some(Group::Global(set)) = t.group() else { panic!("not a global set") };
        set.iter().map(|i| i.map(|i| (i.key, i.value.to_vec()))).collect::<Result<_, _>>().unwrap()
    }

    #[test]
    fn global_tags_of_13_and_14_bytes() {
        // A 2-byte designator leaves 14 bytes for the tag; multi-byte words
        // keep the word count within 12.
        let set_key = ul("06.0E.2B.34.02.02.03.01.06.0E.00.00.00.00.00.00");
        for key in [
            "06.0E.2B.34.01.01.01.01.0E.81.03.01.81.01.05.00", // 13 bytes, 11 words
            "06.0E.2B.34.01.01.01.01.0E.01.03.81.01.81.01.05", // 14 bytes, 12 words
            "06.0E.2B.34.01.01.01.01.0E.81.03.81.01.81.01.05", // 14 bytes, 11 words
        ] {
            let mut e = GlobalSetEncoder::new(set_key).unwrap();
            e.item(ul(key), &[0xAA]).unwrap();
            assert_eq!(global_items(&e.finish().unwrap()), [(ul(key), alloc::vec![0xAA])], "{key}");
        }
        // 3-byte designator, 13-byte tag of 11 words.
        let set_key = ul("06.0E.2B.34.02.02.04.01.06.0E.2B.00.00.00.00.00");
        let key = ul("06.0E.2B.34.01.01.01.01.0E.81.03.01.81.01.05.00");
        let mut e = GlobalSetEncoder::new(set_key).unwrap();
        e.item(key, &[1, 2]).unwrap();
        assert_eq!(global_items(&e.finish().unwrap()), [(key, alloc::vec![1, 2])]);
    }

    #[test]
    fn global_keys_that_cannot_round_trip_are_refused() {
        let set_key = ul("06.0E.2B.34.02.02.05.01.06.0E.2B.34.00.00.00.00");
        let mut e = GlobalSetEncoder::new(set_key).unwrap();
        let refused = [
            // A zero sub-identifier followed by more bytes.
            "06.0E.2B.34.01.01.00.02.00.00.00.00.00.00.00.00",
            "06.0E.2B.34.01.01.01.01.0E.00.05.01.00.00.00.00",
            // An unfinished last word, and too few words.
            "06.0E.2B.34.01.01.01.01.01.01.01.01.01.01.01.81",
            "06.0E.2B.34.01.00.00.00.00.00.00.00.00.00.00.00",
        ];
        for key in refused {
            assert_eq!(e.item(ul(key), &[1]).unwrap_err().kind(), ErrorKind::InvalidGlobalTag, "{key}");
        }
        // A word padded with 0x80.
        let padded = ul("06.0E.2B.34.01.80.05.01.00.00.00.00.00.00.00.00");
        assert_eq!(e.item(padded, &[1]).unwrap_err(), Error::new(ErrorKind::NonMinimalOid, 5));
        let label = ul("06.0E.2B.34.04.01.01.01.04.01.01.01.01.01.00.00");
        assert_eq!(e.item(label, &[1]).unwrap_err().kind(), ErrorKind::LabelKey);
        assert!(e.is_empty(), "refused items append nothing");
        // A designator that makes every item key a Label.
        let labels = ul("06.0E.2B.34.02.02.06.01.06.0E.2B.34.04.01.00.00");
        assert_eq!(GlobalSetEncoder::new(labels).unwrap_err(), Error::new(ErrorKind::LabelKey, 12));
        // A designator without the UL header is refused; one ending in the
        // multi-byte word 81 00 is a valid 6-byte designator.
        let no_header = ul("06.0E.2B.34.02.02.03.01.01.02.00.00.00.00.00.00");
        assert_eq!(GlobalSetEncoder::new(no_header).unwrap_err().kind(), ErrorKind::InvalidGlobalSetDesignator);
        let word = ul("06.0E.2B.34.02.02.05.01.06.0E.2B.34.81.00.00.00");
        assert!(GlobalSetEncoder::new(word).is_ok());
        let set = GlobalSet::new(word, &[], LengthEncoding::Ber);
        assert!(set.is_designator_valid());
        assert_eq!(set.designator(), &[0x06, 0x0E, 0x2B, 0x34, 0x81, 0x00]);
        let ends_mid_word = ul("06.0E.2B.34.02.02.05.01.06.0E.2B.34.01.01.01.81");
        assert_eq!(GlobalSetEncoder::new(ends_mid_word).unwrap_err().kind(), ErrorKind::InvalidGlobalSetDesignator);
    }

    #[test]
    fn keys_the_decoder_rejects_are_refused() {
        let private = UniversalLabel::from_bytes([0, 0, 0, 0, 2, 3, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(LocalSetEncoder::new(private).unwrap_err().kind(), ErrorKind::InvalidKey);
        assert_eq!(
            LocalSetEncoder::with_coding(private, TagEncoding::U8, LengthEncoding::Ber).unwrap_err().kind(),
            ErrorKind::InvalidKey
        );
        let set_key = ul("06.0E.2B.34.02.01.01.01.0F.01.01.01.00.00.00.00");
        let mut u = UniversalSetEncoder::new(set_key).unwrap();
        assert_eq!(u.item(UniversalLabel::from_bytes([0x11; 16]), b"x").unwrap_err().kind(), ErrorKind::InvalidKey);
        let label = ul("06.0E.2B.34.04.01.01.01.04.01.01.01.01.01.00.00");
        assert_eq!(u.item(label, b"x").unwrap_err().kind(), ErrorKind::LabelKey);
        assert!(u.is_empty());
        let packet = u.item(UniversalLabel::FILL, &[]).unwrap().finish().unwrap();
        let t = Triplet::parse_exact_with(&packet, &DecodeOptions::strict()).unwrap();
        assert_eq!(t.group().unwrap().validate(), Ok(()));
    }
}
