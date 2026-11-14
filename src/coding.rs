//! Group codings: what byte 6 of a set or pack key says about the tag and
//! length fields of the items inside (SMPTE ST 336:2017 Tables 3 to 6).

use crate::ber::{self, BerForm, Length};
use crate::{Error, ErrorKind, Sink};

/// How the length of each item in a group is coded.
///
/// Fixed-size fields are big-endian (SMPTE ST 336:2017 sections 7.3 to 7.5).
/// Top-level triplets always use [`Ber`](Self::Ber).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum LengthEncoding {
    /// ASN.1 BER short or long form, any length (the default).
    #[default]
    Ber,
    /// One byte, lengths up to 255.
    U8,
    /// Two bytes, lengths up to 65,535.
    U16,
    /// Four bytes, lengths up to 2^32 - 1.
    U32,
}

impl LengthEncoding {
    /// The field size for fixed encodings; `None` for BER.
    pub const fn fixed_size(self) -> Option<usize> {
        match self {
            LengthEncoding::Ber => None,
            LengthEncoding::U8 => Some(1),
            LengthEncoding::U16 => Some(2),
            LengthEncoding::U32 => Some(4),
        }
    }

    /// The largest length the field can hold.
    pub const fn max_length(self) -> u64 {
        match self {
            LengthEncoding::Ber => u64::MAX,
            LengthEncoding::U8 => u8::MAX as u64,
            LengthEncoding::U16 => u16::MAX as u64,
            LengthEncoding::U32 => u32::MAX as u64,
        }
    }

    /// Bits 5 and 6 of byte 6, counting from 0 (`0b0_LL_TT_KKK`).
    const fn code(self) -> u8 {
        match self {
            LengthEncoding::Ber => 0,
            LengthEncoding::U8 => 1,
            LengthEncoding::U16 => 2,
            LengthEncoding::U32 => 3,
        }
    }

    const fn from_code(c: u8) -> Self {
        match c & 3 {
            0 => LengthEncoding::Ber,
            1 => LengthEncoding::U8,
            2 => LengthEncoding::U16,
            _ => LengthEncoding::U32,
        }
    }

    /// Decode a length field at the start of `buf`. Returns the length and
    /// the bytes the field occupied.
    ///
    /// Inside a group the end of every item must be known, so the BER
    /// indefinite length `0x80` is [`ErrorKind::IndefiniteLength`].
    pub fn decode(self, buf: &[u8]) -> Result<(u64, usize), Error> {
        match self {
            LengthEncoding::Ber => match ber::decode_length(buf)? {
                (Length::Definite(n), used) => Ok((n, used)),
                (Length::Indefinite, _) => Err(Error::new(ErrorKind::IndefiniteLength, 0)),
            },
            fixed => {
                let size = fixed.fixed_size().unwrap_or(0);
                let bytes = buf.get(..size).ok_or(Error::end(size, buf.len()))?;
                Ok((bytes.iter().fold(0u64, |v, &b| (v << 8) | u64::from(b)), size))
            }
        }
    }

    /// Size of the field holding `len`. `form` applies to BER only.
    pub fn encoded_size(self, len: u64, form: BerForm) -> Result<usize, Error> {
        match self.fixed_size() {
            None => ber::length_size(len, form),
            Some(_) if len > self.max_length() => {
                Err(Error::new(ErrorKind::LengthNotRepresentable { length: len }, 0))
            }
            Some(size) => Ok(size),
        }
    }

    /// Write `len` in this encoding. `form` applies to BER only. Returns the
    /// bytes written.
    pub fn encode<S: Sink + ?Sized>(self, len: u64, form: BerForm, out: &mut S) -> Result<usize, Error> {
        let size = self.encoded_size(len, form)?;
        if self == LengthEncoding::Ber {
            return ber::encode_length(len, form, out);
        }
        out.write_bytes(&len.to_be_bytes()[8 - size..])?;
        Ok(size)
    }
}

/// How the local tag of each Local Set item is coded (SMPTE ST 336:2017
/// Table 5). Fixed-size tags are big-endian.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum TagEncoding {
    /// One byte, the preferred size and the default.
    #[default]
    U8,
    /// Two bytes, as in MXF header metadata (SMPTE ST 377-1).
    U16,
    /// Four bytes.
    U32,
    /// An ASN.1 BER-OID value ("primitive BER"), as used by MISB ST 0601.
    BerOid,
}

impl TagEncoding {
    /// The field size for fixed encodings; `None` for BER-OID.
    pub const fn fixed_size(self) -> Option<usize> {
        match self {
            TagEncoding::U8 => Some(1),
            TagEncoding::U16 => Some(2),
            TagEncoding::U32 => Some(4),
            TagEncoding::BerOid => None,
        }
    }

    /// The largest tag the field can hold.
    pub const fn max_tag(self) -> u64 {
        match self {
            TagEncoding::U8 => u8::MAX as u64,
            TagEncoding::U16 => u16::MAX as u64,
            TagEncoding::U32 => u32::MAX as u64,
            TagEncoding::BerOid => u64::MAX,
        }
    }

    /// Bits 3 and 4 of byte 6, counting from 0 (`0b0_LL_TT_KKK`).
    const fn code(self) -> u8 {
        match self {
            TagEncoding::U8 => 0,
            TagEncoding::BerOid => 1,
            TagEncoding::U16 => 2,
            TagEncoding::U32 => 3,
        }
    }

    const fn from_code(c: u8) -> Self {
        match c & 3 {
            0 => TagEncoding::U8,
            1 => TagEncoding::BerOid,
            2 => TagEncoding::U16,
            _ => TagEncoding::U32,
        }
    }

    /// Decode a tag at the start of `buf`. Returns the tag and the bytes it
    /// occupied. `strict_oid` rejects non-minimal BER-OID tags.
    pub fn decode(self, buf: &[u8], strict_oid: bool) -> Result<(u64, usize), Error> {
        match self.fixed_size() {
            None => ber::decode_oid(buf, strict_oid),
            Some(size) => {
                let bytes = buf.get(..size).ok_or(Error::end(size, buf.len()))?;
                Ok((bytes.iter().fold(0u64, |v, &b| (v << 8) | u64::from(b)), size))
            }
        }
    }

    /// Size of the field holding `tag`.
    pub fn encoded_size(self, tag: u64) -> Result<usize, Error> {
        match self.fixed_size() {
            None => Ok(ber::oid_size(tag)),
            Some(_) if tag > self.max_tag() => Err(Error::new(ErrorKind::TagNotRepresentable { tag }, 0)),
            Some(size) => Ok(size),
        }
    }

    /// Write `tag` in this encoding. Returns the bytes written.
    pub fn encode<S: Sink + ?Sized>(self, tag: u64, out: &mut S) -> Result<usize, Error> {
        let size = self.encoded_size(tag)?;
        if self == TagEncoding::BerOid {
            return ber::encode_oid(tag, out);
        }
        out.write_bytes(&tag.to_be_bytes()[8 - size..])?;
        Ok(size)
    }
}

/// The five kinds of group (SMPTE ST 336:2017 section 7), in order of
/// increasing coding efficiency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum GroupKind {
    /// Items are full KLV triplets with 16-byte keys (section 7.2).
    UniversalSet,
    /// Items are keyed by Global Tags that abbreviate a common key prefix
    /// (section 7.3).
    GlobalSet,
    /// Items are keyed by local tags a defining document maps to keys
    /// (section 7.4).
    LocalSet,
    /// Items are length and value only, in a defined order (section 7.5).
    VariableLengthPack,
    /// Items are values only, in a defined order with defined lengths
    /// (section 7.6).
    DefinedLengthPack,
}

/// How a group's value is coded, as declared by byte 6 (the Registry
/// Designator) of its key.
///
/// Byte 6 is `0b0_LL_TT_KKK`: `KKK` is the kind (1 universal set, 2 global
/// set, 3 local set, 4 variable-length pack, 5 defined-length pack), `LL`
/// the item length coding (BER, 1, 2 or 4 bytes) and `TT` the local tag
/// coding (1 byte, BER-OID, 2 or 4 bytes). Only the 26 values listed in SMPTE
/// ST 336:2017 Tables 3 to 6 are defined; [`from_registry_designator`]
/// returns `None` for the rest.
///
/// ```
/// use smpte_klv::{GroupCoding, LengthEncoding, TagEncoding};
///
/// let mxf = GroupCoding::from_registry_designator(0x53).unwrap();
/// assert_eq!(mxf, GroupCoding::LocalSet { tag: TagEncoding::U16, length: LengthEncoding::U16 });
/// assert_eq!(mxf.registry_designator(), 0x53);
/// assert_eq!(GroupCoding::from_registry_designator(0x06), None);
/// ```
///
/// [`from_registry_designator`]: GroupCoding::from_registry_designator
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum GroupCoding {
    /// `0x01` (Table 3).
    UniversalSet,
    /// `0x02`, `0x22`, `0x42`, `0x62` (Table 4).
    GlobalSet {
        /// Item length coding.
        length: LengthEncoding,
    },
    /// `0x03` to `0x7B` in steps of 8 (Table 5).
    LocalSet {
        /// Local tag coding.
        tag: TagEncoding,
        /// Item length coding.
        length: LengthEncoding,
    },
    /// `0x04`, `0x24`, `0x44`, `0x64` (Table 6).
    VariableLengthPack {
        /// Item length coding.
        length: LengthEncoding,
    },
    /// `0x05` (Table 3).
    DefinedLengthPack,
}

impl GroupCoding {
    /// The coding byte 6 declares, or `None` if ST 336 does not define it.
    pub const fn from_registry_designator(b: u8) -> Option<Self> {
        let length = LengthEncoding::from_code(b >> 5);
        let tag_bits = (b >> 3) & 3;
        if b & 0x80 != 0 {
            return None;
        }
        match b & 7 {
            1 if b == 0x01 => Some(GroupCoding::UniversalSet),
            2 if tag_bits == 0 => Some(GroupCoding::GlobalSet { length }),
            3 => Some(GroupCoding::LocalSet { tag: TagEncoding::from_code(tag_bits), length }),
            4 if tag_bits == 0 => Some(GroupCoding::VariableLengthPack { length }),
            5 if b == 0x05 => Some(GroupCoding::DefinedLengthPack),
            _ => None,
        }
    }

    /// The byte 6 value that declares this coding.
    pub const fn registry_designator(self) -> u8 {
        match self {
            GroupCoding::UniversalSet => 0x01,
            GroupCoding::GlobalSet { length } => 0x02 | length.code() << 5,
            GroupCoding::LocalSet { tag, length } => 0x03 | tag.code() << 3 | length.code() << 5,
            GroupCoding::VariableLengthPack { length } => 0x04 | length.code() << 5,
            GroupCoding::DefinedLengthPack => 0x05,
        }
    }

    /// Which kind of group this is.
    pub const fn kind(self) -> GroupKind {
        match self {
            GroupCoding::UniversalSet => GroupKind::UniversalSet,
            GroupCoding::GlobalSet { .. } => GroupKind::GlobalSet,
            GroupCoding::LocalSet { .. } => GroupKind::LocalSet,
            GroupCoding::VariableLengthPack { .. } => GroupKind::VariableLengthPack,
            GroupCoding::DefinedLengthPack => GroupKind::DefinedLengthPack,
        }
    }

    /// The item length coding, for the kinds that have item lengths.
    pub const fn length_encoding(self) -> Option<LengthEncoding> {
        match self {
            GroupCoding::UniversalSet => Some(LengthEncoding::Ber),
            GroupCoding::GlobalSet { length }
            | GroupCoding::LocalSet { length, .. }
            | GroupCoding::VariableLengthPack { length } => Some(length),
            GroupCoding::DefinedLengthPack => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SliceSink;

    /// Every byte 6 value of SMPTE ST 336:2017 Tables 3 to 6, with what it
    /// declares.
    const TABLE: [(u8, GroupCoding); 26] = {
        use GroupCoding::*;
        use LengthEncoding as L;
        use TagEncoding as T;
        [
            (0x01, UniversalSet),
            (0x02, GlobalSet { length: L::Ber }),
            (0x22, GlobalSet { length: L::U8 }),
            (0x42, GlobalSet { length: L::U16 }),
            (0x62, GlobalSet { length: L::U32 }),
            (0x03, LocalSet { tag: T::U8, length: L::Ber }),
            (0x0B, LocalSet { tag: T::BerOid, length: L::Ber }),
            (0x13, LocalSet { tag: T::U16, length: L::Ber }),
            (0x1B, LocalSet { tag: T::U32, length: L::Ber }),
            (0x23, LocalSet { tag: T::U8, length: L::U8 }),
            (0x2B, LocalSet { tag: T::BerOid, length: L::U8 }),
            (0x33, LocalSet { tag: T::U16, length: L::U8 }),
            (0x3B, LocalSet { tag: T::U32, length: L::U8 }),
            (0x43, LocalSet { tag: T::U8, length: L::U16 }),
            (0x4B, LocalSet { tag: T::BerOid, length: L::U16 }),
            (0x53, LocalSet { tag: T::U16, length: L::U16 }),
            (0x5B, LocalSet { tag: T::U32, length: L::U16 }),
            (0x63, LocalSet { tag: T::U8, length: L::U32 }),
            (0x6B, LocalSet { tag: T::BerOid, length: L::U32 }),
            (0x73, LocalSet { tag: T::U16, length: L::U32 }),
            (0x7B, LocalSet { tag: T::U32, length: L::U32 }),
            (0x04, VariableLengthPack { length: L::Ber }),
            (0x24, VariableLengthPack { length: L::U8 }),
            (0x44, VariableLengthPack { length: L::U16 }),
            (0x64, VariableLengthPack { length: L::U32 }),
            (0x05, DefinedLengthPack),
        ]
    };

    #[test]
    fn registry_designators_match_the_standard() {
        for &(b, coding) in &TABLE {
            assert_eq!(GroupCoding::from_registry_designator(b), Some(coding), "{b:#04x}");
            assert_eq!(coding.registry_designator(), b);
        }
        let defined = (0..=255u8).filter(|&b| GroupCoding::from_registry_designator(b).is_some()).count();
        assert_eq!(defined, TABLE.len(), "only the listed values are defined");
    }

    #[test]
    fn kinds_and_lengths() {
        assert_eq!(GroupCoding::UniversalSet.kind(), GroupKind::UniversalSet);
        assert_eq!(GroupCoding::DefinedLengthPack.length_encoding(), None);
        let ls = GroupCoding::LocalSet { tag: TagEncoding::U16, length: LengthEncoding::U32 };
        assert_eq!(ls.kind(), GroupKind::LocalSet);
        assert_eq!(ls.length_encoding(), Some(LengthEncoding::U32));
        assert_eq!(GroupCoding::GlobalSet { length: LengthEncoding::U8 }.kind(), GroupKind::GlobalSet);
        assert_eq!(GroupCoding::VariableLengthPack { length: LengthEncoding::U16 }.kind(), GroupKind::VariableLengthPack);
        assert_eq!(GroupCoding::UniversalSet.length_encoding(), Some(LengthEncoding::Ber));
    }

    #[test]
    fn fixed_lengths() {
        assert_eq!(LengthEncoding::U8.decode(&[0xFF, 9]), Ok((255, 1)));
        assert_eq!(LengthEncoding::U16.decode(&[0x01, 0x02]), Ok((0x0102, 2)));
        assert_eq!(LengthEncoding::U32.decode(&[0, 0, 1, 0]), Ok((256, 4)));
        assert_eq!(LengthEncoding::U32.decode(&[0, 0, 1]), Err(Error::end(4, 3)));
        assert_eq!(LengthEncoding::Ber.decode(&[0x81, 0x90]), Ok((0x90, 2)));
        assert_eq!(LengthEncoding::Ber.decode(&[0x80]), Err(Error::new(ErrorKind::IndefiniteLength, 0)));
        // A fixed one-byte field may hold 0x80: only BER gives it meaning.
        assert_eq!(LengthEncoding::U8.decode(&[0x80]), Ok((0x80, 1)));
        assert_eq!(LengthEncoding::U8.max_length(), 255);
        assert_eq!(LengthEncoding::Ber.fixed_size(), None);
    }

    #[test]
    fn length_encoding_round_trip_and_limits() {
        for enc in [LengthEncoding::Ber, LengthEncoding::U8, LengthEncoding::U16, LengthEncoding::U32] {
            for len in [0u64, 1, 127, 128, 255, 256, 65_535, 65_536, u32::MAX as u64, u64::MAX] {
                let mut buf = [0u8; 16];
                let mut out = SliceSink::new(&mut buf);
                match enc.encode(len, BerForm::Minimal, &mut out) {
                    Ok(n) => {
                        assert!(len <= enc.max_length());
                        assert_eq!(enc.decode(&buf[..n]), Ok((len, n)));
                    }
                    Err(e) => {
                        assert!(len > enc.max_length());
                        assert_eq!(e.kind(), ErrorKind::LengthNotRepresentable { length: len });
                    }
                }
            }
        }
    }

    #[test]
    fn tags() {
        assert_eq!(TagEncoding::U8.decode(&[0x80], true), Ok((0x80, 1)));
        assert_eq!(TagEncoding::U16.decode(&[0x3C, 0x0A], true), Ok((0x3C0A, 2)));
        assert_eq!(TagEncoding::U32.decode(&[1, 2, 3, 4], true), Ok((0x0102_0304, 4)));
        assert_eq!(TagEncoding::U16.decode(&[1], true), Err(Error::end(2, 1)));
        assert_eq!(TagEncoding::BerOid.decode(&[0x81, 0x01], true), Ok((129, 2)));
        assert_eq!(TagEncoding::BerOid.decode(&[0x80, 0x01], true), Err(Error::new(ErrorKind::NonMinimalOid, 0)));
        assert_eq!(TagEncoding::BerOid.decode(&[0x80, 0x01], false), Ok((1, 2)));
        for enc in [TagEncoding::U8, TagEncoding::U16, TagEncoding::U32, TagEncoding::BerOid] {
            for tag in [0u64, 1, 127, 128, 255, 256, 65_535, 65_536, u32::MAX as u64, u64::MAX] {
                let mut buf = [0u8; 16];
                let mut out = SliceSink::new(&mut buf);
                match enc.encode(tag, &mut out) {
                    Ok(n) => assert_eq!(enc.decode(&buf[..n], true), Ok((tag, n))),
                    Err(e) => {
                        assert!(tag > enc.max_tag());
                        assert_eq!(e.kind(), ErrorKind::TagNotRepresentable { tag });
                    }
                }
            }
        }
    }
}
