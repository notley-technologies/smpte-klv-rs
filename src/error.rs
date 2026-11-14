//! Errors from decoding and encoding KLV.

use core::fmt;

/// Why KLV data could not be decoded or encoded.
///
/// Every decoder in this crate reports malformed or truncated input with an
/// `Error` instead of panicking. The [`kind`](Error::kind) says what was
/// wrong and the [`offset`](Error::offset) says where: a byte offset from the
/// start of the buffer handed to the function or iterator that failed. Items
/// of a set or pack report offsets from the start of its value. Errors from
/// encoders that do not concern a position in some input have offset 0.
///
/// ```
/// use smpte_klv::{ErrorKind, Triplet};
///
/// let err = Triplet::parse(&[0x06, 0x0E, 0x2B, 0x34]).unwrap_err();
/// assert_eq!(err.kind(), ErrorKind::UnexpectedEnd { needed: 17, available: 4 });
/// assert!(err.is_incomplete());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Error {
    kind: ErrorKind,
    offset: usize,
}

/// The kinds of [`Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input ended before the structure did, and more input could
    /// complete it: [`Error::is_incomplete`] is true. Both counts are
    /// measured from the same origin as [`Error::offset`]: the structure is
    /// complete once the buffer holds `needed` bytes. More bytes may be
    /// needed after that if what they reveal (a long-form length, say) asks
    /// for more. `needed` never exceeds `isize::MAX`, the largest possible
    /// buffer; a structure that would need more is
    /// [`LengthOverflow`](Self::LengthOverflow).
    ///
    /// Only parsing of a buffer that may grow reports this: [`Header`] and
    /// [`Triplet`] parsing and the top-level [`Triplets`] iterator. Inside a
    /// set or pack, whose size is fixed, the same condition is
    /// [`Overrun`](Self::Overrun).
    ///
    /// [`Header`]: crate::Header
    /// [`Triplet`]: crate::Triplet
    /// [`Triplets`]: crate::Triplets
    UnexpectedEnd {
        /// Bytes the buffer must hold to make progress.
        needed: usize,
        /// Bytes the buffer held.
        available: usize,
    },
    /// An item runs past the end of the set or pack value, or of the
    /// exactly-sized buffer, that must contain it. The container's size is
    /// fixed by its own length field, so more input cannot fix this. The
    /// counts are measured like those of
    /// [`UnexpectedEnd`](Self::UnexpectedEnd): decoding could only go on if
    /// the container held `needed` bytes (where the item ends or, for a tag,
    /// key or length field cut off, where that field ends), and it holds
    /// `available`.
    Overrun {
        /// Bytes the container would have to hold to go on.
        needed: usize,
        /// Bytes the container holds.
        available: usize,
    },
    /// A key does not start with the SMPTE universal label prefix
    /// `06 0E 2B 34` (SMPTE ST 336:2017 Table 2, SMPTE ST 298).
    InvalidKey,
    /// A SMPTE Label (byte 5 is `0x04`) appears where a key is expected,
    /// including a key a Global Set rebuilds. SMPTE ST 336:2017 section 9:
    /// "SMPTE Labels shall not be used as the Key in KLV coding". Reported
    /// when [`DecodeOptions::reject_label_keys`](crate::DecodeOptions::reject_label_keys)
    /// is set, and always by the group encoders (not by the low-level
    /// [`write_triplet`](crate::encode::write_triplet)).
    LabelKey,
    /// A BER length starts with `0xFF`, which ISO/IEC 8825-1 8.1.3.5 c
    /// reserves.
    ReservedLength,
    /// A BER length is `0x80`, the non-deterministic length of SMPTE ST
    /// 336:2017 section 5.3, where the end of the value cannot be found
    /// without it: inside a set or pack, or at the top level unless
    /// [`IndefiniteLength::ToEnd`](crate::IndefiniteLength::ToEnd) is set.
    IndefiniteLength,
    /// A length does not fit in a `u64`, or the structure it delimits would
    /// end past `isize::MAX` bytes, the largest buffer possible on this
    /// platform.
    LengthOverflow,
    /// A BER-OID value starts with `0x80`, which ISO/IEC 8825-1 8.19.2
    /// forbids ("the fewest possible octets"). Decoders report it when
    /// [`DecodeOptions::strict_oid`](crate::DecodeOptions::strict_oid) is
    /// set, and the Global Set encoder for an item key whose tag has such a
    /// word.
    NonMinimalOid,
    /// A BER-OID value does not fit in a `u64`.
    OidOverflow,
    /// The Global Set Designator in bytes 9 to 16 of a Global Set key is not
    /// 2 to 8 significant bytes followed only by zeros, does not start with
    /// the UL header, or ends inside a multi-byte sub-identifier (SMPTE ST
    /// 336:2017 section 7.3).
    InvalidGlobalSetDesignator,
    /// A Global Tag is empty, shorter than the 2 words SMPTE ST 336:2017
    /// section 7.3 requires, longer than 12 words, would rebuild a key longer
    /// than 16 bytes, or (to an encoder) has a zero sub-identifier that would
    /// end it early. A word not in its shortest form is
    /// [`NonMinimalOid`](Self::NonMinimalOid).
    InvalidGlobalTag,
    /// A key given to a Global Set encoder does not start with the set's
    /// Global Set Designator, so no Global Tag can represent it.
    KeyOutsideDesignator,
    /// A key does not identify the kind of group an operation needs; the
    /// value is the key's registry designator, byte 6.
    UnexpectedGroupCoding {
        /// Byte 6 of the key.
        registry_designator: u8,
    },
    /// A length is too large for the length field it must be written to.
    LengthNotRepresentable {
        /// The length that did not fit.
        length: u64,
    },
    /// A local tag is too large for the tag field it must be written to.
    TagNotRepresentable {
        /// The tag that did not fit.
        tag: u64,
    },
    /// A [`BerForm::Long`](crate::BerForm::Long) byte count outside 1 to 126.
    InvalidLengthForm,
    /// Bytes are left over after a structure that was required to fill the
    /// buffer.
    TrailingBytes {
        /// How many bytes were left over.
        count: usize,
    },
    /// An output buffer is too small for the encoded data.
    BufferTooSmall {
        /// Bytes the write needed.
        needed: usize,
        /// Bytes left in the buffer.
        available: usize,
    },
    /// A [`Sink`](crate::encode::Sink) implemented outside this crate could
    /// not accept the data for a reason of its own.
    SinkFailed,
}

impl Error {
    /// An error of `kind` at byte `offset`.
    pub const fn new(kind: ErrorKind, offset: usize) -> Self {
        Error { kind, offset }
    }

    /// What was wrong.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Where it was found, in bytes from the start of the input the failing
    /// call was given. For [`ErrorKind::UnexpectedEnd`] this is where the
    /// input ran out.
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// True when more input could fix the error: the data seen so far is
    /// valid but incomplete ([`ErrorKind::UnexpectedEnd`]). Incremental
    /// decoders wait for more bytes on these errors and give up on any
    /// other. Errors from inside a set or pack are never incomplete: the
    /// container's own length fixes its size ([`ErrorKind::Overrun`]).
    pub const fn is_incomplete(&self) -> bool {
        matches!(self.kind, ErrorKind::UnexpectedEnd { .. })
    }

    /// For [`ErrorKind::UnexpectedEnd`], the number of bytes the input must
    /// hold to make progress.
    pub const fn needed(&self) -> Option<usize> {
        match self.kind {
            ErrorKind::UnexpectedEnd { needed, .. } => Some(needed),
            _ => None,
        }
    }

    /// An [`ErrorKind::UnexpectedEnd`] at the end of the available input.
    pub(crate) const fn end(needed: usize, available: usize) -> Self {
        Error { kind: ErrorKind::UnexpectedEnd { needed, available }, offset: available }
    }

    /// An [`ErrorKind::Overrun`] at the end of a container of `available`
    /// bytes.
    pub(crate) const fn overrun(needed: usize, available: usize) -> Self {
        Error { kind: ErrorKind::Overrun { needed, available }, offset: available }
    }

    /// The same error seen from an origin `by` bytes earlier: the failing
    /// item starts at `by`. A byte count that would pass the largest
    /// possible buffer becomes [`ErrorKind::LengthOverflow`], reported where
    /// the item starts, instead of saturating.
    pub(crate) fn shift(self, by: usize) -> Self {
        let moved = |needed: usize, available: usize| match needed.checked_add(by) {
            Some(n) if n <= MAX_LEN => Some((n, available.saturating_add(by))),
            _ => None,
        };
        let overflow = Error { kind: ErrorKind::LengthOverflow, offset: by };
        let kind = match self.kind {
            ErrorKind::UnexpectedEnd { needed, available } => match moved(needed, available) {
                Some((needed, available)) => ErrorKind::UnexpectedEnd { needed, available },
                None => return overflow,
            },
            ErrorKind::Overrun { needed, available } => match moved(needed, available) {
                Some((needed, available)) => ErrorKind::Overrun { needed, available },
                None => return overflow,
            },
            k => k,
        };
        Error { kind, offset: self.offset.saturating_add(by) }
    }

    /// The same error found inside a container whose size is fixed: an
    /// [`ErrorKind::UnexpectedEnd`] becomes an [`ErrorKind::Overrun`].
    pub(crate) const fn bounded(self) -> Self {
        match self.kind {
            ErrorKind::UnexpectedEnd { needed, available } => {
                Error { kind: ErrorKind::Overrun { needed, available }, offset: self.offset }
            }
            _ => self,
        }
    }

    /// True for kinds only encoders report, whose offset says nothing.
    const fn is_encoding(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::LengthNotRepresentable { .. }
                | ErrorKind::TagNotRepresentable { .. }
                | ErrorKind::InvalidLengthForm
                | ErrorKind::KeyOutsideDesignator
                | ErrorKind::BufferTooSmall { .. }
                | ErrorKind::SinkFailed
        )
    }
}

/// The largest buffer Rust can address: no slice is longer than
/// `isize::MAX` bytes.
pub(crate) const MAX_LEN: usize = isize::MAX as usize;

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ErrorKind::UnexpectedEnd { needed, available } => {
                write!(f, "unexpected end of input: needed {needed} bytes, {available} available")
            }
            ErrorKind::Overrun { needed, available } => {
                write!(f, "item runs past the end of its container: ends at byte {needed}, container holds {available}")
            }
            ErrorKind::InvalidKey => f.write_str("key is not a SMPTE universal label"),
            ErrorKind::LabelKey => f.write_str("a SMPTE Label cannot be used as a key"),
            ErrorKind::ReservedLength => f.write_str("reserved BER length byte 0xFF"),
            ErrorKind::IndefiniteLength => f.write_str("indefinite BER length 0x80 not allowed here"),
            ErrorKind::LengthOverflow => f.write_str("length too large"),
            ErrorKind::NonMinimalOid => f.write_str("BER-OID value not in its shortest form"),
            ErrorKind::OidOverflow => f.write_str("BER-OID value too large"),
            ErrorKind::InvalidGlobalSetDesignator => f.write_str("malformed Global Set Designator"),
            ErrorKind::InvalidGlobalTag => f.write_str("malformed Global Tag"),
            ErrorKind::KeyOutsideDesignator => {
                f.write_str("key does not start with the Global Set Designator")
            }
            ErrorKind::UnexpectedGroupCoding { registry_designator } => {
                write!(f, "key does not identify this kind of group (byte 6 is {registry_designator:#04x})")
            }
            ErrorKind::LengthNotRepresentable { length } => {
                write!(f, "length {length} does not fit the length field")
            }
            ErrorKind::TagNotRepresentable { tag } => write!(f, "tag {tag} does not fit the tag field"),
            ErrorKind::InvalidLengthForm => f.write_str("BER long form must use 1 to 126 bytes"),
            ErrorKind::TrailingBytes { count } => write!(f, "{count} unexpected trailing bytes"),
            ErrorKind::BufferTooSmall { needed, available } => {
                write!(f, "output buffer too small: needed {needed} bytes, {available} available")
            }
            ErrorKind::SinkFailed => f.write_str("the output sink failed"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_encoding() {
            fmt::Display::fmt(&self.kind, f)
        } else {
            write!(f, "{} at byte {}", self.kind, self.offset)
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors() {
        let e = Error::end(5, 2);
        assert_eq!(e.kind(), ErrorKind::UnexpectedEnd { needed: 5, available: 2 });
        assert_eq!(e.offset(), 2);
        assert!(e.is_incomplete());
        assert_eq!(e.needed(), Some(5));
        let e = Error::new(ErrorKind::ReservedLength, 3);
        assert!(!e.is_incomplete());
        assert_eq!(e.needed(), None);
    }

    #[test]
    fn shift_moves_every_position() {
        let e = Error::end(5, 2).shift(10);
        assert_eq!(e, Error::new(ErrorKind::UnexpectedEnd { needed: 15, available: 12 }, 12));
        let e = Error::new(ErrorKind::OidOverflow, 1).shift(4);
        assert_eq!(e, Error::new(ErrorKind::OidOverflow, 5));
        let e = Error::end(MAX_LEN, 1).shift(1);
        assert_eq!(e.kind(), ErrorKind::LengthOverflow);
        assert_eq!(e.offset(), 1, "reported where the item starts");
        let e = Error::end(MAX_LEN - 1, 1).shift(1);
        assert_eq!(e.needed(), Some(MAX_LEN));
        let e = Error::overrun(usize::MAX, 1).shift(1);
        assert_eq!(e.kind(), ErrorKind::LengthOverflow);
        let e = Error::overrun(5, 2).shift(10);
        assert_eq!(e, Error::new(ErrorKind::Overrun { needed: 15, available: 12 }, 12));
    }

    #[test]
    fn bounded_errors_are_not_incomplete() {
        let e = Error::end(5, 2).bounded();
        assert_eq!(e, Error::new(ErrorKind::Overrun { needed: 5, available: 2 }, 2));
        assert!(!e.is_incomplete());
        assert_eq!(e.needed(), None);
        let e = Error::new(ErrorKind::ReservedLength, 1);
        assert_eq!(e.bounded(), e);
    }

    #[cfg(feature = "std")]
    #[test]
    fn display() {
        use std::string::ToString;
        assert_eq!(Error::end(17, 4).to_string(), "unexpected end of input: needed 17 bytes, 4 available at byte 4");
        assert_eq!(
            Error::new(ErrorKind::UnexpectedGroupCoding { registry_designator: 0x0B }, 0).to_string(),
            "key does not identify this kind of group (byte 6 is 0x0b) at byte 0"
        );
        let e = Error::new(ErrorKind::BufferTooSmall { needed: 9, available: 3 }, 0);
        assert_eq!(e.to_string(), "output buffer too small: needed 9 bytes, 3 available");
        assert_eq!(
            Error::overrun(7, 3).to_string(),
            "item runs past the end of its container: ends at byte 7, container holds 3 at byte 3"
        );
        fn takes(_: &dyn std::error::Error) {}
        takes(&Error::new(ErrorKind::InvalidKey, 0));
    }
}
