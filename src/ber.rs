//! BER length and BER-OID coding.
//!
//! SMPTE ST 336:2017 uses two different ASN.1 Basic Encoding Rules codings,
//! both defined in ISO/IEC 8825-1 (ITU-T X.690):
//!
//! - **BER length** (8.1.3, ST 336 section 5.3) for the L of every KLV
//!   triplet. The short form is one byte below `0x80`. The long form is a
//!   byte `0x80 | n` followed by `n` big-endian bytes; the sender may use it
//!   for any length, including small ones and with leading zero bytes, and
//!   ST 336 sets no maximum on `n`. `0x80` alone is the non-deterministic
//!   length of ST 336 section 5.3, and `0xFF` is reserved.
//! - **BER-OID** (8.19, "primitive BER") for object identifier
//!   sub-identifiers, local tags of sets coded with Registry Designator
//!   `0x0B`, `0x2B`, `0x4B` or `0x6B` (ST 336 Table 5), and the bytes of a
//!   universal label. Seven bits per byte, most significant group first, the
//!   top bit set on every byte but the last, in the fewest bytes possible.
//!
//! ```
//! use smpte_klv::ber::{self, BerForm, Length};
//!
//! assert_eq!(ber::decode_length(&[0x82, 0x01, 0x00]).unwrap(), (Length::Definite(256), 3));
//! assert_eq!(ber::decode_oid(&[0x81, 0x01], true).unwrap(), (129, 2));
//!
//! let mut buf = [0u8; 8];
//! let mut out = smpte_klv::SliceSink::new(&mut buf);
//! ber::encode_length(300, BerForm::Long(3), &mut out).unwrap();
//! assert_eq!(out.written(), &[0x83, 0x00, 0x01, 0x2C]);
//! ```

use crate::{Error, ErrorKind, Sink};

/// The non-deterministic length byte (SMPTE ST 336:2017 section 5.3).
pub const INDEFINITE_LENGTH: u8 = 0x80;

/// The reserved first length byte (ISO/IEC 8825-1 8.1.3.5 c).
pub const RESERVED_LENGTH: u8 = 0xFF;

/// Most subsequent bytes a long-form length can have: `0x80 | 127` is the
/// reserved `0xFF`.
pub const MAX_LONG_FORM_BYTES: u8 = 126;

/// A decoded BER length field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Length {
    /// The value is this many bytes long.
    Definite(u64),
    /// The length byte was `0x80`: the value's length was not known when it
    /// was written, and the application must find its end some other way
    /// (SMPTE ST 336:2017 section 5.3).
    Indefinite,
}

impl Length {
    /// The length, if it is definite.
    pub const fn definite(self) -> Option<u64> {
        match self {
            Length::Definite(n) => Some(n),
            Length::Indefinite => None,
        }
    }
}

/// How to write a BER length.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum BerForm {
    /// The shortest encoding: short form up to 127, otherwise long form with
    /// as few bytes as the length needs. ST 336:2017 section 5.3 suggests the
    /// short form for lengths up to 127.
    #[default]
    Minimal,
    /// Long form with exactly this many subsequent bytes (1 to 126), padded
    /// with leading zeros. Fixed-size length fields let an encoder reserve
    /// space before the length is known; MXF (SMPTE ST 377-1) commonly uses
    /// `Long(3)` or `Long(8)`.
    Long(u8),
}

/// Decode a BER length at the start of `buf`.
///
/// Returns the length and the number of bytes it occupied; trailing bytes are
/// ignored. Non-minimal long forms are accepted, as ISO/IEC 8825-1 8.1.3.3
/// leaves the choice to the sender. Errors: [`ErrorKind::ReservedLength`] for
/// `0xFF`, [`ErrorKind::LengthOverflow`] when the value does not fit a `u64`,
/// and [`ErrorKind::UnexpectedEnd`] when `buf` is too short.
#[inline]
pub fn decode_length(buf: &[u8]) -> Result<(Length, usize), Error> {
    let first = match buf.first() {
        Some(&b) => b,
        None => return Err(Error::end(1, 0)),
    };
    if first < 0x80 {
        return Ok((Length::Definite(u64::from(first)), 1));
    }
    if first == INDEFINITE_LENGTH {
        return Ok((Length::Indefinite, 1));
    }
    if first == RESERVED_LENGTH {
        return Err(Error::new(ErrorKind::ReservedLength, 0));
    }
    let n = usize::from(first & 0x7F);
    if buf.len() <= n {
        return Err(Error::end(1 + n, buf.len()));
    }
    let mut value: u64 = 0;
    for (i, &b) in buf[1..=n].iter().enumerate() {
        if value > u64::MAX >> 8 {
            return Err(Error::new(ErrorKind::LengthOverflow, 1 + i));
        }
        value = (value << 8) | u64::from(b);
    }
    Ok((Length::Definite(value), 1 + n))
}

/// Bytes needed to hold `v` big-endian without leading zeros (0 for 0).
const fn significant_bytes(v: u64) -> usize {
    (64 - v.leading_zeros() as usize + 7) / 8
}

/// Size in bytes of `len` written as a BER length in `form`.
///
/// Fails like [`encode_length`]: [`ErrorKind::InvalidLengthForm`] for
/// `Long(0)` or more than [`MAX_LONG_FORM_BYTES`], and
/// [`ErrorKind::LengthNotRepresentable`] when `len` needs more bytes than
/// `Long(n)` provides.
pub fn length_size(len: u64, form: BerForm) -> Result<usize, Error> {
    match form {
        BerForm::Minimal if len < 0x80 => Ok(1),
        BerForm::Minimal => Ok(1 + significant_bytes(len)),
        BerForm::Long(n) => {
            if n == 0 || n > MAX_LONG_FORM_BYTES {
                return Err(Error::new(ErrorKind::InvalidLengthForm, 0));
            }
            if significant_bytes(len) > usize::from(n) {
                return Err(Error::new(ErrorKind::LengthNotRepresentable { length: len }, 0));
            }
            Ok(1 + usize::from(n))
        }
    }
}

/// Write `len` as a BER length in `form`. Returns the bytes written.
///
/// Fails with [`ErrorKind::InvalidLengthForm`] for `Long(0)` or more than
/// [`MAX_LONG_FORM_BYTES`], and [`ErrorKind::LengthNotRepresentable`] when
/// `len` needs more bytes than `Long(n)` provides. The field goes to the
/// sink in one [`Sink::write_bytes`] call, so nothing is written on error.
pub fn encode_length<S: Sink + ?Sized>(len: u64, form: BerForm, out: &mut S) -> Result<usize, Error> {
    let mut buf = [0u8; 1 + MAX_LONG_FORM_BYTES as usize];
    let size = put_length(len, form, &mut buf)?;
    out.write_bytes(&buf[..size])?;
    Ok(size)
}

/// Write `len` in `form` to the start of `buf`, which must hold
/// `1 + MAX_LONG_FORM_BYTES` bytes, and return the size.
pub(crate) fn put_length(len: u64, form: BerForm, buf: &mut [u8; 1 + MAX_LONG_FORM_BYTES as usize]) -> Result<usize, Error> {
    let size = length_size(len, form)?;
    if size == 1 {
        buf[0] = len as u8;
        return Ok(1);
    }
    let n = size - 1;
    buf[0] = 0x80 | n as u8;
    // Leading zero padding for Long(n) with n > 8, then the value.
    buf[1..size].fill(0);
    let be = len.to_be_bytes();
    let k = n.min(8);
    buf[size - k..size].copy_from_slice(&be[8 - k..]);
    Ok(size)
}

/// Decode one BER-OID value (an ISO/IEC 8825-1 8.19 sub-identifier) at the
/// start of `buf`.
///
/// Returns the value and the bytes it occupied. With `strict`, a leading
/// `0x80` byte (a non-minimal encoding) is [`ErrorKind::NonMinimalOid`];
/// without it such padding is skipped. A value above `u64::MAX` is
/// [`ErrorKind::OidOverflow`], and [`ErrorKind::UnexpectedEnd`] means `buf`
/// ended before a byte with the top bit clear.
#[inline]
pub fn decode_oid(buf: &[u8], strict: bool) -> Result<(u64, usize), Error> {
    let mut value: u64 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i == 0 && b == 0x80 && strict {
            return Err(Error::new(ErrorKind::NonMinimalOid, 0));
        }
        if value > u64::MAX >> 7 {
            return Err(Error::new(ErrorKind::OidOverflow, i));
        }
        value = (value << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(Error::end(buf.len() + 1, buf.len()))
}

/// Size in bytes of `value` written as a minimal BER-OID.
pub const fn oid_size(value: u64) -> usize {
    if value == 0 {
        1
    } else {
        (64 - value.leading_zeros() as usize + 6) / 7
    }
}

/// Write `value` as a minimal BER-OID. Returns the bytes written.
pub fn encode_oid<S: Sink + ?Sized>(value: u64, out: &mut S) -> Result<usize, Error> {
    let n = oid_size(value);
    let mut buf = [0u8; 10];
    for (i, slot) in buf[..n].iter_mut().enumerate() {
        let shift = 7 * (n - 1 - i);
        let more = if i + 1 < n { 0x80 } else { 0 };
        *slot = ((value >> shift) & 0x7F) as u8 | more;
    }
    out.write_bytes(&buf[..n])?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SliceSink;

    fn enc_len(len: u64, form: BerForm) -> Result<([u8; 130], usize), Error> {
        let mut buf = [0u8; 130];
        let mut out = SliceSink::new(&mut buf);
        let n = encode_length(len, form, &mut out)?;
        assert_eq!(out.position(), n);
        assert_eq!(length_size(len, form)?, n);
        Ok((buf, n))
    }

    #[test]
    fn length_short_and_long_forms() {
        assert_eq!(decode_length(&[0x00]), Ok((Length::Definite(0), 1)));
        assert_eq!(decode_length(&[0x7F, 0xFF]), Ok((Length::Definite(127), 1)));
        assert_eq!(decode_length(&[0x81, 0x80]), Ok((Length::Definite(128), 2)));
        assert_eq!(decode_length(&[0x81, 0xC9]), Ok((Length::Definite(201), 2))); // X.690 example
        assert_eq!(decode_length(&[0x82, 0x12, 0x34]), Ok((Length::Definite(0x1234), 3)));
        assert_eq!(decode_length(&[0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), Ok((Length::Definite(u64::MAX), 9)));
    }

    #[test]
    fn length_accepts_non_minimal_long_form() {
        // A sender may use the long form for small lengths, with padding.
        assert_eq!(decode_length(&[0x81, 0x05]), Ok((Length::Definite(5), 2)));
        assert_eq!(decode_length(&[0x83, 0x00, 0x00, 0x05]), Ok((Length::Definite(5), 4)));
        let mut long = [0u8; 21];
        long[0] = 0x94;
        long[20] = 7;
        assert_eq!(decode_length(&long), Ok((Length::Definite(7), 21)));
        let mut max = [0u8; 127];
        max[0] = 0xFE;
        max[126] = 1;
        assert_eq!(decode_length(&max), Ok((Length::Definite(1), 127)));
    }

    #[test]
    fn length_special_and_bad_values() {
        assert_eq!(decode_length(&[0x80]), Ok((Length::Indefinite, 1)));
        assert_eq!(Length::Indefinite.definite(), None);
        assert_eq!(Length::Definite(3).definite(), Some(3));
        assert_eq!(decode_length(&[0xFF, 0, 0]), Err(Error::new(ErrorKind::ReservedLength, 0)));
        assert_eq!(decode_length(&[]), Err(Error::end(1, 0)));
        assert_eq!(decode_length(&[0x82, 0x01]), Err(Error::end(3, 2)));
        let big = [0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode_length(&big), Err(Error::new(ErrorKind::LengthOverflow, 9)));
        // Leading zeros do not count towards overflow.
        let padded = [0x89, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(decode_length(&padded), Ok((Length::Definite(u64::MAX), 10)));
    }

    #[test]
    fn length_encoding() {
        let (b, n) = enc_len(0, BerForm::Minimal).unwrap();
        assert_eq!(&b[..n], &[0x00]);
        let (b, n) = enc_len(127, BerForm::Minimal).unwrap();
        assert_eq!(&b[..n], &[0x7F]);
        let (b, n) = enc_len(128, BerForm::Minimal).unwrap();
        assert_eq!(&b[..n], &[0x81, 0x80]);
        let (b, n) = enc_len(0x1_0000, BerForm::Minimal).unwrap();
        assert_eq!(&b[..n], &[0x83, 0x01, 0x00, 0x00]);
        let (b, n) = enc_len(u64::MAX, BerForm::Minimal).unwrap();
        assert_eq!(&b[..n], &[0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let (b, n) = enc_len(5, BerForm::Long(3)).unwrap();
        assert_eq!(&b[..n], &[0x83, 0, 0, 5]);
        let (b, n) = enc_len(0, BerForm::Long(1)).unwrap();
        assert_eq!(&b[..n], &[0x81, 0]);
        let (b, n) = enc_len(0x0102, BerForm::Long(10)).unwrap();
        assert_eq!(&b[..n], &[0x8A, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02]);
        let (b, n) = enc_len(9, BerForm::Long(126)).unwrap();
        assert_eq!(n, 127);
        assert_eq!(b[0], 0xFE);
        assert_eq!(b[126], 9);
        assert_eq!(decode_length(&b[..n]), Ok((Length::Definite(9), 127)));
    }

    #[test]
    fn length_encoding_errors() {
        let invalid = Err(Error::new(ErrorKind::InvalidLengthForm, 0));
        assert_eq!(enc_len(1, BerForm::Long(0)).map(|_| ()), invalid);
        assert_eq!(enc_len(1, BerForm::Long(127)).map(|_| ()), invalid);
        assert_eq!(
            enc_len(256, BerForm::Long(1)).map(|_| ()),
            Err(Error::new(ErrorKind::LengthNotRepresentable { length: 256 }, 0))
        );
        let mut tiny = [0u8; 2];
        let mut out = SliceSink::new(&mut tiny);
        assert!(matches!(
            encode_length(300, BerForm::Minimal, &mut out).unwrap_err().kind(),
            ErrorKind::BufferTooSmall { .. }
        ));
    }

    #[test]
    fn length_round_trip() {
        let forms = [BerForm::Minimal, BerForm::Long(8), BerForm::Long(9), BerForm::Long(126)];
        for &len in &[0, 1, 127, 128, 255, 256, 65_535, 65_536, 1 << 32, u64::MAX] {
            for &form in &forms {
                let (b, n) = enc_len(len, form).unwrap();
                assert_eq!(decode_length(&b[..n]), Ok((Length::Definite(len), n)), "{len} {form:?}");
            }
        }
    }

    #[test]
    fn oid_decoding() {
        assert_eq!(decode_oid(&[0x00], true), Ok((0, 1)));
        assert_eq!(decode_oid(&[0x7F], true), Ok((127, 1)));
        assert_eq!(decode_oid(&[0x81, 0x00], true), Ok((128, 2)));
        assert_eq!(decode_oid(&[0x81, 0x34, 0x03], true), Ok((180, 2))); // X.690 8.19 example
        assert_eq!(decode_oid(&[0x81, 0x01, 0x99], true), Ok((129, 2)));
        let max = [0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        assert_eq!(decode_oid(&max, true), Ok((u64::MAX, 10)));
    }

    #[test]
    fn oid_errors_and_leniency() {
        assert_eq!(decode_oid(&[], true), Err(Error::end(1, 0)));
        assert_eq!(decode_oid(&[0x81], true), Err(Error::end(2, 1)));
        assert_eq!(decode_oid(&[0x80, 0x05], true), Err(Error::new(ErrorKind::NonMinimalOid, 0)));
        assert_eq!(decode_oid(&[0x80, 0x05], false), Ok((5, 2)));
        assert_eq!(decode_oid(&[0x80; 40], false), Err(Error::end(41, 40)));
        let over = [0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
        assert_eq!(decode_oid(&over, true), Err(Error::new(ErrorKind::OidOverflow, 9)));
    }

    #[test]
    fn oid_round_trip() {
        for &v in &[0, 1, 127, 128, 255, 16_383, 16_384, 1 << 35, u64::MAX >> 1, u64::MAX] {
            let mut buf = [0u8; 10];
            let mut out = SliceSink::new(&mut buf);
            let n = encode_oid(v, &mut out).unwrap();
            assert_eq!(n, oid_size(v));
            assert_eq!(decode_oid(&buf[..n], true), Ok((v, n)), "{v}");
        }
        assert_eq!(oid_size(u64::MAX), 10);
    }
}
