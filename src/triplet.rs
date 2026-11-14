//! Key-Length-Value triplets (SMPTE ST 336:2017 section 5).

use crate::ber::{self, Length};
use crate::error::MAX_LEN;
use crate::group::Group;
use crate::{DecodeOptions, Error, ErrorKind, IndefiniteLength, Sink, UniversalLabel};
use core::fmt;

/// Size of a key.
pub const KEY_LEN: usize = 16;

/// The key and length of a triplet, decoded without needing its value.
///
/// Useful to decide whether a value is worth buffering, or how many more
/// bytes to read, before it has arrived:
///
/// ```
/// use smpte_klv::{ber::Length, Header};
///
/// let mut buf = vec![0x06, 0x0E, 0x2B, 0x34, 1, 1, 1, 1, 1, 5, 2, 0, 0, 0, 0, 0];
/// buf.extend([0x83, 0x01, 0x00, 0x00]); // 65,536 byte value, not here yet
/// let header = Header::parse(&buf).unwrap();
/// assert_eq!(header.length(), Length::Definite(65_536));
/// assert_eq!(header.header_len(), 20);
/// assert_eq!(header.total_len(), Some(65_556));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    key: UniversalLabel,
    length: Length,
    header_len: usize,
}

impl Header {
    /// Decode the key and length at the start of `buf` with the default
    /// (strict) options.
    pub fn parse(buf: &[u8]) -> Result<Header, Error> {
        Header::parse_with(buf, &DecodeOptions::default())
    }

    /// Decode the key and length at the start of `buf`.
    ///
    /// With [`DecodeOptions::require_smpte_key`], a buffer whose first bytes
    /// already differ from `06 0E 2B 34` fails with
    /// [`ErrorKind::InvalidKey`] even if it is too short for a whole key.
    /// Likewise, with [`DecodeOptions::reject_label_keys`], a SMPTE key whose
    /// byte 5 is `0x04` fails with [`ErrorKind::LabelKey`] as soon as that
    /// byte is there.
    pub fn parse_with(buf: &[u8], opts: &DecodeOptions) -> Result<Header, Error> {
        // Compare against the 4-byte array where possible, which compiles to
        // a single comparison instead of a call.
        let smpte = match buf.get(..4) {
            Some(prefix) => prefix == UniversalLabel::PREFIX,
            None => buf == &UniversalLabel::PREFIX[..buf.len()],
        };
        if opts.require_smpte_key && !smpte {
            return Err(Error::new(ErrorKind::InvalidKey, 0));
        }
        if opts.reject_label_keys && smpte && buf.get(4) == Some(&0x04) {
            return Err(Error::new(ErrorKind::LabelKey, 4));
        }
        let key = UniversalLabel::from_slice(buf).ok_or(Error::end(KEY_LEN + 1, buf.len()))?;
        let (length, n) = ber::decode_length(&buf[KEY_LEN..]).map_err(|e| e.shift(KEY_LEN))?;
        Ok(Header { key, length, header_len: KEY_LEN + n })
    }

    /// The key.
    pub const fn key(&self) -> UniversalLabel {
        self.key
    }

    /// The decoded length field.
    pub const fn length(&self) -> Length {
        self.length
    }

    /// Bytes taken by the key and length field.
    pub const fn header_len(&self) -> usize {
        self.header_len
    }

    /// Header plus value, when the length is definite and the sum fits a
    /// `u64`. On a 32-bit platform this can exceed what a buffer can hold.
    pub fn total_len(&self) -> Option<u64> {
        self.length.definite()?.checked_add(self.header_len as u64)
    }
}

/// One KLV triplet, borrowed from the input.
///
/// ```
/// use smpte_klv::Triplet;
///
/// // SMPTE ST 336:2017 Annex B: Main Title "Yesterdays World".
/// let mut buf = vec![0x06, 0x0E, 0x2B, 0x34, 1, 1, 1, 1, 1, 5, 2, 0, 0, 0, 0, 0, 0x10];
/// buf.extend(b"Yesterdays World");
/// let t = Triplet::parse(&buf).unwrap();
/// assert_eq!(t.key().to_string(), "06.0E.2B.34.01.01.01.01.01.05.02.00.00.00.00.00");
/// assert_eq!(t.value(), b"Yesterdays World");
/// assert_eq!(t.as_bytes(), &buf[..]);
/// assert!(t.group().is_none()); // a single item, not a set or pack
/// ```
#[derive(Clone, Copy)]
pub struct Triplet<'a> {
    key: UniversalLabel,
    value: &'a [u8],
    raw: &'a [u8],
    header_len: usize,
    indefinite: bool,
    opts: DecodeOptions,
}

/// Triplets are equal when their encoded bytes are. The options they were
/// decoded with are not compared.
impl PartialEq for Triplet<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw && self.header_len == other.header_len
    }
}

impl Eq for Triplet<'_> {}

impl core::hash::Hash for Triplet<'_> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
        self.header_len.hash(state);
    }
}

/// Shows the key, the header length and the value; the raw bytes are the
/// two together.
impl fmt::Debug for Triplet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Triplet")
            .field("key", &self.key)
            .field("header_len", &self.header_len)
            .field("value", &self.value)
            .field("indefinite", &self.indefinite)
            .finish()
    }
}

impl<'a> Triplet<'a> {
    /// Decode the triplet at the start of `buf` with the default (strict)
    /// options. Trailing bytes are ignored; see
    /// [`encoded_len`](Self::encoded_len) and [`Triplets`].
    pub fn parse(buf: &'a [u8]) -> Result<Triplet<'a>, Error> {
        Triplet::parse_with(buf, &DecodeOptions::default())
    }

    /// Decode the triplet at the start of `buf`; trailing bytes are ignored.
    pub fn parse_with(buf: &'a [u8], opts: &DecodeOptions) -> Result<Triplet<'a>, Error> {
        let header = Header::parse_with(buf, opts)?;
        let start = header.header_len;
        let (end, indefinite) = match header.length {
            Length::Definite(n) => {
                let end = usize::try_from(n)
                    .ok()
                    .and_then(|n| start.checked_add(n))
                    .filter(|&end| end <= MAX_LEN)
                    .ok_or(Error::new(ErrorKind::LengthOverflow, KEY_LEN))?;
                (end, false)
            }
            Length::Indefinite => match opts.indefinite_length {
                IndefiniteLength::Reject => return Err(Error::new(ErrorKind::IndefiniteLength, KEY_LEN)),
                IndefiniteLength::ToEnd => (buf.len(), true),
            },
        };
        if buf.len() < end {
            return Err(Error::end(end, buf.len()));
        }
        Ok(Triplet {
            key: header.key,
            value: &buf[start..end],
            raw: &buf[..end],
            header_len: start,
            indefinite,
            opts: *opts,
        })
    }

    /// A triplet over bytes already known to be one: `raw` is the whole
    /// triplet with a definite length and `header_len` header bytes.
    #[cfg(feature = "alloc")]
    pub(crate) fn from_valid(raw: &'a [u8], header_len: usize, opts: DecodeOptions) -> Triplet<'a> {
        let key = UniversalLabel::from_slice(raw).expect("a frame holds a whole key");
        Triplet { key, value: &raw[header_len..], raw, header_len, indefinite: false, opts }
    }

    /// Decode a triplet that must fill `buf` exactly, such as one datagram,
    /// with the default (strict) options. Leftover bytes are
    /// [`ErrorKind::TrailingBytes`], and a triplet longer than `buf` is
    /// [`ErrorKind::Overrun`]: `buf` is meant to be complete, so more input
    /// cannot help.
    pub fn parse_exact(buf: &'a [u8]) -> Result<Triplet<'a>, Error> {
        Triplet::parse_exact_with(buf, &DecodeOptions::default())
    }

    /// [`parse_exact`](Self::parse_exact) with the given options.
    pub fn parse_exact_with(buf: &'a [u8], opts: &DecodeOptions) -> Result<Triplet<'a>, Error> {
        let t = Triplet::parse_with(buf, opts).map_err(Error::bounded)?;
        match buf.len() - t.raw.len() {
            0 => Ok(t),
            count => Err(Error::new(ErrorKind::TrailingBytes { count }, t.raw.len())),
        }
    }

    /// The key.
    pub const fn key(&self) -> UniversalLabel {
        self.key
    }

    /// The value bytes.
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// The whole triplet as it appears in the input: key, length field and
    /// value. ST 336:2017 section 5.2.1 requires items that are stored and
    /// forwarded to be forwarded unaltered; these are the bytes to forward.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// The length field as it appears in the input.
    pub fn length_bytes(&self) -> &'a [u8] {
        &self.raw[KEY_LEN..self.header_len]
    }

    /// Bytes taken by the key and length field.
    pub const fn header_len(&self) -> usize {
        self.header_len
    }

    /// Bytes taken by the whole triplet.
    pub const fn encoded_len(&self) -> usize {
        self.raw.len()
    }

    /// True when the length field was `0x80` and the value was taken to run
    /// to the end of the buffer ([`IndefiniteLength::ToEnd`]).
    pub const fn is_indefinite(&self) -> bool {
        self.indefinite
    }

    /// True for a KLV Fill item ([`UniversalLabel::is_fill`]).
    pub fn is_fill(&self) -> bool {
        self.key.is_fill()
    }

    /// The options the triplet was decoded with. [`group`](Self::group)
    /// passes them on.
    pub const fn options(&self) -> &DecodeOptions {
        &self.opts
    }

    /// The value as a set or pack, if the key is a SMPTE universal label
    /// that declares one ST 336 defines (see
    /// [`UniversalLabel::group_coding`]). Items are decoded lazily, so a
    /// malformed group shows up as an `Err` while iterating; such errors are
    /// never [incomplete](Error::is_incomplete).
    pub fn group(&self) -> Option<Group<'a>> {
        Group::new(self.key, self.value, self.opts)
    }

    /// Copy the triplet, unaltered, to `out`. Returns the bytes written.
    pub fn write_to<S: Sink + ?Sized>(&self, out: &mut S) -> Result<usize, Error> {
        out.write_bytes(self.raw)?;
        Ok(self.raw.len())
    }
}

/// Iterator over consecutive triplets in a buffer, such as a `.klv` file or
/// a Universal Set value.
///
/// Yields `Err` once and then stops if a triplet is malformed or cut short;
/// the error's offset is from the start of the buffer, and
/// [`offset`](Self::offset) tells where the failing triplet began. Bytes
/// between triplets are not skipped: use the streaming
/// [`Decoder`](crate::Decoder) for damaged streams that need resynchronising.
///
/// ```
/// use smpte_klv::Triplets;
///
/// let key = [0x06, 0x0E, 0x2B, 0x34, 1, 1, 1, 1, 1, 5, 2, 0, 0, 0, 0, 0];
/// let mut buf = Vec::new();
/// for value in [&b"one"[..], b"two"] {
///     buf.extend(key);
///     buf.push(value.len() as u8);
///     buf.extend(value);
/// }
/// let values: Vec<&[u8]> = Triplets::new(&buf).map(|t| t.unwrap().value()).collect();
/// assert_eq!(values, [&b"one"[..], b"two"]);
/// ```
#[derive(Clone, Debug)]
pub struct Triplets<'a> {
    buf: &'a [u8],
    pos: usize,
    opts: DecodeOptions,
    done: bool,
    /// The buffer is a Universal Set value, whose size is fixed: truncation
    /// is an overrun, not something more input could fix.
    bounded: bool,
}

impl<'a> Triplets<'a> {
    /// Iterate over the triplets in `buf` with the default options.
    pub fn new(buf: &'a [u8]) -> Self {
        Triplets::with_options(buf, DecodeOptions::default())
    }

    /// Iterate over the triplets in `buf`. A triplet cut off by the end of
    /// `buf` is [`ErrorKind::UnexpectedEnd`], as `buf` may be the start of a
    /// longer stream.
    pub fn with_options(buf: &'a [u8], opts: DecodeOptions) -> Self {
        Triplets { buf, pos: 0, opts, done: false, bounded: false }
    }

    /// Iterate over the items of a set value: truncation is
    /// [`ErrorKind::Overrun`].
    pub(crate) fn within(buf: &'a [u8], opts: DecodeOptions) -> Self {
        Triplets { buf, pos: 0, opts, done: false, bounded: true }
    }

    /// Offset of the next triplet, or of the one that failed.
    pub const fn offset(&self) -> usize {
        self.pos
    }

    /// Bytes not yet decoded, starting at [`offset`](Self::offset).
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

impl<'a> Iterator for Triplets<'a> {
    type Item = Result<Triplet<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done && self.pos < self.buf.len() {
            match Triplet::parse_with(&self.buf[self.pos..], &self.opts) {
                Ok(t) => {
                    self.pos += t.encoded_len();
                    if self.opts.skip_fill && t.is_fill() {
                        continue;
                    }
                    return Some(Ok(t));
                }
                Err(e) => {
                    self.done = true;
                    let e = e.shift(self.pos);
                    return Some(Err(if self.bounded { e.bounded() } else { e }));
                }
            }
        }
        None
    }
}

impl core::iter::FusedIterator for Triplets<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [6, 0x0E, 0x2B, 0x34, 1, 1, 1, 1, 1, 5, 2, 0, 0, 0, 0, 0];

    fn klv(key: &[u8; 16], len: &[u8], value: &[u8]) -> ([u8; 64], usize) {
        let mut b = [0u8; 64];
        let mut n = 0;
        for part in [&key[..], len, value] {
            b[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        (b, n)
    }

    #[test]
    fn parses() {
        let (b, n) = klv(&KEY, &[0x81, 0x03], &[1, 2, 3]);
        let t = Triplet::parse(&b[..n + 1]).unwrap();
        assert_eq!(t.key(), UniversalLabel::from_bytes(KEY));
        assert_eq!(t.value(), &[1, 2, 3]);
        assert_eq!(t.header_len(), 18);
        assert_eq!(t.encoded_len(), 21);
        assert_eq!(t.as_bytes(), &b[..21]);
        assert_eq!(t.length_bytes(), &[0x81, 0x03]);
        assert!(!t.is_indefinite() && !t.is_fill());
        assert_eq!(Triplet::parse_exact(&b[..n]), Ok(t));
        assert_eq!(
            Triplet::parse_exact(&b[..n + 2]),
            Err(Error::new(ErrorKind::TrailingBytes { count: 2 }, 21))
        );
    }

    #[test]
    fn empty_value() {
        let (b, n) = klv(&KEY, &[0x00], &[]);
        let t = Triplet::parse(&b[..n]).unwrap();
        assert!(t.value().is_empty());
        assert_eq!(t.encoded_len(), 17);
    }

    #[test]
    fn truncation_reports_bytes_needed() {
        assert_eq!(Triplet::parse(&[]), Err(Error::end(17, 0)));
        assert_eq!(Triplet::parse(&KEY[..10]), Err(Error::end(17, 10)));
        assert_eq!(Triplet::parse(&KEY), Err(Error::end(17, 16)));
        let (b, n) = klv(&KEY, &[0x82, 0x01], &[]);
        assert_eq!(Triplet::parse(&b[..n]), Err(Error::end(19, 18)));
        let (b, n) = klv(&KEY, &[0x05], &[1, 2]);
        assert_eq!(Triplet::parse(&b[..n]), Err(Error::end(22, 19)));
        assert!(Triplet::parse(&b[..n]).unwrap_err().is_incomplete());
    }

    #[test]
    fn key_validation() {
        assert_eq!(Triplet::parse(&[0x06, 0x0E, 0x2B, 0x35]), Err(Error::new(ErrorKind::InvalidKey, 0)));
        assert_eq!(Triplet::parse(&[0x07]), Err(Error::new(ErrorKind::InvalidKey, 0)));
        let mut other = KEY;
        other[0] = 0x2B;
        let (b, n) = klv(&other, &[0x01], &[9]);
        assert_eq!(Triplet::parse(&b[..n]), Err(Error::new(ErrorKind::InvalidKey, 0)));
        let opts = DecodeOptions { require_smpte_key: false, ..DecodeOptions::strict() };
        assert_eq!(Triplet::parse_with(&b[..n], &opts).unwrap().value(), &[9]);
    }

    #[test]
    fn bad_lengths() {
        let (b, n) = klv(&KEY, &[0xFF], &[]);
        assert_eq!(Triplet::parse(&b[..n]), Err(Error::new(ErrorKind::ReservedLength, 16)));
        let (b, n) = klv(&KEY, &[0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], &[]);
        assert_eq!(Triplet::parse(&b[..n]), Err(Error::new(ErrorKind::LengthOverflow, 16)));
        assert!(Header::parse(&b[..n]).unwrap().total_len().is_none());
    }

    #[test]
    fn indefinite_length() {
        let (b, n) = klv(&KEY, &[0x80], &[1, 2, 3]);
        assert_eq!(Triplet::parse(&b[..n]), Err(Error::new(ErrorKind::IndefiniteLength, 16)));
        let opts = DecodeOptions { indefinite_length: IndefiniteLength::ToEnd, ..DecodeOptions::strict() };
        let t = Triplet::parse_with(&b[..n], &opts).unwrap();
        assert!(t.is_indefinite());
        assert_eq!(t.value(), &[1, 2, 3]);
        assert_eq!(Header::parse(&b[..n]).unwrap().length(), Length::Indefinite);
        assert_eq!(Header::parse(&b[..n]).unwrap().total_len(), None);
    }

    #[test]
    fn iterates_and_stops_after_an_error() {
        let mut buf = [0u8; 64];
        let (a, an) = klv(&KEY, &[0x01], &[7]);
        buf[..an].copy_from_slice(&a[..an]);
        let (f, fl) = klv(UniversalLabel::FILL.as_bytes(), &[0x02], &[0, 0]);
        buf[an..an + fl].copy_from_slice(&f[..fl]);
        let end = an + fl;
        buf[end..end + 3].copy_from_slice(&[0x06, 0x0E, 0x2B]);
        let data = &buf[..end + 3];

        let mut it = Triplets::new(data);
        assert_eq!(it.next().unwrap().unwrap().value(), &[7]);
        assert!(it.next().unwrap().unwrap().is_fill());
        assert_eq!(it.offset(), end);
        assert_eq!(it.remaining(), &[0x06, 0x0E, 0x2B]);
        assert_eq!(it.next(), Some(Err(Error::end(end + 17, end + 3))));
        assert_eq!(it.next(), None);
        assert_eq!(it.offset(), end);

        let opts = DecodeOptions { skip_fill: true, ..DecodeOptions::strict() };
        let mut it = Triplets::with_options(&data[..end], opts);
        assert_eq!(it.next().unwrap().unwrap().value(), &[7]);
        assert_eq!(it.next(), None);
        assert_eq!(Triplets::new(&[]).count(), 0);
    }

    #[test]
    fn write_to_copies_unaltered() {
        let (b, n) = klv(&KEY, &[0x83, 0, 0, 1], &[5]);
        let t = Triplet::parse(&b[..n]).unwrap();
        let mut out = [0u8; 32];
        let mut sink = crate::SliceSink::new(&mut out);
        assert_eq!(t.write_to(&mut sink), Ok(n));
        assert_eq!(sink.written(), &b[..n]);
    }

    #[test]
    fn exact_buffers_overrun_instead_of_waiting() {
        let (b, n) = klv(&KEY, &[0x05], &[1, 2]);
        let e = Triplet::parse_exact(&b[..n]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Overrun { needed: 22, available: 19 });
        assert!(!e.is_incomplete());
        assert!(Triplet::parse(&b[..n]).unwrap_err().is_incomplete());
    }

    #[test]
    fn labels_are_not_keys() {
        let mut label = KEY;
        label[4] = 0x04;
        let (b, n) = klv(&label, &[0x01], &[0xAA]);
        assert_eq!(Triplet::parse(&b[..n]), Err(Error::new(ErrorKind::LabelKey, 4)));
        // Reported as soon as byte 5 arrives.
        assert_eq!(Header::parse(&b[..5]), Err(Error::new(ErrorKind::LabelKey, 4)));
        assert!(Triplet::parse_with(&b[..n], &DecodeOptions::lenient()).is_ok());
        // Byte 5 only means something in a SMPTE key.
        let mut private = label;
        private[0] = 0x07;
        let opts = DecodeOptions { require_smpte_key: false, ..DecodeOptions::strict() };
        let (b, n) = klv(&private, &[0x01], &[0xAA]);
        assert!(Triplet::parse_with(&b[..n], &opts).is_ok());
    }

    #[test]
    fn lengths_past_any_buffer_overflow() {
        // A length that ends past isize::MAX can never be satisfied.
        let (b, n) = klv(&KEY, &[0x88, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], &[]);
        if usize::BITS == 64 {
            assert_eq!(Triplet::parse(&b[..n]), Err(Error::new(ErrorKind::LengthOverflow, KEY_LEN)));
        }
        let (b, n) = klv(&KEY, &[0x84, 0x7F, 0xFF, 0xFF, 0xD0], &[]);
        assert!(Triplet::parse(&b[..n]).unwrap_err().is_incomplete());
    }

    #[test]
    fn debug_and_hash_follow_the_bytes() {
        use core::hash::{Hash, Hasher};
        struct H(u64);
        impl Hasher for H {
            fn finish(&self) -> u64 {
                self.0
            }
            fn write(&mut self, bytes: &[u8]) {
                for &b in bytes {
                    self.0 = self.0.wrapping_mul(31).wrapping_add(u64::from(b));
                }
            }
        }
        let (b, n) = klv(&KEY, &[0x01], &[0xAA]);
        let a = Triplet::parse(&b[..n]).unwrap();
        let lenient = Triplet::parse_with(&b[..n], &DecodeOptions::lenient()).unwrap();
        assert_eq!(a, lenient);
        let (mut h1, mut h2) = (H(0), H(0));
        a.hash(&mut h1);
        lenient.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}
