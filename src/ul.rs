//! SMPTE universal labels (SMPTE ST 298, ST 336:2017 section 5.2).

use crate::ber;
use crate::coding::GroupCoding;
use core::fmt;
use core::str::FromStr;

/// A 16-byte SMPTE universal label: the key of every KLV triplet.
///
/// The bytes are laid out as in SMPTE ST 336:2017 Table 2. The standard
/// numbers them from 1, and so do the method descriptions here:
///
/// | Bytes | Field | Accessor |
/// |---|---|---|
/// | 1-4 | `06 0E 2B 34`: OID, size, ISO/ORG, SMPTE | [`is_smpte`](Self::is_smpte) |
/// | 5 | Category Designator | [`category`](Self::category) |
/// | 6 | Registry Designator | [`registry_designator`](Self::registry_designator) |
/// | 7 | Structure Designator | [`structure_designator`](Self::structure_designator) |
/// | 8 | Version Number | [`version`](Self::version) |
/// | 9-16 | Item Designator | [`item_designator`](Self::item_designator) |
///
/// Displayed as dotted upper-case hex, for example
/// `06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00`; [`urn`](Self::urn)
/// gives the SMPTE ST 2029 URN form. [`FromStr`] accepts both, and the forms
/// listed under [`ParseLabelError`].
///
/// ```
/// use smpte_klv::{Category, GroupCoding, LengthEncoding, TagEncoding, UniversalLabel};
///
/// let key: UniversalLabel = "06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00".parse().unwrap();
/// assert!(key.is_smpte());
/// assert_eq!(key.category(), Category::Group);
/// assert_eq!(
///     key.group_coding(),
///     Some(GroupCoding::LocalSet { tag: TagEncoding::BerOid, length: LengthEncoding::Ber })
/// );
/// assert_eq!(key.urn().to_string(), "urn:smpte:ul:060e2b34.020b0101.0e010301.01000000");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UniversalLabel([u8; 16]);

/// The registry category, byte 5 of a universal label (SMPTE ST 336:2017
/// Table 3).
///
/// Values compare by their byte, so `Category::Reserved(0x02)` equals
/// [`Category::Group`]; [`Category::from_byte`] never produces the former.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum Category {
    /// `0x01`: individual data items from a dictionary (section 6).
    Dictionary,
    /// `0x02`: sets and packs (section 7); byte 6 gives the
    /// [`GroupCoding`].
    Group,
    /// `0x03`: wrappers and containers (section 8).
    WrapperOrContainer,
    /// `0x04`: labels, which identify something by themselves and are never
    /// used as keys (section 9).
    Label,
    /// `0x05`: registered private information (section 10, SMPTE RP 225).
    RegisteredPrivate,
    /// Any other value. ST 336 reserves the one-byte values it does not
    /// define; `0x00` and `0x80` to `0xFF` are not one-byte sub-identifiers
    /// at all.
    Reserved(u8),
}

impl PartialEq for Category {
    fn eq(&self, other: &Self) -> bool {
        self.to_byte() == other.to_byte()
    }
}

impl Eq for Category {}

impl core::hash::Hash for Category {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_byte().hash(state);
    }
}

impl Category {
    /// The category for a byte 5 value.
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Category::Dictionary,
            0x02 => Category::Group,
            0x03 => Category::WrapperOrContainer,
            0x04 => Category::Label,
            0x05 => Category::RegisteredPrivate,
            b => Category::Reserved(b),
        }
    }

    /// The byte 5 value.
    pub const fn to_byte(self) -> u8 {
        match self {
            Category::Dictionary => 0x01,
            Category::Group => 0x02,
            Category::WrapperOrContainer => 0x03,
            Category::Label => 0x04,
            Category::RegisteredPrivate => 0x05,
            Category::Reserved(b) => b,
        }
    }
}

impl UniversalLabel {
    /// The four bytes every SMPTE universal label starts with (SMPTE ST 298):
    /// object identifier, label size 14, ISO/ORG (1.3), SMPTE (52).
    pub const PREFIX: [u8; 4] = [0x06, 0x0E, 0x2B, 0x34];

    /// The KLV Fill item, also called the Empty data item (SMPTE ST
    /// 336:2017 section 5.5; key from the SMPTE metadata dictionary, as used
    /// by SMPTE ST 377-1). Encoders disagree on its version byte, so compare
    /// with [`is_fill`](Self::is_fill), which ignores it.
    pub const FILL: UniversalLabel = UniversalLabel([
        0x06, 0x0E, 0x2B, 0x34, 0x01, 0x01, 0x01, 0x02, 0x03, 0x01, 0x02, 0x10, 0x01, 0x00, 0x00, 0x00,
    ]);

    /// A label from its 16 bytes. Any bytes are accepted; see
    /// [`is_smpte`](Self::is_smpte) and [`is_well_formed`](Self::is_well_formed).
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        UniversalLabel(bytes)
    }

    /// A label from the first 16 bytes of `bytes`, or `None` if it is
    /// shorter.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let b = bytes.get(..16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Some(UniversalLabel(a))
    }

    /// The 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The 16 bytes, by value.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// True when the label starts with [`PREFIX`](Self::PREFIX). ST 336
    /// requires this of every key.
    pub const fn is_smpte(&self) -> bool {
        let b = &self.0;
        b[0] == Self::PREFIX[0] && b[1] == Self::PREFIX[1] && b[2] == Self::PREFIX[2] && b[3] == Self::PREFIX[3]
    }

    /// Byte 5, the Category Designator.
    pub const fn category(&self) -> Category {
        Category::from_byte(self.0[4])
    }

    /// Byte 6, the Registry Designator. For groups it encodes the
    /// [`GroupCoding`].
    pub const fn registry_designator(&self) -> u8 {
        self.0[5]
    }

    /// Byte 7, the Structure Designator.
    pub const fn structure_designator(&self) -> u8 {
        self.0[6]
    }

    /// Byte 8, the Version Number of the register that first defined the
    /// item. ST 336:2017 section 5.2.3 lets decoders ignore it for items
    /// SMPTE registers; registrants of other items set their own policy. See
    /// [`eq_ignoring_version`](Self::eq_ignoring_version).
    pub const fn version(&self) -> u8 {
        self.0[7]
    }

    /// Bytes 9 to 16, the Item Designator.
    pub fn item_designator(&self) -> &[u8; 8] {
        let s: &[u8] = &self.0[8..];
        s.try_into().expect("8 bytes")
    }

    /// For a SMPTE group key (byte 5 is `0x02`), how its value is coded,
    /// from byte 6. `None` for labels without the SMPTE prefix, whose bytes 5
    /// and 6 mean nothing to ST 336, for other categories, and for registry
    /// designators that ST 336 does not define; ST 336:2017 section 5.2.1
    /// says to pass such triplets on to the application uninterpreted.
    pub const fn group_coding(&self) -> Option<GroupCoding> {
        if !self.is_smpte() || self.0[4] != 0x02 {
            return None;
        }
        GroupCoding::from_registry_designator(self.0[5])
    }

    /// The same label with byte 6 replaced so that it declares `coding`
    /// (and byte 5 set to `0x02`). ST 336:2017 section 7.6 notes that a group
    /// can switch between set and pack codings by changing only this byte.
    /// Like every key, it only declares a coding if it starts with the SMPTE
    /// prefix (see [`group_coding`](Self::group_coding)).
    #[must_use]
    pub const fn with_group_coding(self, coding: GroupCoding) -> Self {
        let mut b = self.0;
        b[4] = 0x02;
        b[5] = coding.registry_designator();
        UniversalLabel(b)
    }

    /// The same label with byte 8, the version, replaced.
    #[must_use]
    pub const fn with_version(self, version: u8) -> Self {
        let mut b = self.0;
        b[7] = version;
        UniversalLabel(b)
    }

    /// Compare two labels ignoring byte 8, the version number. ST 336:2017
    /// section 5.2.3 lets decoders ignore it, and encoders disagree on which
    /// register version they stamp into otherwise identical labels.
    pub fn eq_ignoring_version(&self, other: &UniversalLabel) -> bool {
        self.0[..7] == other.0[..7] && self.0[8..] == other.0[8..]
    }

    /// True for the KLV Fill item, whatever its version byte.
    pub fn is_fill(&self) -> bool {
        self.eq_ignoring_version(&Self::FILL)
    }

    /// True when the label follows the syntax ST 336:2017 requires of a
    /// key: the SMPTE prefix; bytes 5 to 8 each a one-byte field of `0x01`
    /// to `0x7F` (Table 2, Table 3); an Item Designator of at least one byte
    /// (section 5.2.4); every sub-identifier BER-OID coded in its shortest
    /// form; and nothing but zero bytes after the first zero-valued
    /// sub-identifier, which terminates the label (section 5.2.1).
    ///
    /// Decoding never requires this. It is a check for encoders and
    /// conformance tools; private labels in the wild sometimes fail it.
    pub fn is_well_formed(&self) -> bool {
        if !self.is_smpte() || !self.0[4..8].iter().all(|&b| (0x01..=0x7F).contains(&b)) || self.0[8] == 0 {
            return false;
        }
        let mut rest = &self.0[8..];
        while !rest.is_empty() {
            match ber::decode_oid(rest, true) {
                Ok((0, _)) => return rest.iter().all(|&b| b == 0),
                Ok((_, n)) => rest = &rest[n..],
                Err(_) => return false,
            }
        }
        true
    }

    /// The object identifier arcs the label encodes: `1, 3, 52, ...` for a
    /// SMPTE label, stopping at the zero sub-identifier that terminates it.
    /// Bytes 1 and 2 (the OID tag and length) are not arcs. Decoding is
    /// lenient: a sub-identifier padded with `0x80` gives its value, and
    /// iteration stops early at a sub-identifier left unfinished by the last
    /// byte or too large for a `u64`. Check
    /// [`is_well_formed`](Self::is_well_formed) first if that matters.
    ///
    /// ```
    /// let key = smpte_klv::UniversalLabel::FILL;
    /// let arcs: Vec<u64> = key.arcs().collect();
    /// assert_eq!(arcs, [1, 3, 52, 1, 1, 1, 2, 3, 1, 2, 16, 1]);
    /// ```
    pub fn arcs(&self) -> Arcs {
        Arcs { bytes: self.0, pos: 2, pending: None }
    }

    /// The label in SMPTE ST 2029 URN form,
    /// `urn:smpte:ul:060e2b34.01010102.03010210.01000000`.
    pub const fn urn(&self) -> Urn {
        Urn(*self)
    }
}

impl From<[u8; 16]> for UniversalLabel {
    fn from(b: [u8; 16]) -> Self {
        UniversalLabel(b)
    }
}

impl From<UniversalLabel> for [u8; 16] {
    fn from(ul: UniversalLabel) -> Self {
        ul.0
    }
}

impl AsRef<[u8]> for UniversalLabel {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for UniversalLabel {
    type Error = ParseLabelError;

    /// Exactly 16 bytes.
    fn try_from(b: &[u8]) -> Result<Self, ParseLabelError> {
        if b.len() != 16 {
            return Err(ParseLabelError(()));
        }
        Ok(UniversalLabel::from_slice(b).expect("16 bytes"))
    }
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Write the 16 bytes as hex into `out`, with `sep` after every `group`
/// bytes but the last, and return the length used.
fn hex_into(bytes: &[u8; 16], digits: &[u8; 16], group: usize, sep: u8, out: &mut [u8; 48]) -> usize {
    let mut n = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && i % group == 0 {
            out[n] = sep;
            n += 1;
        }
        out[n] = digits[usize::from(b >> 4)];
        out[n + 1] = digits[usize::from(b & 0x0F)];
        n += 2;
    }
    n
}

/// Write `s` honouring the formatter's width, fill and alignment (left by
/// default), but never truncating it to a precision: a label cut short would
/// be a different label.
fn pad(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    use fmt::Write;
    let len = s.len(); // ASCII
    let Some(width) = f.width().filter(|&w| w > len) else {
        return f.write_str(s);
    };
    let fill = width - len;
    let (before, after) = match f.align() {
        Some(fmt::Alignment::Right) => (fill, 0),
        Some(fmt::Alignment::Center) => (fill / 2, fill - fill / 2),
        _ => (0, fill),
    };
    let c = f.fill();
    for _ in 0..before {
        f.write_char(c)?;
    }
    f.write_str(s)?;
    for _ in 0..after {
        f.write_char(c)?;
    }
    Ok(())
}

/// Honours width, fill and alignment, and ignores precision.
impl fmt::Display for UniversalLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = [0u8; 48];
        let n = hex_into(&self.0, HEX_UPPER, 1, b'.', &mut out);
        pad(f, core::str::from_utf8(&out[..n]).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for UniversalLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A label in SMPTE ST 2029 URN form, from [`UniversalLabel::urn`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Urn(UniversalLabel);

impl Urn {
    /// The label.
    pub const fn label(&self) -> UniversalLabel {
        self.0
    }
}

/// Honours width, fill and alignment, and ignores precision.
impl fmt::Display for Urn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const URN: &[u8; 13] = b"urn:smpte:ul:";
        let mut out = [0u8; 13 + 35];
        out[..13].copy_from_slice(URN);
        let mut body = [0u8; 48];
        let n = hex_into(&self.0 .0, HEX_LOWER, 4, b'.', &mut body);
        out[13..13 + n].copy_from_slice(&body[..n]);
        pad(f, core::str::from_utf8(&out[..13 + n]).map_err(|_| fmt::Error)?)
    }
}

/// The OID arcs of a label, from [`UniversalLabel::arcs`].
#[derive(Clone, Debug)]
pub struct Arcs {
    bytes: [u8; 16],
    pos: usize,
    /// The second arc, split from the first sub-identifier.
    pending: Option<u64>,
}

impl Iterator for Arcs {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if let Some(v) = self.pending.take() {
            return Some(v);
        }
        let first = self.pos == 2;
        let rest = &self.bytes[self.pos..];
        let Ok((v, n)) = ber::decode_oid(rest, false) else {
            self.pos = self.bytes.len();
            return None;
        };
        if v == 0 && !first {
            self.pos = self.bytes.len();
            return None;
        }
        self.pos += n;
        if first {
            // ISO/IEC 8825-1 8.19.4: the first sub-identifier packs two arcs.
            let x = (v / 40).min(2);
            self.pending = Some(v - 40 * x);
            return Some(x);
        }
        Some(v)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let pending = usize::from(self.pending.is_some());
        (pending, Some(pending + self.bytes.len() - self.pos + usize::from(self.pos == 2)))
    }
}

impl core::iter::FusedIterator for Arcs {}

/// A string or byte slice that is not a universal label.
///
/// [`UniversalLabel`]'s `FromStr` accepts, ignoring ASCII whitespace at
/// either end:
///
/// - 32 hex digits: `060E2B34020B01010E01030101000000`;
/// - 16 two-digit groups joined by one of `.`, `-`, `:` or a space, the same
///   one throughout: `06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00`;
/// - 4 eight-digit groups joined by `.`, the SMPTE ST 2029 form, with or
///   without the `urn:smpte:ul:` prefix (in any case):
///   `urn:smpte:ul:060e2b34.020b0101.0e010301.01000000`.
///
/// Hex digits may be upper or lower case. Anything else, including
/// separators that do not fall between bytes, is an error, so a mistyped
/// label cannot parse as a different one. `TryFrom<&[u8]>` also returns this
/// error, for a slice that is not exactly 16 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParseLabelError(());

impl fmt::Display for ParseLabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a 16-byte universal label")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseLabelError {}

impl FromStr for UniversalLabel {
    type Err = ParseLabelError;

    fn from_str(s: &str) -> Result<Self, ParseLabelError> {
        let b = s.trim_matches(|c: char| c.is_ascii_whitespace()).as_bytes();
        const URN: &[u8] = b"urn:smpte:ul:";
        let parsed = if b.len() >= URN.len() && b[..URN.len()].eq_ignore_ascii_case(URN) {
            parse_grouped(&b[URN.len()..], 8, Some(b'.'))
        } else {
            match b.len() {
                32 => parse_grouped(b, 32, None),
                35 => parse_grouped(b, 8, Some(b'.')),
                47 if matches!(b[2], b'.' | b'-' | b':' | b' ') => parse_grouped(b, 2, Some(b[2])),
                _ => None,
            }
        };
        parsed.map(UniversalLabel).ok_or(ParseLabelError(()))
    }
}

/// 32 hex digits in groups of `group` digits, with `sep` between groups.
fn parse_grouped(b: &[u8], group: usize, sep: Option<u8>) -> Option<[u8; 16]> {
    let stride = group + usize::from(sep.is_some());
    let expected = 32 + if sep.is_some() { 32 / group - 1 } else { 0 };
    if b.len() != expected {
        return None;
    }
    let mut out = [0u8; 16];
    let mut n = 0;
    for (i, &c) in b.iter().enumerate() {
        if let Some(sep) = sep {
            if i % stride == group {
                if c != sep {
                    return None;
                }
                continue;
            }
        }
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        out[n / 2] |= if n % 2 == 0 { v << 4 } else { v };
        n += 1;
    }
    Some(out)
}

#[cfg(feature = "serde")]
impl serde::Serialize for UniversalLabel {
    /// As the dotted hex string.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::{LengthEncoding, TagEncoding};

    const ST0601: [u8; 16] = [6, 0x0E, 0x2B, 0x34, 2, 0x0B, 1, 1, 0x0E, 1, 3, 1, 1, 0, 0, 0];

    #[test]
    fn fields() {
        let k = UniversalLabel::from_bytes(ST0601);
        assert!(k.is_smpte());
        assert_eq!(k.category(), Category::Group);
        assert_eq!(k.registry_designator(), 0x0B);
        assert_eq!(k.structure_designator(), 0x01);
        assert_eq!(k.version(), 0x01);
        assert_eq!(k.item_designator(), &[0x0E, 1, 3, 1, 1, 0, 0, 0]);
        assert_eq!(k.as_bytes(), &ST0601);
        assert_eq!(k.to_bytes(), ST0601);
        assert_eq!(<[u8; 16]>::from(k), ST0601);
        assert_eq!(k.as_ref(), &ST0601[..]);
        assert_eq!(k.group_coding(), Some(GroupCoding::LocalSet { tag: TagEncoding::BerOid, length: LengthEncoding::Ber }));
    }

    #[test]
    fn categories() {
        for b in 0..=255u8 {
            assert_eq!(Category::from_byte(b).to_byte(), b);
        }
        assert_eq!(Category::from_byte(4), Category::Label);
        assert_eq!(Category::from_byte(6), Category::Reserved(6));
        assert_eq!(Category::Reserved(2), Category::Group);
        assert_ne!(Category::Reserved(6), Category::Reserved(7));
        // Bytes 5 and 6 mean nothing without the SMPTE prefix.
        let mut private = ST0601;
        private[0] = 0x07;
        assert_eq!(UniversalLabel::from_bytes(private).group_coding(), None);
        let mut dict = ST0601;
        dict[4] = 1;
        assert_eq!(UniversalLabel::from_bytes(dict).group_coding(), None);
        let mut unknown = ST0601;
        unknown[5] = 0x06;
        assert_eq!(UniversalLabel::from_bytes(unknown).group_coding(), None);
    }

    #[test]
    fn rewriting() {
        let k = UniversalLabel::from_bytes(ST0601);
        let pack = k.with_group_coding(GroupCoding::DefinedLengthPack);
        assert_eq!(pack.registry_designator(), 0x05);
        assert_eq!(pack.item_designator(), k.item_designator());
        let v = k.with_version(0x0F);
        assert_ne!(v, k);
        assert!(v.eq_ignoring_version(&k));
        let mut other = ST0601;
        other[12] = 2;
        assert!(!k.eq_ignoring_version(&UniversalLabel::from_bytes(other)));
    }

    #[test]
    fn fill() {
        assert!(UniversalLabel::FILL.is_fill());
        assert!(UniversalLabel::FILL.with_version(1).is_fill());
        assert!(!UniversalLabel::from_bytes(ST0601).is_fill());
        assert!(UniversalLabel::FILL.is_well_formed());
        assert_eq!(UniversalLabel::FILL.category(), Category::Dictionary);
    }

    #[test]
    fn well_formed() {
        assert!(UniversalLabel::from_bytes(ST0601).is_well_formed());
        let mut b = ST0601;
        b[0] = 0x07;
        assert!(!UniversalLabel::from_bytes(b).is_well_formed());
        // A non-zero byte after the terminating zero.
        let mut b = ST0601;
        b[15] = 1;
        assert!(!UniversalLabel::from_bytes(b).is_well_formed());
        // Multi-byte sub-identifier 128 = 81 00: its zero byte is not a
        // terminator.
        let mut b = ST0601;
        b[13] = 0x81;
        b[14] = 0x00;
        assert!(UniversalLabel::from_bytes(b).is_well_formed());
        // Non-minimal sub-identifier.
        let mut b = ST0601;
        b[13] = 0x80;
        b[14] = 0x01;
        assert!(!UniversalLabel::from_bytes(b).is_well_formed());
        // Unfinished final sub-identifier.
        let mut b = ST0601;
        b[15] = 0x81;
        assert!(!UniversalLabel::from_bytes(b).is_well_formed());
        // All 16 bytes significant.
        let full = [6, 0x0E, 0x2B, 0x34, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert!(UniversalLabel::from_bytes(full).is_well_formed());
        // Table 2 fields that are zero, or multi-byte, and an empty Item
        // Designator.
        for (i, v) in [(4, 0), (5, 0), (6, 0x80), (7, 0x81), (8, 0)] {
            let mut b = ST0601;
            b[i] = v;
            assert!(!UniversalLabel::from_bytes(b).is_well_formed(), "byte {i} = {v:#x}");
        }
        assert!(!UniversalLabel::from_bytes([6, 0x0E, 0x2B, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_well_formed());
    }

    #[test]
    fn arcs() {
        let k = UniversalLabel::from_bytes(ST0601);
        let mut a = [0u64; 16];
        let mut n = 0;
        for v in k.arcs() {
            a[n] = v;
            n += 1;
        }
        assert_eq!(&a[..n], &[1, 3, 52, 2, 11, 1, 1, 14, 1, 3, 1, 1]);
        let multi = UniversalLabel::from_bytes([6, 0x0E, 0x2B, 0x34, 1, 1, 1, 1, 0x81, 0x00, 5, 0, 0, 0, 0, 0]);
        assert_eq!(multi.arcs().nth(7), Some(128));
        assert_eq!(multi.arcs().count(), 9);
        let unfinished = UniversalLabel::from_bytes([6, 0x0E, 0x2B, 0x34, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x81]);
        assert_eq!(unfinished.arcs().count(), 14);
        // Arcs own the label, so a temporary works and the iterator fuses.
        let mut it = UniversalLabel::from_bytes(ST0601).arcs();
        let (lo, hi) = it.size_hint();
        assert!(lo <= 12 && hi >= Some(12));
        assert_eq!(it.by_ref().count(), 12);
        assert_eq!(it.next(), None);
        assert_eq!(it.size_hint().0, 0);
    }

    #[test]
    fn parsing() {
        let k = UniversalLabel::from_bytes(ST0601);
        for s in [
            "06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00",
            "060e2b34020b01010e01030101000000",
            "06 0E 2B 34 02 0B 01 01 0E 01 03 01 01 00 00 00",
            "urn:smpte:ul:060e2b34.020b0101.0e010301.01000000",
            "URN:SMPTE:UL:060E2B34.020B0101.0E010301.01000000",
            "  06-0E-2B-34-02-0B-01-01-0E-01-03-01-01-00-00-00\n",
            "06:0e:2b:34:02:0b:01:01:0e:01:03:01:01:00:00:00",
            "060e2b34.020b0101.0e010301.01000000",
        ] {
            assert_eq!(s.parse::<UniversalLabel>(), Ok(k), "{s}");
        }
        for s in [
            "",
            "06.0E",
            "060e2b34020b01010e0103010100000000",
            "060e2b34020b01010e010301010000zz",
            "é",
            // A nibble moved across a separator.
            "6.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.000",
            // Mixed, leading, trailing or repeated separators.
            "06.0E-2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00",
            ".060E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.0",
            "06..0E2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00",
            // GUID grouping.
            "060e2b34-020b-0101-0e01-030101000000",
            "urn:smpte:ul:060e2b34020b01010e01030101000000",
            "urn:smpte:ul:",
            "+6.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00",
        ] {
            assert!(s.parse::<UniversalLabel>().is_err(), "{s}");
        }
    }

    #[test]
    fn slices() {
        assert_eq!(UniversalLabel::from_slice(&ST0601[..15]), None);
        let mut long = [0u8; 20];
        long[..16].copy_from_slice(&ST0601);
        assert_eq!(UniversalLabel::from_slice(&long), Some(UniversalLabel::from_bytes(ST0601)));
        assert!(UniversalLabel::try_from(&long[..]).is_err());
        assert_eq!(UniversalLabel::try_from(&ST0601[..]), Ok(UniversalLabel::from_bytes(ST0601)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn display() {
        use std::string::ToString;
        let k = UniversalLabel::from_bytes(ST0601);
        assert_eq!(k.to_string(), "06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00");
        assert_eq!(std::format!("{k:?}"), k.to_string());
        assert_eq!(k.urn().to_string(), "urn:smpte:ul:060e2b34.020b0101.0e010301.01000000");
        assert_eq!(k.to_string().parse::<UniversalLabel>(), Ok(k));
        assert_eq!(k.urn().to_string().parse::<UniversalLabel>(), Ok(k));
        assert_eq!(k.urn().label(), k);
        assert_eq!(ParseLabelError(()).to_string(), "not a 16-byte universal label");
        // Width and alignment apply to the whole label; precision never
        // truncates it, also inside a derived Debug.
        assert_eq!(std::format!("[{k:>48}]"), std::format!("[ {k}]"));
        assert_eq!(std::format!("[{k:-^49}]"), std::format!("[-{k}-]"));
        assert_eq!(std::format!("{k:.3}"), k.to_string());
        assert_eq!(std::format!("{:.2?}", (1.0f64, k)), std::format!("(1.00, {k})"));
        assert_eq!(std::format!("{:.5}", k.urn()), k.urn().to_string());
        // A urn of a temporary can be kept.
        let urn = UniversalLabel::FILL.urn();
        assert_eq!(urn.to_string(), "urn:smpte:ul:060e2b34.01010102.03010210.01000000");
    }
}
