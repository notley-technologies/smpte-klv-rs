//! Validation options shared by every decoder.

/// What to do with a top-level BER length of `0x80`, the non-deterministic
/// length of SMPTE ST 336:2017 section 5.3.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum IndefiniteLength {
    /// Report [`ErrorKind::IndefiniteLength`](crate::ErrorKind::IndefiniteLength).
    /// ST 336 requires an application document to say where such a value
    /// ends; without one, the end cannot be found.
    #[default]
    Reject,
    /// The value runs to the end of the buffer. Use this when the buffer
    /// boundary is the "alternative method of locating the end" the
    /// application defines, for example one KLV item per transport packet.
    ToEnd,
}

/// How strictly to validate while decoding.
///
/// Framing rules are always enforced, since getting them wrong would
/// misplace every following item: BER lengths (reserved `0xFF`, `0x80` where
/// the end of a value cannot be found otherwise, lengths past the end of the
/// data or of the containing set or pack), tag and length fields of every
/// set and pack coding, and Global Tag termination.
///
/// The default, [`DecodeOptions::strict`], also enforces these rules of
/// SMPTE ST 336:2017 and ISO/IEC 8825-1 that real encoders sometimes break:
///
/// - keys start with the SMPTE prefix ([`require_smpte_key`](Self::require_smpte_key));
/// - a SMPTE Label is not used as a key ([`reject_label_keys`](Self::reject_label_keys));
/// - BER-OID local tags and Global Tag words are in their shortest form
///   ([`strict_oid`](Self::strict_oid));
/// - Global Set designators and tags have the shape section 7.3 requires
///   ([`strict_global_set`](Self::strict_global_set)).
///
/// [`DecodeOptions::lenient`] turns off all but the first. Some rules are not
/// checked while decoding by either preset, because they do not affect
/// framing and ST 336 asks decoders to pass unknown data on: the full syntax
/// of a key ([`UniversalLabel::is_well_formed`](crate::UniversalLabel::is_well_formed)
/// checks it), the registry ranges of key bytes 5 to 8, the Global Set
/// Structure Designator, and the order and uniqueness of items.
///
/// ```
/// use smpte_klv::{DecodeOptions, LocalSet, TagEncoding, LengthEncoding};
///
/// // Tag 5 padded to two bytes: not the shortest BER-OID form.
/// let value = [0x80, 0x05, 0x01, 0xAA];
/// let set = LocalSet::new(&value, TagEncoding::BerOid, LengthEncoding::Ber);
/// assert!(set.iter().next().unwrap().is_err());
///
/// let set = set.with_options(DecodeOptions::lenient());
/// assert_eq!(set.iter().next().unwrap().unwrap().tag, 5);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct DecodeOptions {
    /// Require keys, including the item keys a Global Set rebuilds, to start
    /// with the SMPTE prefix `06 0E 2B 34` (ST 336:2017 section 5.2.1),
    /// reporting
    /// [`ErrorKind::InvalidKey`](crate::ErrorKind::InvalidKey) otherwise. The
    /// streaming `Decoder` (with the `alloc` feature) can only resynchronise
    /// after damaged input when this is set. Default true in both presets.
    pub require_smpte_key: bool,
    /// Top-level `0x80` lengths. Default [`IndefiniteLength::Reject`].
    pub indefinite_length: IndefiniteLength,
    /// Reject BER-OID local tags and Global Tag words that are not in their
    /// shortest form (ISO/IEC 8825-1 8.19.2), reporting
    /// [`ErrorKind::NonMinimalOid`](crate::ErrorKind::NonMinimalOid).
    /// Default true; false in [`lenient`](Self::lenient).
    pub strict_oid: bool,
    /// Reject Global Sets whose designator is not 2 to 8 significant bytes
    /// followed by zeros starting with the UL header, and Global Tags
    /// shorter than 2 words (ST 336:2017 section 7.3). Default true; false
    /// in [`lenient`](Self::lenient).
    pub strict_global_set: bool,
    /// Reject a SMPTE key (including a key a Global Set rebuilds) whose
    /// byte 5 is `0x04`, a SMPTE Label, with
    /// [`ErrorKind::LabelKey`](crate::ErrorKind::LabelKey): ST 336:2017
    /// section 9 says labels "shall not be used as the Key in KLV coding".
    /// A label found where a key is expected is a standalone 16-byte item
    /// with no length or value, so reading a length after it would misframe
    /// what follows; the streaming decoder skips it as damage and
    /// resynchronises on the next key. Default true; false in
    /// [`lenient`](Self::lenient).
    pub reject_label_keys: bool,
    /// Skip KLV Fill items (ST 336:2017 section 5.5 lets applications drop
    /// them) when iterating triplets, Universal Set items and Global Set
    /// items, and in the streaming decoder. Default false.
    pub skip_fill: bool,
}

impl DecodeOptions {
    /// Enforce every rule listed above. The default.
    pub const fn strict() -> Self {
        DecodeOptions {
            require_smpte_key: true,
            indefinite_length: IndefiniteLength::Reject,
            strict_oid: true,
            strict_global_set: true,
            reject_label_keys: true,
            skip_fill: false,
        }
    }

    /// Accept non-minimal BER-OID tags, loosely formed Global Sets and
    /// labels used as keys, but still require SMPTE keys. Every field is
    /// set here explicitly, so a check added to [`strict`](Self::strict)
    /// later does not change what this preset accepts.
    pub const fn lenient() -> Self {
        DecodeOptions {
            require_smpte_key: true,
            indefinite_length: IndefiniteLength::Reject,
            strict_oid: false,
            strict_global_set: false,
            reject_label_keys: false,
            skip_fill: false,
        }
    }
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self::strict()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets() {
        let s = DecodeOptions::default();
        assert_eq!(s, DecodeOptions::strict());
        assert!(s.require_smpte_key && s.strict_oid && s.strict_global_set && s.reject_label_keys && !s.skip_fill);
        assert_eq!(s.indefinite_length, IndefiniteLength::Reject);
        let l = DecodeOptions::lenient();
        assert!(l.require_smpte_key && !l.strict_oid && !l.strict_global_set && !l.reject_label_keys && !l.skip_fill);
        assert_eq!(l.indefinite_length, IndefiniteLength::Reject);
    }
}
