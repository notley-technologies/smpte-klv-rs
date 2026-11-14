//! SMPTE ST 336 Key-Length-Value (KLV) parser and encoder.
//!
//! KLV is the byte-level coding SMPTE ST 336 defines for metadata, and the
//! foundation of MXF, MISB motion imagery metadata and many other formats.
//! This crate implements ST 336 itself and nothing above it: no dictionary
//! of keys, no interpretation of values. Formats built on KLV, such as
//! MISB ST 0601, belong in crates that use this one.
//!
//! - [`UniversalLabel`]: the 16-byte keys, with their registry fields.
//! - [`ber`]: BER lengths and BER-OID values.
//! - [`Triplet`], [`Triplets`], [`Header`]: zero-copy decoding of KLV
//!   triplets from a buffer, and incremental decoding that says how many
//!   bytes the buffer must hold to make progress.
//! - [`Group`]: the five group codings, [`UniversalSet`], [`GlobalSet`],
//!   [`LocalSet`], [`VariableLengthPack`] and [`DefinedLengthPack`], chosen
//!   from byte 6 of the key ([`GroupCoding`]) or given explicitly.
//! - [`encode`]: writers for triplets and every kind of group.
//! - [`Decoder`]: push-based decoding of a stream in chunks of any size,
//!   with bounded memory and resynchronisation after damage.
//!
//! Decode a triplet and the Local Set inside it:
//!
//! ```
//! use smpte_klv::{Group, Triplet};
//!
//! let packet = [
//!     0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01, // key: a Local Set with BER-OID
//!     0x0E, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, //      tags and BER lengths
//!     0x07,                                           // length
//!     0x41, 0x01, 0x13,                               // tag 65, length 1
//!     0x81, 0x01, 0x01, 0x2A,                         // tag 129, length 1
//! ];
//! let triplet = Triplet::parse(&packet)?;
//! let Some(Group::Local(set)) = triplet.group() else { panic!("not a local set") };
//! for item in &set {
//!     let item = item?;
//!     println!("tag {} = {:02X?}", item.tag, item.value);
//! }
//! assert_eq!(set.get(129)?.map(|i| i.value), Some(&[0x2A][..]));
//! # Ok::<(), smpte_klv::Error>(())
//! ```
//!
//! Or push a stream as it arrives:
//!
//! ```no_run
//! # #[cfg(feature = "alloc")]
//! # fn main() {
//! # fn recv() -> Vec<u8> { vec![] }
//! let mut decoder = smpte_klv::Decoder::new();
//! loop {
//!     decoder.push(&recv());
//!     for frame in decoder.frames() {
//!         println!("{} ({} bytes)", frame.key(), frame.value().len());
//!     }
//! }
//! # }
//! # #[cfg(not(feature = "alloc"))]
//! # fn main() {}
//! ```
//!
//! # Validation
//!
//! Decoding never panics, never reads out of bounds and never allocates
//! based on a length read from the input. Malformed and truncated input is
//! reported as an [`Error`] with a byte offset; [`Error::is_incomplete`]
//! separates "wait for more bytes" from "this is wrong" (anything inside a
//! set or pack is never incomplete, as its size is fixed). How strictly the
//! rules that do not affect framing are enforced is up to
//! [`DecodeOptions`]; its documentation lists what the strict default
//! checks and what no preset checks while decoding.
//!
//! The encoders check what they are given, so that their output decodes
//! under the strict defaults to exactly the items that went in; the
//! low-level [`encode::write_triplet`] and [`encode::write_header`] write
//! any key unchecked.
//!
//! # Features
//!
//! - `std` (default): `std::error::Error` for the error types. Implies
//!   `alloc`.
//! - `alloc`: the streaming [`Decoder`] and the group encoders. Without it
//!   the crate is `no_std` and allocation-free: decoding borrows from the
//!   input and encoding writes to a [`SliceSink`].
//! - `capi`: the C interface declared in `include/smpte_klv.h`. Implies `std`.
//! - `serde`: `Serialize` for labels, codings, options, errors and stats.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Without `alloc` the docs still mention the allocating types by name.
#![cfg_attr(not(feature = "alloc"), allow(rustdoc::broken_intra_doc_links))]
#![warn(missing_docs)]
#![cfg_attr(not(feature = "capi"), forbid(unsafe_code))]
#![cfg_attr(feature = "capi", deny(unsafe_code))]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod ber;
#[cfg(feature = "capi")]
mod capi;
mod coding;
pub mod encode;
mod error;
mod group;
mod options;
#[cfg(feature = "alloc")]
mod stream;
mod triplet;
mod ul;

pub use ber::{BerForm, Length};
pub use coding::{GroupCoding, GroupKind, LengthEncoding, TagEncoding};
pub use encode::{Sink, SliceSink};
#[cfg(feature = "alloc")]
pub use encode::{
    DefinedLengthPackEncoder, GlobalSetEncoder, LocalSetEncoder, UniversalSetEncoder, VariableLengthPackEncoder,
};
pub use error::{Error, ErrorKind};
pub use group::{
    DefinedItems, DefinedLengthPack, GlobalItem, GlobalItems, GlobalSet, Group, LocalItem, LocalItems, LocalSet,
    PackItem, PackItems, PackReader, UniversalSet, VariableLengthPack,
};
pub use options::{DecodeOptions, IndefiniteLength};
#[cfg(feature = "alloc")]
pub use stream::{Config, Decoder, Frame, Stats, FRAME_OVERHEAD};
pub use triplet::{Header, Triplet, Triplets, KEY_LEN};
pub use ul::{Arcs, Category, ParseLabelError, UniversalLabel, Urn};
