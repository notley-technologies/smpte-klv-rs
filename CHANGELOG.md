# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/).

## Unreleased

### Added

- A versioned C ABI for triplets, sets, packs, and streaming, with C examples, shared and static libraries, pkg-config metadata, and CMake targets.
- Universal labels: registry fields, group coding from byte 6, version-insensitive comparison, Fill item detection, a well-formedness check against ST 336:2017 Tables 2 and 3, OID arcs, dotted and SMPTE ST 2029 URN forms, and strict parsing of the usual text forms.
- BER length coding (short, long, non-minimal, indefinite and reserved forms) and BER-OID coding.
- Zero-copy decoding of triplets, headers and every SMPTE ST 336 group coding: Universal, Global and Local Sets, Variable-Length and Defined-Length Packs, with all 26 registry designators of ST 336:2017 Tables 3 to 6.
- Strict and lenient validation through `DecodeOptions`, including rejection of SMPTE Labels used as keys (ST 336:2017 section 9).
- Errors that separate input that is incomplete (`UnexpectedEnd`) from items that run past the set or pack holding them (`Overrun`).
- Encoders for triplets and every kind of group, to a `Vec` or a fixed buffer, that refuse anything whose output would not decode back to the same items.
- Push-based stream decoder with bounded memory, key filtering, resynchronisation (optionally treating reserved key categories as damage, and bounding how far a damaged length can make it skip) and byte-exact statistics.
- `no_std` support without an allocator, and an optional `serde` feature.
- Fuzz harnesses for the stable toolchain and cargo-fuzz.
- Examples: `klvdump`, `encode` and `stream`.
