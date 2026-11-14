# smpte-klv

A parser and encoder for SMPTE ST 336 Key-Length-Value (KLV) data. It reads 16-byte universal labels, BER lengths, BER-OID tags, and all five set and pack codings. You can decode triplets directly from a buffer or feed bytes to a bounded stream decoder. The library provides a Rust API and a C API with a stable ABI.

The library handles KLV framing. Applications such as MISB ST 0601 and MXF supply their own dictionaries and interpret the value bytes. The Rust crate has no required dependencies. The parser and slice encoder use safe Rust and can run without `std` or an allocator.

## Usage

Parse the first triplet in a buffer and read the items if it contains a Local Set. Byte 6 of the key selects the group decoder.

```rust
use smpte_klv::{Group, Triplet};

let triplet = Triplet::parse(&bytes)?;
println!("{} ({} bytes)", triplet.key(), triplet.value().len());
if let Some(Group::Local(set)) = triplet.group() {
    for item in &set {
        let item = item?;
        println!("tag {} = {:02X?}", item.tag, item.value);
    }
}
```

For a buffer containing several triplets, `Triplets::new(&bytes)` yields them in order and stops at the first error.

For a live feed, push each chunk and drain the completed frames.

```rust
let mut decoder = smpte_klv::Decoder::new();
for chunk in chunks {
    decoder.push(&chunk);
    for frame in decoder.frames() {
        handle(frame.key(), frame.value(), frame.offset());
    }
}
decoder.finish();
for frame in decoder.frames() {
    handle(frame.key(), frame.value(), frame.offset());
}
```

Use one `Decoder` per feed. To keep only frames with a particular key, call `set_filter` before the first push. The decoder checks each key before buffering its value.

## Reading KLV

| Call | Returns |
|---|---|
| `Header::parse(&bytes)` | the key and BER length, even if the value has yet to arrive |
| `triplet.key()`, `triplet.value()` | the universal label and borrowed value bytes |
| `triplet.as_bytes()` | the original encoding, including the length field, for forwarding unchanged |
| `triplet.group()` | a view of a Universal Set, Global Set, Local Set, Variable-Length Pack or Defined-Length Pack, when the key declares one |
| `key.group_coding()` | the group coding declared by byte 6, including the tag and length encodings where applicable |
| `key.eq_ignoring_version(&other)` | whether two universal labels match apart from their version byte |
| `error.offset()`, `error.is_incomplete()` | where decoding failed and whether more input could complete the triplet |

`Group::with_coding` takes an explicit coding when the defining document supplies one. Group iteration reads one level at a time. An item that overruns its enclosing set or pack returns `ErrorKind::Overrun`.

## Encoding groups

Build a Local Set with the tag and length coding declared by its key.

```rust
use smpte_klv::LocalSetEncoder;

let mut set = LocalSetEncoder::new(key)?;
set.item(2, &timestamp)?.item(65, &[19])?;
let packet = set.finish()?;
```

Each of the five group encoders checks that its output will decode under the strict defaults. For a checksum that covers the header, use `encode::write_header` and append the bytes from `into_value()`. For allocation-free encoding, pass a `SliceSink` over your own buffer to the writers in `encode`, `ber`, `TagEncoding` or `LengthEncoding`.

## Configuration

`Config` sets the stream decoder's memory limits and validation options.

```rust
use smpte_klv::{Config, Decoder};

let mut config = Config::default();
config.max_value_len = 64 * 1024;
config.options.skip_fill = true;
let mut decoder = Decoder::with_config(config);
```

| Field | Default | Purpose |
|---|---|---|
| `max_value_len` | 16 MiB | skip larger values without buffering them |
| `max_queue_bytes` | 64 MiB | bound queued frames and their bookkeeping. An empty queue can accept one larger frame |
| `max_skip_len` | `u64::MAX` | resynchronise on the next key if a triplet to be skipped declares more bytes than this limit |
| `options` | `DecodeOptions::strict()` | control key validation, BER-OID tags, Global Sets and Fill handling |
| `resync_on_reserved_category` | `false` | treat reserved key categories as damage when scanning for the next key |

With the defaults, the decoder recovers from damage by scanning for the SMPTE prefix `06 0E 2B 34`. Set both length limits near the largest triplet you expect to bound how much data a damaged length can consume. `decoder.stats()` counts frames, skipped bytes and recoveries. Each input byte is delivered, skipped or still buffered.

<a id="c-abi"></a>

## C API

Include `<smpte_klv.h>` to parse, stream or encode KLV. The header documents status codes, pointer lifetimes, thread use and how to set `struct_size`. [Public header](include/smpte_klv.h)

On Linux or macOS, build and install both libraries, the header and the pkg-config and CMake files.

```bash
make
sudo make install      # default prefix: /usr/local
```

Compile a C application with pkg-config.

```bash
cc app.c $(pkg-config --cflags --libs smpte_klv) -o app
```

In a CMake project, link the installed target.

```cmake
find_package(smpte_klv 0.1 REQUIRED)
target_link_libraries(app PRIVATE smpte_klv::smpte_klv)   # or smpte_klv::smpte_klv_static
```

- `smpte_klv_abi_version()` returns the ABI version to compare with `SMPTE_KLV_ABI_VERSION`. The shared library name carries the same version, for example `libsmpte_klv.so.1` on Linux.
- The CMake static target includes Rust's system libraries. For other build systems, `pkg-config --static --libs smpte_klv` lists them.
- Make accepts `PREFIX`, `LIBDIR`, `INCLUDEDIR` and `DESTDIR`. Use the same settings with `make uninstall`.
- On Windows with MSVC, `cargo rustc --release --lib --features capi --crate-type cdylib,staticlib` builds `smpte_klv.dll`, its import library `smpte_klv.dll.lib` and the static library `smpte_klv.lib` in `target/release`.

## Standards compliance

The rules are taken from SMPTE ST 336:2017 (which the 2007 edition matches for everything implemented here) and the ISO/IEC 8825-1 sections it cites.

| Rule | Where | Behaviour |
|---|---|---|
| Keys are 16-byte SMPTE ULs starting `06 0E 2B 34` | §5.2.1, Table 2 | Enforced by default (`require_smpte_key`), also for the keys Global Sets rebuild |
| SMPTE Labels (byte 5 `0x04`) are never keys | §9 | Strict: `ErrorKind::LabelKey`; the stream decoder skips one as damage; encoders refuse them |
| Byte 5 categories, byte 6 registry designators | Table 3 | `Category`, `GroupCoding` |
| Unknown bytes 5 and 6: hand K, L and V to the application, carry on | §5.2.1 | `group()` returns `None`, iteration continues |
| Store and forward unaltered | §5.2.1 | `Triplet::as_bytes`, `write_to` |
| BER length, short or long form at the sender's option, no maximum size | §5.3, X.690 8.1.3 | Non-minimal long forms are accepted, up to 126 bytes |
| `0xFF` length reserved | X.690 8.1.3.5 c | `ErrorKind::ReservedLength` |
| `0x80` non-deterministic length | §5.3 | Rejected by default, or the value runs to the end of the buffer (`IndefiniteLength::ToEnd`); always an error inside groups |
| Fill (Empty) items may be dropped; ignore their version | §5.5 | `UniversalLabel::is_fill`, `skip_fill` |
| Label termination, BER-OID sub-identifiers, Table 2 field sizes | §5.2.1, §5.2.4, Tables 2-3 | `UniversalLabel::is_well_formed` (a check, not enforced while decoding) |
| Global Set designator: 2-8 significant bytes, then zeros, including the UL header | §7.3 | Strict: `InvalidGlobalSetDesignator`; encoders require it |
| Global Set Structure Designator (byte 7) | §7.3 | Not used: the 2007 and 2017 Annex examples disagree on it, and the designator's terminator gives its length |
| Global Tags: 2-12 words, ended by a zero unless 12 words long; key = designator + tag, zero filled | §7.3 | A zero byte inside a multi-byte word is not taken as the terminator; encoders refuse keys that would not rebuild |
| Global Set length coding | Table 4 | `0x02`, `0x22`, `0x42`, `0x62` |
| Local Set tag and length codings | Table 5 | All 16 combinations; fixed-size fields are big-endian |
| BER-OID shortest form | X.690 8.19.2 | Strict: `NonMinimalOid` |
| Variable-Length Pack length coding | Table 6 | `0x04`, `0x24`, `0x44`, `0x64` |
| Defined-Length Packs: lengths given only by the defining document, filling the pack | §7.6 | `PackReader`, `split` (which reports bytes left over) |

Every example in ST 336:2017 Annexes A to H, and the Global Set example from the 2007 edition, is decoded and re-encoded byte for byte in [tests/spec_examples.rs](tests/spec_examples.rs).

## Features

| Feature | Default | Adds |
|---|---|---|
| `std` | yes | `std::error::Error` impls; implies `alloc` |
| `alloc` | via `std` | `Decoder` and the group encoders |
| `capi` | no | Public C ABI for shared and static libraries, implies `std` |
| `serde` | no | `Serialize` for labels, codings, options, errors, `Config` and `Stats` |

With `default-features = false` the crate is `no_std` and does no allocation.

The minimum supported Rust version is 1.70. The optional `serde` dependency needs a newer compiler.

## Examples

```bash
cargo run --release --example encode -- annex.klv       # write the five ST 336 Annex C-G groups
cargo run --release --example klvdump -- annex.klv --values
cargo run --release --example stream < annex.klv
```

The stream example accepts `--key <universal-label>` to select a key ignoring its version byte.

With the C package installed, write a Local Set to a file and read it back with the stream decoder. Pass `-DSMPTE_KLV_STATIC=ON` at configure time for static linking. [Encoder](examples/c/klv_encode.c) · [Decoder](examples/c/klv_dump.c)

```bash
cmake -S examples/c -B build
cmake --build build
./build/klv_encode sample.klv
./build/klv_dump sample.klv
```

## Tests

```bash
cargo test --all-features
make check               # C package tests on Linux and macOS
```

The Rust suite covers ST 336 Annex examples, every group coding, chunk boundaries, truncated and corrupted input, and randomised round trips. The C tests install the package into a temporary prefix, verify the exported symbols against the header, and run shared and static consumers built with pkg-config and CMake.

## Fuzzing

Three Rust harnesses exercise the parser, decoder and encoders. [Harness source](tests/harness/mod.rs)

- `parse`: raw bytes, decoded as triplets and as the value of each of the 26 group codings. It checks error positions, that items tile their set exactly, and that every decoded group re-encodes to the same items.
- `stream`: raw bytes through the `Decoder`, pushed whole and in random chunks. The frames and stats must match, every byte must be accounted for, and buffers must stay within their limits.
- `roundtrip`: the bytes describe nested groups to build with the encoders, including Global Tags of every size the key allows. Each item must be refused for a reason an independent check agrees with, or decode back exactly under the strict options. The packets must stream back out unchanged, and with a damaged length between them, the decoder must lose only that header.

`cargo test` runs them over a few thousand mutated inputs on the stable toolchain. Use a larger iteration count for longer runs, or use [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) for coverage-guided fuzzing.

```bash
SMPTE_KLV_FUZZ_ITERATIONS=1000000 cargo test --release --test fuzz
cargo +nightly fuzz run parse
```

CI also fuzzes the C ABI with libFuzzer and AddressSanitizer. [C harness](tests/c/fuzz.c)

The stable runner saves a failing input under `target/fuzz-failures/`. Once it is fixed, add the input to `tests/fuzz_regressions/<target>/` so every test run replays it.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Notley Technologies and Noah Davis.

Licensed under the [Apache License, Version 2.0](LICENSE).
