# smpte-klv

A parser and encoder for SMPTE ST 336 Key-Length-Value (KLV) data: 16-byte universal labels, BER lengths, BER-OID tags, KLV triplets, and all five group codings (Universal Sets, Global Sets, Local Sets, Variable-Length Packs and Defined-Length Packs).

It implements ST 336 and nothing above it. It has no dictionary of keys and does not interpret values, so formats built on KLV, such as MISB ST 0601 or MXF, belong in crates that use this one. Decoding is zero-copy and never panics. A push-based decoder handles streams in chunks of any size, with bounded memory. The crate works without `std` or an allocator, has no required dependencies, and uses safe Rust throughout the parser and encoder.

## Usage

Decode a triplet and the set inside it. Byte 6 of the key says how the set is coded, and `group()` picks the matching decoder:

```rust
use smpte_klv::{Group, Triplet};

let triplet = Triplet::parse(&bytes)?;
println!("{} ({} bytes)", triplet.key(), triplet.value().len());

match triplet.group() {
    Some(Group::Local(set)) => {
        for item in &set {
            let item = item?;
            println!("tag {} = {:02X?}", item.tag, item.value);
        }
    }
    Some(Group::Universal(set)) => { /* items are triplets */ }
    Some(other) => println!("{:?}", other.coding()),
    None => { /* a single item, or a key ST 336 does not define */ }
}
```

Iterate over a buffer of triplets, such as a `.klv` file:

```rust
for triplet in smpte_klv::Triplets::new(&bytes) {
    let triplet = triplet?;   // stops after the first malformed triplet
}
```

Use a live feed, pushed in chunks of any size. The frames do not depend on how the input is split:

```rust
let mut decoder = smpte_klv::Decoder::new();
decoder.set_filter(move |h| h.key().eq_ignoring_version(&wanted));   // others are skipped unbuffered
loop {
    decoder.push(&socket_bytes());
    for frame in decoder.frames() {
        handle(frame.key(), frame.value(), frame.offset());
    }
}
```

Encode. The encoders check every key, tag and length, so that what they write decodes, under the strict defaults, to exactly the items that went in:

```rust
use smpte_klv::LocalSetEncoder;

let mut set = LocalSetEncoder::new(key)?;       // key byte 6 = 0x0B: BER-OID tags, BER lengths
set.item(2, &timestamp)?.item(65, &[19])?;
let packet: Vec<u8> = set.finish()?;
```

For a checksum that covers the header, write the header yourself with `encode::write_header` and append the value from `into_value()`. To encode without allocating, use the writers in `encode`, `ber`, `TagEncoding` and `LengthEncoding` with a `SliceSink` over your own buffer.

## API overview

| Item | Purpose |
|---|---|
| `UniversalLabel` | 16-byte key: category, registry and structure designators, version, item designator, `group_coding()`, `eq_ignoring_version`, `is_fill`, `is_well_formed`, OID `arcs()`, dotted and ST 2029 URN forms |
| `ber` | `decode_length` / `encode_length` (short, long, non-minimal, `0x80`, `0xFF`), `decode_oid` / `encode_oid` |
| `Header` | key and length only, for deciding before the value arrives |
| `Triplet`, `Triplets` | zero-copy triplets: `key`, `value`, `as_bytes` (for forwarding unaltered), `group()` |
| `Group` | `UniversalSet`, `GlobalSet`, `LocalSet`, `VariableLengthPack`, `DefinedLengthPack`, chosen from byte 6 or given with `Group::with_coding` |
| `GroupCoding`, `TagEncoding`, `LengthEncoding` | the byte 6 tables of ST 336 |
| `*Encoder` | build any group item by item |
| `Decoder`, `Config`, `Frame`, `Stats` | push-based stream decoding |
| `DecodeOptions` | `strict()` (default) or `lenient()`, top-level `0x80` handling, Fill item skipping |
| `Error`, `ErrorKind` | what went wrong, at which byte; `is_incomplete()` means "feed more" (never true inside a set or pack, whose size is fixed: that is `ErrorKind::Overrun`) |

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

## Robustness

- **No panics on input.** Every decoder reports malformed or truncated data as an `Error` with a byte offset.
- **No trust in declared lengths.** Nothing is allocated from a length read off the wire. The `Decoder` skips values above `Config::max_value_len` (16 MiB by default) without buffering them, and holds at most `Config::max_queue_bytes` of finished frames, counting each frame's bookkeeping as well as its bytes (one frame larger than the limit is still accepted into an empty queue).
- **No recursion.** Nested groups are decoded one level at a time, at the caller's request, so deep nesting cannot exhaust the stack.
- **Resynchronisation.** The `Decoder` skips damage by scanning for the next `06 0E 2B 34` (with `require_smpte_key`, the default). A damaged length that is still valid looks like a real one and is skipped, or buffered, by its declared size. Set `Config::max_skip_len` to bound the skip; together with `max_value_len` it caps what one damaged length can cost, so a bit error cannot discard the rest of a stream. `Stats` accounts for every byte: each pushed byte is counted once, as delivered, skipped or still buffered.

## Features

| Feature | Default | Adds |
|---|---|---|
| `std` | yes | `std::error::Error` impls; implies `alloc` |
| `alloc` | via `std` | `Decoder` and the group encoders |
| `capi` | no | Public C ABI for shared and static libraries, implies `std` |
| `serde` | no | `Serialize` for labels, codings, options, errors, `Config` and `Stats` |

With `default-features = false` the crate is `no_std` and does no allocation.

The minimum supported Rust version is 1.70. The optional `serde` dependency needs a newer compiler.

## C ABI

C, C++, and languages with a C FFI can parse and encode triplets, read and build all five group codings, and push chunks through a bounded stream decoder. The [public header](include/smpte_klv.h) specifies the functions, status codes, buffer lifetimes, and ABI version.

On Linux and macOS, install the header, shared and static libraries, pkg-config file, and CMake package into a prefix of your choice.

```sh
prefix="$HOME/.local"
make install PREFIX="$prefix"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
cc examples/c/klv_dump.c $(pkg-config --cflags --libs smpte_klv) -Wl,-rpath,"$prefix/lib" -o klv_dump
```

For a CMake project, use `find_package(smpte_klv 0.1 REQUIRED)` and link to `smpte_klv::smpte_klv` for shared linking or `smpte_klv::smpte_klv_static` for static linking. The static target includes the system libraries Rust requires. The two C examples write a Local Set to a file and read it back through the streaming API.

```sh
cmake -S examples/c -B build -DCMAKE_PREFIX_PATH="$prefix"
cmake --build build
./build/klv_encode sample.klv
./build/klv_dump sample.klv
# @0 060E2B34020B01010E01030101000000 4 bytes
```

Pass `-DSMPTE_KLV_STATIC=ON` to build the examples with the static library. For staged installs, Make accepts `DESTDIR`, `LIBDIR`, and `INCLUDEDIR`. Use the same prefix and directories with `make uninstall`.

On Windows with the MSVC Rust toolchain, build both libraries with Cargo.

```powershell
cargo rustc --release --lib --features capi --crate-type cdylib --crate-type staticlib
```

Include `include/smpte_klv.h` and link against `target/release/smpte_klv.dll.lib` for the DLL, or `target/release/smpte_klv.lib` for the static library. Place `smpte_klv.dll` beside the executable when using the DLL.

## Examples

```bash
cargo run --example klvdump -- capture.klv --values     # structure of every triplet and set
cargo run --example encode -- annex.klv                 # one of each group, from ST 336 Annexes C-G
cat capture.klv | cargo run --example stream -- --key 06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00
```

## Tests

```bash
cargo test --all-features
```

The suite has unit tests in each module, the ST 336 Annex examples, randomised round trips through every coding, tests that every split of a stream gives the same result, truncation and corruption at every byte, and a short fuzzing pass. Run `make check` on Linux or macOS to install into a temporary prefix, verify the ABI from C, and run both examples with shared and static linking through pkg-config and CMake.

## Fuzzing

Three harnesses in [tests/harness](tests/harness/mod.rs) accept any bytes:

- `parse`: raw bytes, decoded as triplets and as the value of each of the 26 group codings. It checks error positions, that items tile their set exactly, and that every decoded group re-encodes to the same items.
- `stream`: raw bytes through the `Decoder`, pushed whole and in random chunks. The frames and stats must match, every byte must be accounted for, and buffers must stay within their limits.
- `roundtrip`: the bytes describe nested groups to build with the encoders, including Global Tags of every size the key allows. Each item must be refused for a reason an independent check agrees with, or decode back exactly under the strict options. The packets must stream back out unchanged, and with a damaged length between them, the decoder must lose only that header.

`cargo test` runs them over a few thousand mutated inputs on the stable toolchain. For longer runs, or coverage-guided fuzzing with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```bash
SMPTE_KLV_FUZZ_ITERATIONS=1000000 cargo test --release --test fuzz
cargo +nightly fuzz run parse
```

The stable runner saves a failing input under `target/fuzz-failures/`. Once it is fixed, add the input to `tests/fuzz_regressions/<target>/` so every test run replays it.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Notley Technologies and Noah Davis.

Licensed under the [Apache License, Version 2.0](LICENSE).
