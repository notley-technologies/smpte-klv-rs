# Contributing

Thanks for taking the time to help. Bug reports, fixes and documentation improvements are all welcome.

## Reporting problems

Open an issue using the bug report template. The most useful reports include:

- the version or commit you are using,
- what the library reported and what you expected,
- if you can share it, the KLV bytes that show the problem: a hex dump of one packet is often enough. Please do not attach data you are not allowed to share.

Security issues are different: see [SECURITY.md](SECURITY.md).

## Development

You need a stable Rust toolchain. The minimum supported version is in `Cargo.toml`.

```bash
cargo test --all-features
```

This runs the unit and integration tests, the SMPTE ST 336 Annex examples, and a short fuzzing pass. CI runs the same on Linux, macOS and Windows, and again without `std` and without an allocator. It also builds with warnings as errors, builds the docs for every feature set and as docs.rs does, builds for a bare-metal target, checks the minimum Rust version, and runs two minutes of coverage-guided fuzzing per target.

Before opening a pull request:

```bash
RUSTFLAGS="-D warnings" cargo build --all-targets --all-features
RUSTFLAGS="-D warnings" cargo build --lib --no-default-features
cargo test --no-default-features
cargo test --no-default-features --features alloc
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --no-default-features
```

For changes to decoding or encoding, a longer fuzz run is worth it:

```bash
SMPTE_KLV_FUZZ_ITERATIONS=1000000 cargo test --release --test fuzz
```

If the fuzzer finds a failing input, fix the bug and add the input to `tests/fuzz_regressions/<target>/` so it is replayed from then on.

## Guidelines

- **Tests.** Fixes come with a test that fails without the fix. Build test data with the helpers in `tests/common/mod.rs` rather than adding binary files.
- **ST 336 only.** This crate implements SMPTE ST 336 and nothing that a format built on it defines. Keys, tag meanings, value types and checksums of MISB, MXF and other formats belong in their own crates. If such a crate needs something generic from here, add that.
- **No I/O.** The library never reads files or sockets.
- **Untrusted input.** Never allocate based on a length read from the input, never recurse on input structure, and never panic on any input. Anything that buffers needs a limit in `Config`.
- **`no_std`.** Decoding and slice encoding must keep working without `std` or `alloc`. Put anything that allocates behind the `alloc` feature.
- **Standards.** Cite the document and section for any rule you implement, in a comment or doc comment. Work from the standard, not from what one encoder happens to produce. Where real data breaks a rule, accept it only under `DecodeOptions::lenient()`.
- **Style.** Match the surrounding code. Comments explain why, not what. Use hyphens, not em dashes.

## Pull requests

Keep pull requests focused on one change and describe what it does and why. Add an entry under "Unreleased" in [CHANGELOG.md](CHANGELOG.md) for anything user-visible.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), as described in section 5 of the license.
