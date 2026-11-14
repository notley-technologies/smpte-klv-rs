## What and why

<!-- What this changes and the reason for it. Link the issue if there is one. -->

## Checklist

- [ ] Tests cover the change (a fix includes a test that fails without it)
- [ ] `cargo test --all-features` passes
- [ ] No new warnings (`RUSTFLAGS="-D warnings" cargo build --all-targets --all-features`)
- [ ] Still builds without `std` (`cargo build --lib --no-default-features`)
- [ ] New rules cite the SMPTE ST 336 (or ISO/IEC 8825-1) section they come from
- [ ] CHANGELOG.md updated for user-visible changes
