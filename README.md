<div align="center">
  <h1>Rust Bitcoin Cash</h1>

  <img alt="Rust Bitcoin Cash logo" src="./logo/rust-bitcoincash.png" width="300" />

  <p>A Rust library for working with Bitcoin Cash (BCH) — de/serialization, parsing, and
    execution of data structures and network messages.
  </p>

  <p>
    <a href="https://github.com/rust-bitcoin/rust-bitcoin/blob/master/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
    <a href="https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html"><img alt="Rustc Version 1.63.0+" src="https://img.shields.io/badge/rustc-1.63.0%2B-lightgrey.svg"/></a>
  </p>
</div>

> [!WARNING]
> **This library is under active construction and is NOT ready for production use.**
>
> Do not use this library with real BCH funds. The API is unstable, behaviour may be
> incorrect or incomplete, and **funds could be lost**. Use at your own risk.

## About

`rust-bitcoincash` is a fork of [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)
reoriented exclusively toward **Bitcoin Cash (BCH)**. The goal is a clean, well-tested Rust
library that tracks the BCH protocol — not BTC or any other chain.

Current scope (partial — work in progress):

- De/serialization of Bitcoin Cash network messages
- De/serialization of blocks and transactions
- Script de/serialization
- Private keys and address creation, de/serialization and validation (including BIP-32)

## Known limitations

### Not production-ready

This library is in early development. Large parts of the codebase still reflect Bitcoin (BTC)
semantics inherited from the upstream fork. BCH-specific protocol rules (e.g. replay
protection, CashAddr, OP_RETURN limits, CHIP changes) may be missing or incorrect.

### Consensus

This library **must not** be used for consensus code (i.e. fully validating blockchain data).
There are many known and unknown deviations from the Bitcoin Cash Node reference implementation.
In a consensus-based system it is critical that all participants use identical rules; this
library cannot guarantee that.

### Semver compliance

The API is considered **unstable** until a 1.0.0 release is made. Breaking changes may occur
between any two versions without notice.

### Support for 16-bit pointer sizes

16-bit pointer sizes are not supported.

## Building

```
git clone <repo-url>
cd rust-bitcoincash
cargo build
```

Run tests with:

```
cargo test --all-features
```

### No-std support

The `std` cargo feature is enabled by default. To build without the Rust standard library:

```
cargo build --no-default-features
```

### Building the docs

Docs are built with the nightly toolchain:

```
RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --all-features -- -D rustdoc::broken-intra-doc-links
```

### Benchmarks

```
RUSTFLAGS='--cfg=bench' cargo +nightly bench
```

## Minimum Supported Rust Version (MSRV)

This library targets **Rust 1.63.0**. Use `Cargo-minimal.lock` to reproduce the MSRV build
(copy it to `Cargo.lock` before building).

## Contributing

Contributions are welcome. Please open an issue before starting large changes to avoid
duplicated effort. For bug reports, questions, or feature requests, open a GitHub issue.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for more details.

## Roadmap

See [`ROADMAP.md`](./ROADMAP.md) for the planned direction of the project.

## Licensing

The code in this project is licensed under the
[Creative Commons CC0 1.0 Universal license](LICENSE).
