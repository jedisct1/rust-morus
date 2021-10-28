# MORUS for Rust

This is a Rust implementation of
[MORUS](https://competitions.cr.yp.to/round3/morusv2.pdf) (MORUS-1280-128)

MORUS is a fast authenticated cipher for platforms without hardware AES acceleration.

It performs especially well on WebAssembly compared to alternatives.

# Cargo flags

- `std`: allow dynamic allocations

`std` is the default.

A benchmark can be run that way:

```sh
export RUSTFLAGS="-C target-cpu=native"
cargo bench
```

# Benchmarks

Benchmarks take a 16384 bytes input block. Results are in bytes per second.

## Rust implementations

Crates:

- `aes-gcm`
- `chacha20poly1305`
- `morus`

Macbook Pro - 2,4 GHz Intel Core i9.

| cipher            | speed    |
| ----------------- | -------- |
| chacha20-poly1305 | 1.48 G/s |
| morus             | 3.76 G/s |

WebAssembly (Wasmtime)

| cipher                       | speed      |
| ---------------------------- | ---------- |
| aes128-gcm                   | 44.13 M/s  |
| chacha20-poly1305            | 193.05 M/s |
| chacha20-poly1305 (+simd128) | 196.54 M/s |
| morus                        | 1.07 G/s   |
| morus (+simd128)             | 1.38 G/s   |

WebAssembly (WAVM)

| cipher            | speed      |
| ----------------- | ---------- |
| aes128-gcm        | 57.01 M/s  |
| chacha20-poly1305 | 335.82 M/s |
| morus             | 1.95 G/s   |

Other implementations (WebAssembly, WAVM)

| cipher (implementation) | speed    |
| ----------------------- | -------- |
| zig-morus (Zig)         | 2.27 G/s |
