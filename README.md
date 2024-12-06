# MProve-Nova: A Privacy-Preserving Proof of Reserves Protocol for Monero

_Rust implementation of MProve-Nova (Accepted at PoPETs 2025 Issue 2 Paper 68)_ 

## Overview

This repository is structured as a Rust library and includes the following key components:
* [`gen_values`](src/bin/gen_values.rs): Implementation to generate one-time addresses, commitments and key images to be used in reserves commitment generator and non-collusion subprotocol
* [`nova_rcg`](src/nova_rcg): Implementation of Nova step computation for reserves commitment generator subprotocol
* [`nova_nc`](src/nova_nc): Implementation of Nova step computation for non-collusion subprotocol
* [`examples`](examples): Examples for proof generation and verification of reserves commitment generator and non-collusion subprotocol
* [`logs`](logs): Output logs of reserves commitment generator and non-collusion subprotocols for varying number of addresses

This library has the following major dependencies:
* [`Nova`](https://github.com/varunthakore/Nova): Zero-Knowledge Implementation of Nova
* [`bellpepper-emulated`](https://github.com/argumentcomputer/bellpepper-gadgets/tree/main/crates/emulated): Non-native field arithmetic package inspired by the [emulated](https://github.com/Consensys/gnark/tree/master/std/math/emulated) package in [Gnark](https://github.com/Consensys/gnark)
* [`bellpepper-ed25519`](https://github.com/argumentcomputer/bellpepper-gadgets/tree/main/crates/ed25519): R1CS Implementation of Ed25519 curve operations using [bellpepper-emulated](bellpepper-emulated/README.md) package
* [`merkle-trees`](https://github.com/varunthakore/merkle-trees): Implementation of Merkle Trees using Poseidon hash and their R1CS circuits

## Install Rust

For macOS, Linux, or another Unix-like OS
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Build

Clone the repository and run the following commands:
```bash
cd mprove-nova/
rustup show
cargo build --release --examples --bins
```

## Tests

The `mprove-nova` library implements several tests.

To run the tests:
```bash
cargo test --release
```

To run a specific test, specify it's name as follows:
```bash
cargo test [name_of_test] --release -- --nocapture
```

## Examples

The `mprove-nova` library implements examples for reserves commitment generator and non-collusion subprotocols.

To run an example for reserves commitment generator subprotocol, run the following commands by passing the number of addresses as argument:
```bash
cargo run --release --bin gen_values [num_of_addrs]
cargo run --release --example rcg [num_of_addrs]
```
Here, `num_of_addrs` specifies the number of addresses owned by the exchange for which it wants to compute the total reserves commitment. The `gen_values` binary generates `num_of_addrs` dummy one-time addresses, commitments, and key images, which are subsequently used in the reserves commitment generator protocol when the `rcg` example is executed.

For instance, to calculate the reserves commitment for 1,000 owned addresses:
```bash
cargo run --release --bin gen_values 1000
cargo run --release --example rcg 1000
```

To run an example for non-collusion subprotocol, run the following command by passing the number of addresses as argument:
```bash
cargo run --release --example nc [num_of_addrs]
```
In the non-collusion protocol, exchange Ex2 shares its double-spend tree leaves with exchange Ex1, and Ex1 runs the non-collusion protocol. Here, `num_of_addrs` represents the number of double-spend tree leaves sent by Ex2 to Ex1, which corresponds to the number of addresses owned by Ex2.

For instance, if Ex2 owns 1,000 addresses and Ex1 wants to prove non-collusion with respect to those 1,000 addresses owned by Ex2:
```bash
cargo run --release --example nc 1000
```

## Benchmarks

To generate benchmarks run the following commands:

```bash
rustup show
cargo build --release --examples --bins
./genlog_all.sh
```

To generate benchmarks for specific number of addresses run:
```bash
rustup show
cargo build --release --examples --bins
./genlog.sh [num_of_addrs]
```

The benchmarks will be generated in the [`logs`](logs) directory which contains two sub-directories:
* [`rcg`](logs/rcg): Logs for reserves commitment generator subprotocol
* [`nc`](logs/nc): Logs for non-collusion subprotocol

Each of the above sub-directories will have `output_N.txt` files. These files contain the program output for `N` number of addresses, for `N` in the set {500, 1000, 3000, 5000, 7000, 10000, 15000, 20000}. 

## Existing Benchmarks
The existing files in the logs directory were generated on a **64 core 2.30GHz Intel Xeon Gold 6314U CPU with 125GB RAM**.

### Proving Time

For reserves commitment generator subprotocol
```bash
$ grep "Total proving time is" $(ls logs/rcg/output_* | sort -V)
logs/rcg/output_500.txt:Total proving time is 1236.964131298s
logs/rcg/output_1000.txt:Total proving time is 2451.683974152s
logs/rcg/output_3000.txt:Total proving time is 7303.713045962s
logs/rcg/output_5000.txt:Total proving time is 12254.04523336s
logs/rcg/output_7000.txt:Total proving time is 17204.209811385s
logs/rcg/output_10000.txt:Total proving time is 24989.116031124s
logs/rcg/output_15000.txt:Total proving time is 37831.119494451s
logs/rcg/output_20000.txt:Total proving time is 50389.009951745s
```

For non-collusion subprotocol
```bash
$ grep "Total proving time is" $(ls logs/nc/output_* | sort -V)
logs/nc/output_500.txt:Total proving time is 143.324505882s
logs/nc/output_1000.txt:Total proving time is 285.208374511s
logs/nc/output_3000.txt:Total proving time is 848.153001505s
logs/nc/output_5000.txt:Total proving time is 1410.219713391s
logs/nc/output_7000.txt:Total proving time is 1984.67171172s
logs/nc/output_10000.txt:Total proving time is 2826.393281175s
logs/nc/output_15000.txt:Total proving time is 4236.945553835s
logs/nc/output_20000.txt:Total proving time is 5632.551304325s
```

### Verification Time

For reserves commitment generator subprotocol
```bash
$ grep "Total verification time" $(ls logs/rcg/output_* | sort -V)
logs/rcg/output_500.txt:Total verification time: 4.398468933s
logs/rcg/output_1000.txt:Total verification time: 4.387817808s
logs/rcg/output_3000.txt:Total verification time: 4.391256186s
logs/rcg/output_5000.txt:Total verification time: 4.392875195s
logs/rcg/output_7000.txt:Total verification time: 4.382738747s
logs/rcg/output_10000.txt:Total verification time: 4.389350362s
logs/rcg/output_15000.txt:Total verification time: 4.344367114s
logs/rcg/output_20000.txt:Total verification time: 4.36039312s
```

For non-collusion subprotocol
```bash
$ grep "Total verification time" $(ls logs/nc/output_* | sort -V) 
logs/nc/output_500.txt:Total verification time: 218.79353ms
logs/nc/output_1000.txt:Total verification time: 221.96927ms
logs/nc/output_3000.txt:Total verification time: 229.690116ms
logs/nc/output_5000.txt:Total verification time: 249.285577ms
logs/nc/output_7000.txt:Total verification time: 212.644103ms
logs/nc/output_10000.txt:Total verification time: 210.938363ms
logs/nc/output_15000.txt:Total verification time: 219.091602ms
logs/nc/output_20000.txt:Total verification time: 214.905847ms
```

### Proof Size

For reserves commitment generator subprotocol
```bash
$ grep "CompressedSNARK::len" $(ls logs/rcg/output_* | sort -V) 
logs/rcg/output_500.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_1000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_3000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_5000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_7000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_10000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_15000.txt:CompressedSNARK::len 28024 bytes
logs/rcg/output_20000.txt:CompressedSNARK::len 28024 bytes
```

For non-collusion subprotocol
```bash
$ grep "CompressedSNARK::len" $(ls logs/nc/output_* | sort -V)
logs/nc/output_500.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_1000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_3000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_5000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_7000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_10000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_15000.txt:CompressedSNARK::len 23704 bytes
logs/nc/output_20000.txt:CompressedSNARK::len 23704 bytes
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
