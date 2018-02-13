# Nim ETH-keys

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)

A reimplementation in pure Nim of [eth-keys](https://github.com/ethereum/eth-keys), the common API for Ethereum key operations.

# Experimental

Warning: this is a proof of concept, not suitable for production use:
  - Future versions will use libsecp256k1 as a cryptographic backend, a proven crypto library.
  - With regards to modular arithmetic, readability of code has been prioritised unless one of the test cases overflowed
    This means that currently code is `(a * b * c + d) mod P` instead of `addmod(mulmod(mulmod(a, b, P), c, P), d, P)`