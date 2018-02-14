# Nim ETH-keys

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)

A reimplementation in pure Nim of [eth-keys](https://github.com/ethereum/eth-keys), the common API for Ethereum key operations.

By default, Nim eth-keys uses Bitcoin's [libsecp256k1](https://github.com/bitcoin-core/secp256k1) as a backend.
Make sure libsecp256k1 is available on your system.

An experimental pure Nim backend (Warning ⚠: do not use in production) is available with the compilation switch `-d:backend_native`
