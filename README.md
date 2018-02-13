# Nim ETH-keys

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)

A reimplementation in pure Nim of [eth-keys](https://github.com/ethereum/eth-keys), the common API for Ethereum key operations.

# Experimental

Warning ⚠: current native backend is a proof of concept, not suitable for production use:
  - Future versions will use libsecp256k1 as a cryptographic backend, a proven crypto library.

DO NOT USE for production