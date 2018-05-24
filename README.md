# Nim ETH-keys

[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)
[![Build Status](https://travis-ci.org/status-im/nim-eth-keys.svg?branch=master)](https://travis-ci.org/status-im/nim-eth-keys)

This library is a Nim re-implementation of [eth-keys](https://github.com/ethereum/eth-keys): the common API for working with Ethereum's public and private keys, signatures, and addresses.

By default, Nim eth-keys uses Bitcoin's [libsecp256k1](https://github.com/bitcoin-core/secp256k1) as a backend. Make sure libsecp256k1 is available on your system.

An experimental pure Nim backend (Warning ⚠: do not use in production) is available with the compilation switch `-d:backend_native`

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
