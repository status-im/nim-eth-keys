# eth_keys

[![Build Status (Travis)](https://img.shields.io/travis/status-im/nim-eth-keys/master.svg?label=Linux%20/%20macOS "Linux/macOS build status (Travis)")](https://travis-ci.org/status-im/nim-eth-keys)
[![Windows build status (Appveyor)](https://img.shields.io/appveyor/ci/nimbus/nim-eth-keys/master.svg?label=Windows "Windows build status (Appveyor)")](https://ci.appveyor.com/project/nimbus/nim-eth-keys)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)

This library is a Nim re-implementation of [eth-keys](https://github.com/ethereum/eth-keys): the common API for working with Ethereum's public and private keys, signatures, and addresses.

By default, Nim eth-keys uses Bitcoin's [libsecp256k1](https://github.com/bitcoin-core/secp256k1) as a backend. Make sure libsecp256k1 is available on your system.

An experimental pure Nim backend (Warning ⚠: do not use in production) is available with the compilation switch `-d:backend_native`

## Installation
nimble install https://github.com/status-im/nim-eth-keys/blob/master/eth_keys.nimble


## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
