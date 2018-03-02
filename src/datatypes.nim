# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ./private/lowlevel_types
import ttmath

export lowlevel_types, ttmath

type
  PublicKey* = object
    raw_key*: ByteArrayBE[64]

  PrivateKey* = object
    raw_key*: ByteArrayBE[32]
    public_key*: PublicKey

  BaseKey* = PrivateKey|PublicKey

  Signature* {.packed.}= object
    r*: UInt256
    s*: UInt256
    v*: range[0.byte .. 1.byte]
