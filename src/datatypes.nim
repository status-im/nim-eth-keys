# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ./private/conversion_bytes

# Note: Fields F should be private, it is intentionally ugly to directly access them
# See private field access issue: https://github.com/nim-lang/Nim/issues/7390
type
  PublicKey* = object
    Fraw_key*: array[64, byte]

  PrivateKey* = object
    Fraw_key*: array[32, byte]
    Fpublic_key*: PublicKey

  Signature* {.packed.}= object
    Fr*: array[32, byte]
    Fs*: array[32, byte]
    Fv*: range[0.byte .. 1.byte] # This should be 27..28 as per Ethereum but it's 0..1 in eth-keys ...

