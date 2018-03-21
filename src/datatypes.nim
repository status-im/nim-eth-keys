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


type
  Scalar256 = array[32, byte]
    # Secp256k1 makes the signature an opaque "implementation dependent".
    #
    # Scalar256 is opaque/distinct too as in practice, they are uint256
    # and by default we don't load any.
    # See implementation details in datatypes.md.

  Signature* {.packed.}= object
    Fr*: Scalar256
    Fs*: Scalar256
    Fv*: range[0.byte .. 1.byte] # This should be 27..28 as per Ethereum but it's 0..1 in eth-keys ...

