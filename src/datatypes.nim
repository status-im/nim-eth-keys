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
    Fraw_key: array[64, byte]

  PrivateKey* = object
    Fraw_key: array[32, byte]

type
  Scalar256 = distinct array[32, byte]
    # Secp256k1 makes the signature an opaque "implementation dependent".
    #
    # Scalar256 is opaque/distinct too as in practice it's uint256
    # and by default we don't load any uint256 library.
    # See implementation details in datatypes.md.

  Signature* {.packed.}= object
    Fr: Scalar256
    Fs: Scalar256
    Fv: range[0.byte .. 1.byte] # This should be 27..28 as per Ethereum but it's 0..1 in eth-keys ...

# Hide the private fields and generate accessors.
# This is needed to:
#   - Be able to not store the public_key in PrivateKey in the future and replace it by
#     an on-the-fly computation
#   - Signature: have different data representation

template genAccessors(name: untyped, fieldType, objType: typedesc): untyped =
  # Access
  proc name*(obj: objType): fieldType {.noSideEffect, inline, noInit.} =
    obj.`F name`

  # Assignement
  proc `name=`*(obj: var objType, value: fieldType) {.noSideEffect, inline.} =
    obj.`F name` = value

  # Mutable
  proc `name`*(obj: var objType): var fieldType {.noSideEffect, inline.} =
    obj.`F name`

genAccessors(raw_key, array[64, byte], PublicKey)
genAccessors(raw_key, array[32, byte], PrivateKey)


## If we hide the fields we need to provide a custom `==` proc
## Because Nim `==` template will not be able to access the fields

proc `==`*(x, y: Scalar256): bool {.noSideEffect, inline, borrow.}
proc `==`*(x, y: PublicKey or PrivateKey or Signature): bool {.noSideEffect, inline.} =
  system.`==`(x, y)
