# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ./private/conversion_bytes
export toHex, hexToByteArrayBE, hexToSeqByteBE


# Note: Fields are intentionally kept private
type
  PublicKey* = object
    Fraw_key: array[64, byte]

  PrivateKey* = object
    Fraw_key: array[32, byte]
    Fpublic_key: PublicKey

  Signature* {.packed.}= object
    Fr: array[32, byte]
    Fs: array[32, byte]
    Fv: range[0.byte .. 1.byte]


# "Public" accessors, only exposed to internal modules

template genAccessors(name: untyped, fieldType, objType: typedesc): untyped =
  # Access
  proc name*(obj: objType): fieldType {.noSideEffect, inline, noInit.} =
    obj.`F name`

  # Assignement
  proc `name=`*(obj: var objType, value: fieldType): fieldType {.noSideEffect, inline.} =
    obj.`F name` = value

  # Mutable
  proc `name`*(obj: var objType): var fieldType {.noSideEffect, inline.} =
    obj.`F name`

genAccessors(raw_key, array[64, byte], PublicKey)
genAccessors(raw_key, array[32, byte], PrivateKey)
genAccessors(public_key, PublicKey, PrivateKey)
genAccessors(s, array[32, byte], Signature)
genAccessors(r, array[32, byte], Signature)
genAccessors(v, range[0.byte .. 1.byte], Signature)
