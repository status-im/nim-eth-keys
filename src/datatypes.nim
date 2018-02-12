# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import strutils, ttmath

type
  PublicKey* = object
    raw_key*: array[64, byte]

  PrivateKey* = object
    raw_key*: array[32, byte]
    public_key*: PublicKey

  BaseKey* = PrivateKey|PublicKey

  Signature* {.partial.}= object
    v*: range[0.uint8 .. 1.uint8]
    r*: UInt256
    s*: UInt256

proc to_bytes*(key: BaseKey): array[32, byte] | array[64, byte] =
  # No-op to satisfy Python API
  key.raw_key

proc to_hex*(key: BaseKey): string =
  result = "0x"
  for i in key.raw_key:
    result.add(i.to_hex)