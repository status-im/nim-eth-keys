# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

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
