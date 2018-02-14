# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import ttmath, ./private/lowlevel_types
export lowlevel_types

type
  PublicKey* = object
    raw_key*: ByteArrayBE[64]

  PrivateKey* = object
    raw_key*: ByteArrayBE[32]
    public_key*: PublicKey

  BaseKey* = PrivateKey|PublicKey

  Signature* = object
    v*: range[0.uint8 .. 1.uint8]
    r*: UInt256
    s*: UInt256
