# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import strutils, ttmath

type
  PublicKey* = object
    raw_key*: array[2, UInt256]

  PrivateKey* = object
    raw_key*: UInt256
    public_key*: PublicKey

  BaseKey* = PrivateKey|PublicKey

  Signature* = object
    v*: range[0.uint8 .. 1.uint8]
    r*: UInt256
    s*: UInt256
