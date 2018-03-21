# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import  ../src/private/[conversion_bytes, conversion_ttmath]
import unittest, ttmath, strutils # TODO remove ttmath needs if backend libsecp256k1

import ./config

suite "Testing conversion functions: Hex, Bytes, Endianness":
  let
    SECPK1_N_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".toLowerAscii
    SECPK1_N = "115792089237316195423570985008687907852837564279074904382605163141518161494337".u256

  test "hex -> uint256":
    check: SECPK1_N_HEX.hexToUInt256 == SECPK1_N

  test "uint256 -> hex":
    check: SECPK1_N.toHex == SECPK1_N_HEX

  test "hex -> big-endian array -> uint256":
    check: hexToByteArrayBE[32](SECPK1_N_HEX).readUint256BE == SECPK1_N

  test "uint256 -> big-endian array -> hex":
    check: SECPK1_N.toByteArrayBE.toHex == SECPK1_N_HEX

suite "Confirming consistency: hex vs decimal conversion":
  # Conversion done through https://www.mobilefish.com/services/big_number/big_number.php

  test "Alice signature":
    check: alice.raw_sig.r.hexToUInt256 == "80536744857756143861726945576089915884233437828013729338039544043241440681784".u256
    check: alice.raw_sig.s.hexToUInt256 == "1902566422691403459035240420865094128779958320521066670269403689808757640701".u256

  test "Bob signature":
    check: bob.raw_sig.r.hexToUInt256 == "41741612198399299636429810387160790514780876799439767175315078161978521003886".u256
    check: bob.raw_sig.s.hexToUInt256 == "47545396818609319588074484786899049290652725314938191835667190243225814114102".u256

  test "Eve signature":
    check: eve.raw_sig.r.hexToUInt256 == "84467545608142925331782333363288012579669270632210954476013542647119929595395".u256
    check: eve.raw_sig.s.hexToUInt256 == "43529886636775750164425297556346136250671451061152161143648812009114516499167".u256

