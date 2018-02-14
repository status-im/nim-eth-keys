# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import  ../src/private/lowlevel_types
import unittest, ttmath, strutils


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