# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ttmath, strutils

# Note on endianness:
# - UInt256 uses host endianness
# - Libsecp256k1, Ethereum EVM expect Big Endian
#   https://github.com/ethereum/evmjit/issues/91
# - Keccak expects least-significant byte first: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
#   Appendix B.1 p37 and outputs a hash with the same endianness as input
#   http://www.dianacoman.com/2018/02/08/eucrypt-chapter-9-byte-order-and-bit-disorder-in-keccak/
#   https://www.reddit.com/r/crypto/comments/6287my/explanations_on_the_keccaksha3_paddingbyte/
#   Note: Since Nim's Keccak-Tiny only accepts string as input, endianness does not matter.

type ByteArrayBE*[N: static[int]] = array[N, byte]
  ## A byte array that stores bytes in big-endian order

proc readUint256BE*(ba: ByteArrayBE[32]): UInt256 {.noSideEffect, inline.}=
  ## Convert a big-endian array of Bytes to an UInt256 (in native host endianness)
  const N = 32
  for i in 0 ..< N:
    {.unroll: 4.}
    result = result shl 8 or ba[i].u256

proc toByteArrayBE*(num: UInt256): ByteArrayBE[32] {.noSideEffect, noInit, inline.}=
  ## Convert an UInt256 (in native host endianness) to a big-endian byte array
  const N = 32
  for i in 0 ..< N:
    {.unroll: 4.}
    result[i] = byte getUInt(num shr uint((N-1-i) * 8))

proc readHexChar(c: char): byte {.noSideEffect.}=
  ## Converts an hex char to a byte
  case c
  of '0'..'9': result = byte(ord(c) - ord('0'))
  of 'a'..'f': result = byte(ord(c) - ord('a') + 10)
  of 'A'..'F': result = byte(ord(c) - ord('A') + 10)
  else:
    raise newException(ValueError, $c & "is not a hexademical character")

proc skip0xPrefix(hexStr: string): int {.inline.} =
  ## Returns the index of the first meaningful char in `hexStr` by skipping
  ## "0x" prefix
  if hexStr[0] == '0' and hexStr[1] in {'x', 'X'}:
    result = 2

proc hexToByteArrayBE*(hexStr: string, output: var openArray[byte], fromIdx, toIdx: int) =
  ## Read a hex string and store it in a Byte Array `output` in Big-Endian order
  var i = skip0xPrefix(hexStr)

  assert(fromIdx >= 0 and toIdx >= fromIdx and fromIdx < output.len and toIdx < output.len)
  let sz = toIdx - fromIdx + 1

  assert hexStr.len - i == 2*sz

  while i < sz:
    output[fromIdx + i] = hexStr[2*i].readHexChar shl 4 or hexStr[2*i+1].readHexChar
    inc(i)

proc hexToByteArrayBE*(hexStr: string, output: var openArray[byte]) {.inline.} =
  ## Read a hex string and store it in a Byte Array `output` in Big-Endian order
  hexToByteArrayBE(hexStr, output, 0, output.high)

proc hexToByteArrayBE*[N: static[int]](hexStr: string): ByteArrayBE[N] {.noSideEffect, noInit, inline.}=
  ## Read an hex string and store it in a Byte Array in Big-Endian order
  hexToByteArrayBE(hexStr, result)

proc hexToSeqByteBE*(hexStr: string): seq[byte] {.noSideEffect.}=
  ## Read an hex string and store it in a sequence of bytes in Big-Endian order
  var i = skip0xPrefix(hexStr)

  let N = (hexStr.len - i) div 2

  result = newSeq[byte](N)
  while i < N:
    result[i] = hexStr[2*i].readHexChar shl 4 or hexStr[2*i+1].readHexChar
    inc(i)

proc hexToUInt256*(hexStr: string): UInt256 {.noSideEffect.}=
  ## Read an hex string and store it in a UInt256
  const N = 32

  var i = skip0xPrefix(hexStr)

  assert hexStr.len - i == 2*N

  while i < 2*N:
    result = result shl 4 or hexStr[i].readHexChar.uint.u256
    inc(i)

proc toHex*(n: UInt256): string {.noSideEffect.}=
  ## Convert uint256 to its hex representation
  ## Output is in lowercase

  var rem = n # reminder to encode

  const
    N = 32 # nb of bytes in n
    hexChars = "0123456789abcdef"

  result = newString(2*N)
  for i in countdown(2*N - 1, 0):
    result[i] = hexChars[(rem and 0xF.u256).getUInt.int]
    rem = rem shr 4

proc toHexAux(ba: openarray[byte]): string {.noSideEffect.} =
  ## Convert a byte-array to its hex representation
  ## Output is in lowercase
  const hexChars = "0123456789abcdef"

  let sz = ba.len
  result = newString(2 * sz)
  for i in 0 ..< sz:
    result[2*i] = hexChars[int ba[i] shr 4 and 0xF]
    result[2*i+1] = hexChars[int ba[i] and 0xF]


proc toHex*(ba: openarray[byte]): string {.noSideEffect, inline.} =
  ## Convert a byte-array to its hex representation
  ## Output is in lowercase
  ##
  ## Warning ⚠: Do not use toHex for hex representation of Public Keys
  ##   Use the ``serialize`` proc:
  ##     - PublicKey is actually 2 separate numbers corresponding to coordinate on elliptic curve
  ##     - It is resistant against timing attack
  toHexAux(ba)

proc toHex*(ba: ByteArrayBE): string {.noSideEffect, inline.} =
  ## Convert a byte-array to its hex representation
  ## Output is in lowercase
  ##
  ## Warning ⚠: Do not use toHex for hex representation of Public Keys
  ##   Use the ``serialize`` proc:
  ##     - PublicKey is actually 2 separate numbers corresponding to coordinate on elliptic curve
  ##     - It is resistant against timing attack
  toHexAux(ba)
