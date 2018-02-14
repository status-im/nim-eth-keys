# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import ttmath, strutils, keccak_tiny, nimsha2, strutils

# Note on endianness:
# - UInt256 uses host endianess
# - Libsecp256k1, Ethereum EVM expect Big Endian
#   https://github.com/ethereum/evmjit/issues/91
# - Keccak expects least-significant byte first: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
#   Appendix B.1 p37 and outputs a hash with the same endianess as input
#   http://www.dianacoman.com/2018/02/08/eucrypt-chapter-9-byte-order-and-bit-disorder-in-keccak/
#   https://www.reddit.com/r/crypto/comments/6287my/explanations_on_the_keccaksha3_paddingbyte/
#   Note: Since Nim's Keccak-Tiny only accepts string as input, endianness does not matter.

type ByteArrayBE*[N: static[int]] = distinct array[N, byte]
  ## A byte array that stores bytes in big-endian order

proc `[]`[N: static[int], I: Ordinal](ba: ByteArrayBE[N], i: I): byte {.noSideEffect.}=
  (array[N,byte])(ba)[i]

proc `[]=`[N: static[int], I: Ordinal](ba: var ByteArrayBE[N], i: I, val: byte) {.noSideEffect.}=
  (array[N,byte])(ba)[i] = val

proc readUint256BE*(ba: ByteArrayBE[32]): UInt256 {.noSideEffect.}=
  ## Convert a big-endian array of Bytes to an UInt256 (in native host endianness)
  const N = 32
  for i in 0 ..< N:
    result = result shl 8 or ba[i].u256

proc toByteArrayBE*(num: UInt256): ByteArrayBE[32] {.noSideEffect, noInit.}=
  ## Convert an UInt256 (in native host endianness) to a big-endian byte array
  const N = 32
  for i in 0 ..< N:
    result[i] = byte getUInt(num shr uint((N-1-i) * 8))

proc readHexChar(c: char): byte {.noSideEffect.}=
  ## Converts an hex char to a byte
  case c
  of '0'..'9': result = byte(ord(c) - ord('0'))
  of 'a'..'f': result = byte(ord(c) - ord('a') + 10)
  of 'A'..'F': result = byte(ord(c) - ord('A') + 10)
  else:
    raise newException(ValueError, $c & "is not a hexademical character")

proc hexToByteArrayBE*[N: static[int]](hexStr: string): ByteArrayBE[N] {.noSideEffect, noInit.}=
  ## Read an hex string and store it in a Byte Array in Big-Endian order
  var i = 0
  if hexStr[i] == '0' and (hexStr[i+1] == 'x' or hexStr[i+1] == 'X'):
    inc(i, 2) # Ignore 0x and 0X prefix

  assert hexStr.len - i == 2*N

  while i < N:
    result[i] = hexStr[2*i].readHexChar shl 4 or hexStr[2*i+1].readHexChar
    inc(i)

proc hexToUInt256*(hexStr: string): UInt256 {.noSideEffect.}=
  ## Read an hex string and store it in a UInt256
  const N = 32

  var i = 0
  if hexStr[i] == '0' and (hexStr[i+1] == 'x' or hexStr[i+1] == 'X'):
    inc(i, 2) # Ignore 0x and 0X prefix

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

proc toHex*[N: static[int]](ba: ByteArrayBE[N]): string {.noSideEffect.}=
  ## Convert a big-endian byte-array to its hex representation
  ## Output is in lowercase

  const hexChars = "0123456789abcdef"

  result = newString(2*N)
  for i in 0 ..< N:
    result[2*i] = hexChars[ba[i] shr 4 and 0xF]
    result[2*i+1] = hexChars[ba[i] and 0xF]
