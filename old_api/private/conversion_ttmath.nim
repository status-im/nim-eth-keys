# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import  ttmath, strutils,
        conversion_bytes


# Note on endianness:
# - UInt256 uses host endianness
# - Libsecp256k1, Ethereum EVM expect Big Endian
#   https://github.com/ethereum/evmjit/issues/91
# - Keccak expects least-significant byte first: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
#   Appendix B.1 p37 and outputs a hash with the same endianness as input
#   http://www.dianacoman.com/2018/02/08/eucrypt-chapter-9-byte-order-and-bit-disorder-in-keccak/
#   https://www.reddit.com/r/crypto/comments/6287my/explanations_on_the_keccaksha3_paddingbyte/
#   Note: Since Nim's Keccak-Tiny only accepts string as input, endianness does not matter.

proc toByteArrayBE*(num: UInt256): array[32, byte] {.noSideEffect, noInit, inline.}=
  ## Convert an UInt256 (in native host endianness) to a big-endian byte array
  const N = 32
  for i in 0 ..< N:
    {.unroll: 4.}
    result[i] = byte getUInt(num shr uint((N-1-i) * 8))

proc readUint256BE*(ba: array[32, byte]): UInt256 {.noSideEffect, inline.}=
  ## Convert a big-endian array of Bytes to an UInt256 (in native host endianness)
  const N = 32
  for i in 0 ..< N:
    {.unroll: 4.}
    result = result shl 8 or ba[i].u256

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
