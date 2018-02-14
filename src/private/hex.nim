# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import ttmath, strutils, ./casting

proc readHexChar(c: char): int =
  case c
  of '0'..'9': result = ord(c) - ord('0')
  of 'a'..'f': result = ord(c) - ord('a') + 10
  of 'A'..'F': result = ord(c) - ord('A') + 10
  else:
    raise newException(ValueError, $c & "is not a hexademical character")

proc hexToByteArray*[N: static[int]](hexStr: string): array[N, byte] {.noSideEffect.}=
  var i = 0
  if hexStr[i] == '0' and (hexStr[i+1] == 'x' or hexStr[i+1] == 'X'):
    # Ignore 0x and OX
    inc(i, 2)
  assert hexStr.len - i == 2*N

  while i < N:
    result[i] = byte(readHexChar(hexStr[2*i]) shl 4 or readHexChar(hexStr[2*i+1]))
    inc(i)

proc hexToUInt256*(hexStr: string): UInt256 {.noSideEffect.}=
  const N = 32

  var i = 0
  if hexStr[i] == '0' and (hexStr[i+1] == 'x' or hexStr[i+1] == 'X'):
    # Ignore 0x and OX
    inc(i, 2)
  assert hexStr.len - i == 2*N

  while i < 2*N:
    result = result shl 4 or readHexChar(hexStr[i]).uint.u256
    inc(i)

proc toHex*(n: UInt256): string =
  var rem = n # reminder to encode

  const
    N = 32 # nb of bytes in n
    hexChars = "0123456789abcdef"

  result = newString(2*N)
  for i in countdown(2*N - 1, 0):
    result[i] = hexChars[(rem and 0xF.u256).getUInt.int]
    rem = rem shr 4