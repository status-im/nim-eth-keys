# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Nim Implementation of HMAC
# https://tools.ietf.org/html/rfc2104.html

import ../private/array_utils
import nimsha2 # TODO: For SHA-256, use OpenSSL instead? (see https://rosettacode.org/wiki/SHA-256#Nim)

proc hmac_sha256*[N: static[int]](key: array[N, byte|char],
                                  data: string|seq[byte|char]): SHA256Digest =
  # Note: due to https://github.com/nim-lang/Nim/issues/7208
  # blockSize cannot be a compile-time parameter with a default value
  const
    opad: byte = 0x5c
    ipad: byte = 0x36
    blockSize = 64

  var k, k_ipad{.noInit.}, k_opad{.noInit.}: array[blockSize, byte]

  when N > blockSize:
    k[0 ..< 32] = key.computeSHA256
  else:
    k[0 ..< N] = cast[array[N, byte]](key)

  for i in 0 ..< blockSize:
    k_ipad[i] = k[i] xor ipad
    k_opad[i] = k[i] xor opad

  result = computeSHA256($k_opad & $computeSHA256($k_ipad & $data))


when isMainModule:
  # From https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
  let
    key = ['k','e','y']
    data = "The quick brown fox jumps over the lazy dog"

  import strutils
  doAssert hmac_sha256(key, data).toHex == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8".toUpperAscii
