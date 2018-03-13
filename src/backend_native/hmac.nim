
# Nim Eth-keyfile
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Nim Implementation of HMAC
# https://tools.ietf.org/html/rfc2104.html

# TODO: this is a duplicate of https://github.com/status-im/nim-eth-keys/blob/master/src/backend_native/hmac.nim
# It should be replaced by a common crypto library in the future like https://github.com/cheatfate/nimcrypto

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

  # computeSHA256 requires a string input output a SHA256Digest* = array[0..31, char]
  # but using $digest creates a string with its ex representation meaning it's a pain to chain
  # The fact that arrays are now printable in Nim 0.18 doesn't help
  # As a workaround we seqify arrays with @ and then convert to string with $
  # TODO Continuous integration

  # inner pass
  result = computeSHA256($cast[array[blockSize,char]](k_ipad) & data)
  # outer pass
  result = computeSHA256($cast[array[blockSize,char]](k_opad) & $result)


when isMainModule:
  # From https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
  let
    key = ['k','e','y']
    data = "The quick brown fox jumps over the lazy dog"

  import strutils
  doAssert hmac_sha256(key, data).toHex == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8".toUpperAscii
