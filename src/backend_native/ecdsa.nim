# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import  ../datatypes, ../private/[array_utils, lowlevel_types],
        ./jacobian, ./mod_arithmetic, ./hmac, ./constants

import  ttmath, keccak_tiny, strutils,
        nimSHA2 # TODO: For SHA-256, use OpenSSL instead? (see https://rosettacode.org/wiki/SHA-256#Nim)


proc decode_public_key(pubKey: ByteArrayBE[64]
  ): array[2, UInt256] {.noInit,inline,noSideEffect.} =

  # Slicing with "result[0] = readUint256BE pubKey[0 ..< 32]" would allocate an intermediary seq
  # See https://github.com/nim-lang/Nim/issues/5753#issuecomment-369597564

  # Workaround: pointers
  var
    pk1, pk2: ptr array[32, byte]

  shallowCopy(pk1, cast[type pk1](pubkey[0].unsafeAddr))
  shallowCopy(pk2, cast[type pk2](pubkey[32].unsafeAddr))

  result[0] = readUint256BE pk1[]
  result[1] = readUint256BE pk2[]

proc encode_raw_public_key(pubKeyInt: array[2, Uint256]
  ): ByteArrayBE[64] {.noInit,inline,noSideEffect.}=

  result[0 ..< 32] = pubKeyInt[0].toByteArrayBE
  result[32 ..< 64] = pubKeyInt[1].toByteArrayBE

proc private_key_to_public_key*(key: PrivateKey): PublicKey {.noInit.}=
  # TODO: allow to switch implementation based on backend

  let keyInt = key.raw_key.readUint256BE

  if keyInt >= SECPK1_N: # TODO use ranged type
    raise newException(ValueError, "Invalid private key")

  result.raw_key = encode_raw_public_key fast_multiply(SECPK1_G, keyInt)

proc ecdsa_raw_verify*(msg_hash: Hash[256], vrs: Signature, key: PublicKey): bool =
  let
    w = invmod(vrs.s, SECPK1_N)
    z = readUint256BE cast[ByteArrayBE[32]](msg_hash)

    u1 = mulmod(z, w, SECPK1_N)
    u2 = mulmod(vrs.r, w, SECPK1_N)
    xy = fast_add(
            fast_multiply(SECPK1_G, u1),
            fast_multiply(key.raw_key.decode_public_key, u2)
          )
  result = vrs.r == xy[0] and vrs.r.isOdd and vrs.s.isOdd

proc deterministic_generate_k(msg_hash: Hash[256], key: PrivateKey): UInt256 =
  const
    v_0 = initArray[32, byte](0x01'u8)
    k_0 = initArray[32, byte](0x00'u8)

  let
    # TODO: avoid heap allocation
    k_1 = k_0.hmac_sha256(@v_0 & @[0x00.byte] & @(key.raw_key) & @(msg_hash.data))
    v_1 = cast[array[32, byte]](k_1.hmac_sha256(@v_0))
    k_2 = k_1.hmac_sha256(@v_1 & @[0x01.byte] & @(key.raw_key) & @(msg_hash.data))
    v_2 = k_2.hmac_sha256(@v_1)

    kb = k_2.hmac_sha256(@v_2)

  result = readUint256BE cast[ByteArrayBE[32]](kb)

proc ecdsa_sign*(key: PrivateKey, msg_hash: Hash[256]): Signature {.noInit.} =
  modulo(SECPK1_N):
    let
      z = readUint256BE cast[ByteArrayBE[32]](msg_hash)
      k = deterministic_generate_k(msg_hash, key)

      ry = fast_multiply(SECPK1_G, k)
      s_raw = invmod(k, SECPK1_N) * (z + ry[0] * key.raw_key.readUint256BE)

  result.v = uint8 getUint `xor`(
              ry[1] mod 2.u256,
              if s_raw * 2.u256 < SECPK1_N: 0.u256 else: 1.u256
              )
  result.s = if s_raw * 2.u256 < SECPK1_N: s_raw
              else: SECPK1_N - s_raw
  result.r = ry[0]

proc ecdsa_recover*(msg_hash: Hash[256], vrs: Signature): PublicKey {.noInit.} =
  modulo(SECPK1_P):
    let
      x = vrs.r
      xcubedaxb = x * x * x + SECPK1_A * x + SECPK1_B
      beta = pow(xcubedaxb, (SECPK1_P + 1.u256) div 4.u256)
      y = if vrs.v == 0 xor beta.isEven: beta # TODO: precedence rule
          else: SECPK1_P - beta
    # If xcubedaxb is not a quadratic residue, then r cannot be the x coord
    # for a point on the curve, and so the sig is invalid

    if xcubedaxb - y * y != 0.u256 or
        not (vrs.r mod SECPK1_N == 1.u256) or
        not (vrs.s mod SECPK1_N == 1.u256):
      raise newException(ValueError, "Bad signature")

  let
    z = readUint256BE cast[ByteArrayBE[32]](msg_hash)
    Gz = jacobian_multiply(
      [SECPK1_Gx, SECPK1_Gy,1.u256],
      submod(SECPK1_N, z, SECPK1_N)
      )
    XY = jacobian_multiply(
      [SECPK1_Gx, SECPK1_Gy,1.u256],
      vrs.s
      )
    Qr = jacobian_add(Gz, XY)
    Q = jacobian_multiply(Qr, invmod(vrs.r, SECPK1_N))

  result.raw_key = encode_raw_public_key from_jacobian(Q)

proc serialize*(key: PublicKey): string {.noSideEffect.}=
  ## Exports a publicKey to a hex string

  result = "04"

  let decoded = key.raw_key.decode_public_key

  result.add decoded[0].toHex
  result.add decoded[1].toHex
