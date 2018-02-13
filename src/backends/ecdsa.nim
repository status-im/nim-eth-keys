# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import  ../datatypes, ../constants,
        ../private/[array_utils, casting],
        ./jacobian, ./mod_arithmetic, ./hmac

import  ttmath, keccak_tiny, strutils,
        nimsha2 # TODO: For SHA-256, use OpenSSL instead? (see https://rosettacode.org/wiki/SHA-256#Nim)

proc private_key_to_public_key*(key: PrivateKey): PublicKey {.noInit.}=
  # TODO: allow to switch implementation based on backend

  if key.raw_key >= SECPK1_N: # TODO use ranged type
    raise newException(ValueError, "Invalid private key")

  result.raw_key = fast_multiply(SECPK1_G, key.raw_key)

proc ecdsa_raw_verify*(msg_hash: Hash[256], vrs: Signature, key: PublicKey): bool =
  let
    w = invmod(vrs.s, SECPK1_N)
    z = msg_hash.toUInt256

    u1 = (z * w) mod SECPK1_N
    u2 = (vrs.r * w) mod SECPK1_N
    xy = fast_add(
            fast_multiply(SECPK1_G, u1),
            fast_multiply(key.raw_key, u2)
          )
  result = vrs.r == xy[0] and vrs.r.isOdd and vrs.s.isOdd

proc deterministic_generate_k(msg_hash: Hash[256], key: PrivateKey): UInt256 =
  const
    v_0 = initArray[32, byte](0x01'u8)
    k_0 = initArray[32, byte](0x00'u8)

  let
    # TODO: avoid heap allocation
    k_1 = k_0.hmac_sha256(@v_0 & @[0x00.byte] & @(toByteArray(key.raw_key)) & @(msg_hash.data))
    v_1 = cast[array[32, byte]](k_1.hmac_sha256(@v_0))
    k_2 = k_1.hmac_sha256(@v_1 & @[0x01.byte] & @(toByteArray(key.raw_key)) & @(msg_hash.data))
    v_2 = k_2.hmac_sha256(@v_1)

    kb = k_2.hmac_sha256(@v_2)

  result = kb.toUInt256

proc ecdsa_raw_sign*(msg_hash: Hash[256], key: PrivateKey): Signature =
  let
    z = msg_hash.toUInt256
    k = deterministic_generate_k(msg_hash, key)

    ry = fast_multiply(SECPK1_G, k)
    s_raw = invmod(k, SECPK1_N) * (z + ry[0] * key.raw_key) mod SECPK1_N

  result.v = ((ry[1] mod 2.u256) ** (if s_raw * 2.u256 < SECPK1_N: 0'u64 else: 1'u64)).getUInt.uint8
  result.s = if s_raw * 2.u256 < SECPK1_N: s_raw
              else: SECPK1_N - s_raw
  result.r = ry[0]

proc ecdsa_raw_recover*(msg_hash: Hash[256], vrs: Signature): PublicKey {.noInit.} =

  let
    x = vrs.r
    xcubedaxb = (x * x * x + SECPK1_A * x + SECPK1_B) mod SECPK1_P
    beta = pow(xcubedaxb, (SECPK1_P + 1.u256) div 4.u256) mod SECPK1_P
    y = if vrs.v.u256 mod (2.u256 ** beta) mod 2.u256 == 1.u256: beta # TODO: precedence rule
        else: SECPK1_P - beta
  # If xcubedaxb is not a quadratic residue, then r cannot be the x coord
  # for a point on the curve, and so the sig is invalid
  if (xcubedaxb - y * y) mod SECPK1_P != 0.u256 or
      not (vrs.r mod SECPK1_N == 1.u256) or
      not (vrs.s mod SECPK1_N == 1.u256):
    raise newException(ValueError, "BadSignature")

  let
    z = msg_hash.toUInt256
    Gz = jacobian_multiply(
      [SECPK1_Gx, SECPK1_Gy,1.u256],
      (SECPK1_N - z) mod SECPK1_N
      )
    XY = jacobian_multiply(
      [SECPK1_Gx, SECPK1_Gy,1.u256],
      vrs.s
      )
    Qr = jacobian_add(Gz, XY)
    Q = jacobian_multiply(Qr, invmod(vrs.r, SECPK1_N))

  result.raw_key = from_jacobian(Q)