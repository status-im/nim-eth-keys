# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import  ../datatypes, ../constants,
        ../private/array_utils,
        ./jacobian, ./mod_arithmetic, ./hmac

import  ttmath, keccak_tiny, strutils,
        nimsha2 # TODO: For SHA-256, use OpenSSL instead? (see https://rosettacode.org/wiki/SHA-256#Nim)


proc decode_public_key*(key: PublicKey): array[2, UInt256] {.noInit.}=
  result = cast[type result](key.raw_key)

proc encode_raw_public_key*(raw_key: array[2, UInt256]): PublicKey {.noInit.}=
  result.raw_key = cast[array[64, byte]](raw_key)

proc private_key_to_public_key*(key: PrivateKey): PublicKey {.noInit.}=
  # TODO: allow to switch implementation based on backend
  let private_key_as_num = cast[UInt256](key.raw_key)

  if private_key_as_num >= SECPK1_N:
    raise newException(ValueError, "Invalid private key")

  let raw_public_key = fast_multiply(SECPK1_G, private_key_as_num)
  result = raw_public_key.encode_raw_public_key

proc ecds_raw_verify*(msg_hash: Hash[256], vrs: Signature, key: PublicKey): bool =
  let
    raw_public_key = cast[array[2, UInt256]](key.raw_key)
    v = vrs.v + 27
  if not (27 <= v and v <= 34): # TODO: what is this? use ranged types
    raise newException(ValueError, "Invalid signature")

  let
    w = inv(vrs.s, SECPK1_N)
    z = cast[UInt256](msg_hash)

    u1 = (z * w) mod SECPK1_N
    u2 = (vrs.r * w) mod SECPK1_N
    xy = fast_add(
            fast_multiply(SECPK1_G, u1),
            fast_multiply(raw_public_key, u2)
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

  result = cast[UInt256](kb)

proc ecds_raw_sign(msg_hash: Hash[256], key: PrivateKey): Signature =
  let
    z = cast[Uint256](msg_hash)
    k = deterministic_generate_k(msg_hash, key)

    ry = fast_multiply(SECPK1_G, k)
    s_raw = inv(k, SECPK1_N) * (z + ry[0] * cast[UInt256](key.raw_key)) mod SECPK1_N

    result.v = ((ry[1] mod 2.u256) ** (if s_raw * 2.u256 < SECPK1_N: 0'u64 else: 1'u64))
    result.s =  if s_raw * 2.u256 < SECPK1_N: s_raw
                else: SECPK1_N - s_raw
    result.r = ry[0]

proc ecdsa_raw_recover(msg_hash: Hash[256], vrs: Signature): PublicKey {.noInit.} =
  let v = vrs.v + 27

  if not (27 <= v and v <= 34): # TODO: what is this? use ranged types
    raise newException(ValueError, "v must be in range 27-31") # TODO: Why is the error message about 31?
    # TODO: if $v: fix ambiguous call; both system.$(x: int)[declared in lib/system.nim(1846, 5)] and system.$(x: int64)[declared in lib/system.nim(1851, 5)] match for: (range 27..28(uint8))

  let
    x = vrs.r
    xcubedaxb = (x * x * x + SECPK1_A * x + SECPK1_B) mod SECPK1_P
    beta = pow(xcubedaxb, (SECPK1_P + 1.u256) div 4.u256) mod SECPK1_P
    y = if v.u256 mod (2.u256 ** beta) mod 2.u256 == 1.u256: beta # TODO: precedence rule
        else: SECPK1_P - beta
  # If xcubedaxb is not a quadratic residue, then r cannot be the x coord
  # for a point on the curve, and so the sig is invalid
  if (xcubedaxb - y * y) mod SECPK1_P != 0.u256 or
      not (vrs.r mod SECPK1_N == 1.u256) or
      not (vrs.s mod SECPK1_N == 1.u256):
    raise newException(ValueError, "BadSignature")

  let
    z = cast[UInt256](msg_hash)
    Gz = jacobian_multiply(
      [SECPK1_Gx, SECPK1_Gy,1.u256],
      (SECPK1_N - z) mod SECPK1_N
      )
    XY = jacobian_multiply(
      [SECPK1_Gx, SECPK1_Gy,1.u256],
      vrs.s
      )
    Qr = jacobian_add(Gz, XY)
    Q = jacobian_multiply(Qr, inv(vrs.r, SECPK1_N))
    raw_public_key = from_jacobian(Q)