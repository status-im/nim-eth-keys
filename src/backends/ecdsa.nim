# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).```

import ../datatypes, ../constants, ./jacobian, ./mod_arithmetic
import ttmath, keccak_tiny, strutils


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

proc ecds_raw_verify*(msg_hash: Hash[256], vrs: Vrs, key: PublicKey): bool =

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

proc ecdsa_raw_recover(msg_hash: Hash[256], vrs: Vrs): PublicKey {.noInit.} =
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