# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import ../constants, ./mod_arithmetic
import ttmath

# TODO: port modular arithmetic to 256-bit
# https://github.com/mratsim/nim-projecteuler/blob/master/src/lib/modular_arithmetic.nim

proc `**`*(a: UInt256, b: uint64|UInt256): UInt256 =
  # alias. Note: this has the same precedence as `*`
  pow(a, b)

proc to_jacobian(p: array[2, UInt256]): array[3, UInt256] {.noInit.}=
  [p[0], p[1], 1.u256]

proc jacobian_double(p: array[3, UInt256]): array[3, UInt256] {.noInit.}=
  if p[1] == 0.u256:
    return [0.u256, 0.u256, 0.u256]

  let
    # TODO implement modular exponentiation/squaring/addition/multiplication to avoid overflow
    ysq = (p[1] ** 2.u256)                                          mod SECPK1_P
    S   = (4.u256 * p[0] * ysq)                                     mod SECPK1_P
    M   = (3.u256 * (p[0] ** 2.u256) + SECPK1_A * (p[2] ** 4.u256)) mod SECPK1_P
    nx  = (M ** 2.u256 - 2.u256 * S)                                mod SECPK1_P
    ny  = (M * (S - nx) - 8.u256 * ysq ** 2.u256)                   mod SECPK1_P
    nz  = mulmod(mulmod(2.u256, p[1], SECPK1_P), p[2], SECPK1_P)    # 2.u256 * p[1] * p[2] mod SECPK1_P

  result = [nx, ny, nz]

proc jacobian_add*(p, q: array[3, UInt256]): array[3, UInt256] {.noInit.}=
  if p[1] == 0.u256:
    return q
  if q[1] == 0.u256:
    return p

  let
    U1 = (p[0] * (q[2] ** 2.u256)) mod SECPK1_P
    U2 = (q[0] * (p[2] ** 2.u256)) mod SECPK1_P
    S1 = (p[1] * (q[2] ** 2.u256)) mod SECPK1_P
    S2 = (q[1] * (p[2] ** 2.u256)) mod SECPK1_P

  if U1 == U2:
    if S1 == S2:
      return [0.u256, 0.u256, 1.u256]
    return jacobian_double(p)

  let
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H)                            mod SECPK1_P
    H3 = (H * H2)                           mod SECPK1_P
    U1H2 = (U1 * H2)                        mod SECPK1_P
    nx = (R ** 2.u256 - H3 - 2.u256 * U1H2) mod SECPK1_P
    ny = (R * (U1H2 - nx) - S1 * H3)        mod SECPK1_P
    nz = (H * p[2] * q[2])                  mod SECPK1_P

  result = [nx, ny, nz]

proc from_jacobian*(p: array[3, UInt256]): array[2, UInt256] =
  let z = invmod(p[2], SECPK1_P)
  result = [(p[0] * z**2.u256) mod SECPK1_P, (p[1] * z**3.u256) mod SECPK1_P]

proc jacobian_multiply*(a: array[3, UInt256], n: UInt256): array[3, UInt256] =
  if a[1] == 0.u256 or n == 0.u256:
    return [0.u256, 0.u256, 1.u256]
  elif n == 1.u256:
    return a
  elif n >= SECPK1_N: # note n cannot be < 0 in Nim
    return jacobian_multiply(a, n mod SECPK1_N)
  elif n.isEven:
    return jacobian_double jacobian_multiply(a, n div 2.u256)
  else: # n.isOdd
    return jacobian_add(jacobian_double jacobian_multiply(a, n div 2.u256), a)

proc fast_multiply*(a: array[2, UInt256], n: UInt256): array[2,UInt256] =
  return from_jacobian jacobian_multiply(a.to_jacobian, n)

proc fast_add*(a, b: array[2, UInt256]): array[2, UInt256] =
  return from_jacobian jacobian_add(a.to_jacobian, b.to_jacobian)