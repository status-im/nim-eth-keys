# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import ./constants, ./mod_arithmetic
import ttmath

proc to_jacobian(p: array[2, UInt256]): array[3, UInt256] {.noInit.}=
  [p[0], p[1], 1.u256]

proc jacobian_double(p: array[3, UInt256]): array[3, UInt256] {.noInit.}=
  if p[1] == 0.u256:
    return [0.u256, 0.u256, 0.u256]

  modulo(SECPK1_P):
    let
      ysq = p[1] ^ 2.u256
      S   = 4.u256 * p[0] * ysq
      M   = 3.u256 * (p[0] ^ 2.u256) + SECPK1_A * (p[2] ^ 4.u256)
      nx  = M ^ 2.u256 - 2.u256 * S
      ny  = M * (S - nx) - 8.u256 * (ysq ^ 2.u256)
      nz  = 2.u256 * p[1] * p[2]

  result = [nx, ny, nz]

proc jacobian_add*(p, q: array[3, UInt256]): array[3, UInt256] {.noInit.}=
  if p[1] == 0.u256:
    return q
  if q[1] == 0.u256:
    return p

  modulo(SECPK1_P):
    let
      U1 = p[0] * (q[2] ^ 2.u256)
      U2 = q[0] * (p[2] ^ 2.u256)
      S1 = p[1] * (q[2] ^ 2.u256)
      S2 = q[1] * (p[2] ^ 2.u256)

  if U1 == U2:
    if S1 == S2:
      return [0.u256, 0.u256, 1.u256]
    return jacobian_double(p)

  modulo(SECPK1_P):
    let
      H = U2 - U1
      R = S2 - S1
      H2 = H * H
      H3 = H * H2
      U1H2 = U1 * H2
      nx = R ^ 2.u256 - H3 - 2.u256 * U1H2
      ny = R * (U1H2 - nx) - S1 * H3
      nz = H * p[2] * q[2]

  result = [nx, ny, nz]

proc from_jacobian*(p: array[3, UInt256]): array[2, UInt256] =
  let z = invmod(p[2], SECPK1_P)
  modulo(SECPK1_P):
    result = [p[0] * (z ^ 2.u256), p[1] * (z ^ 3.u256)]

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
