# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ttmath

proc isEven*(a: UInt256): bool =
  (a and 1.u256) == 0.u256

proc isOdd*(a: UInt256): bool =
  (a and 1.u256) != 0.u256

proc addmod*(a, b, m: UInt256): UInt256 =
  ## Modular addition

  let a_m = if a < m: a
            else: a mod m
  if b == 0.u256:
    return a_m
  let b_m = if b < m: b
            else: b mod m

  # We don't do a + b to avoid overflows
  # But we know that m at least is inferior to biggest UInt256

  let b_from_m = m - b_m
  if a_m >= b_from_m:
    return a_m - b_from_m
  return m - b_from_m + a_m

proc submod*(a, b, m: UInt256): UInt256 =
  ## Modular substraction

  let a_m = if a < m: a
            else: a mod m
  if b == 0.u256:
    return a_m
  let b_m = if b < m: b
            else: b mod m

  # We don't do a - b to avoid overflows

  if a_m >= b_m:
    return a_m - b_m
  return m - b_m + a_m

proc doublemod(a, m: UInt256): UInt256 {.inline.}=
  ## double a modulo m. assume a < m
  result = a
  if a >= m - a:
    result -= m
  result += a

proc mulmod*(a, b, m: UInt256): UInt256 =
  ## Modular multiplication

  var a_m = if a < m: a
            else: a mod m
  var b_m = if b < m: b
            else: b mod m

  if b_m > a_m:
    swap(a_m, b_m)
  while b_m > 0.u256:
    if b_m.isOdd:
      result = addmod(result, a_m, m)
    a_m = doublemod(a_m, m)
    b_m = b_m shr 1

proc expmod*(base, exponent, m: UInt256): UInt256 =
  ## Modular exponentiation

  # Formula from applied Cryptography by Bruce Schneier
  # function modular_pow(base, exponent, modulus)
  #     result := 1
  #     while exponent > 0
  #         if (exponent mod 2 == 1):
  #            result := (result * base) mod modulus
  #         exponent := exponent >> 1
  #         base = (base * base) mod modulus
  #     return result

  result = 1.u256 # (exp 0 = 1)

  var e = exponent
  var b = base

  while e > 0.u256:
    if isOdd e:
      result = mulmod(result, b, m)
    e = e shr 1 # e div 2
    b = mulmod(b,b,m)

proc invmod*(a, m: UInt256): UInt256 =
  ## Modular multiplication inverse
  ## Input:
  ##   - 2 positive integers a and m
  ## Result:
  ##   - An integer z that solves `az ≡ 1 mod m`
  # Adapted from Knuth, The Art of Computer Programming, Vol2 p342
  # and Menezes, Handbook of Applied Cryptography (HAC), p610
  # to avoid requiring signed integers
  # http://cacr.uwaterloo.ca/hac/about/chap14.pdf

  # Starting from the binary extended GCD formula (Bezout identity),
  # `ax + by = gcd(x,y)`
  # with input x,y and outputs a, b, gcd
  # We assume a and m are coprimes, i.e. gcd is 1, otherwise no inverse
  # `ax + my = 1`
  # `ax + my ≡ 1 mod m`
  # `ax ≡ 1 mod m``
  # Meaning we can use the Extended Euclid Algorithm
  # `ax + by` with
  # a = a, x = result, b = m, y = 0

  var
    a = a
    x = 1.u256
    b = m
    y = 0.u256
    oddIter = true # instead of requiring signed int, we keep track of even/odd iterations which would be in negative

  while b != 0.u256:
    let
      q = a div b
      r = a mod b
      t = x + q * y
    x = y; y = t; a = b; b = r
    oddIter = not oddIter

  if a != 1.u256:
    # a now holds the gcd(a, m) and should equal 1
    raise newException(ValueError, "No modular inverse exists")

  if oddIter:
    return x
  return m - x

template modulo*(modulus: UInt256, body: untyped): untyped =
  # `+`, `*`, `^` and pow will be replaced by their modular version
  template `+`(a, b: UInt256): UInt256 =
    addmod(a, b, `modulus`)
  template `-`(a, b: UInt256): UInt256 =
    submod(a, b, `modulus`)
  template `*`(a, b: UInt256): UInt256 =
    mulmod(a, b, `modulus`)
  template `^`(a, b: UInt256): UInt256 =
    expmod(a, b, `modulus`)
  template pow(a, b: UInt256): UInt256 =
    expmod(a, b, `modulus`)
  body

when isMainModule:
  # https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/fast-modular-exponentiation
  assert expmod(5.u256, 117.u256, 19.u256) == 1.u256
  assert expmod(3.u256, 1993.u256, 17.u256) == 14.u256

  assert invmod(42.u256, 2017.u256) == 1969.u256
  assert invmod(271.u256, 383.u256) == 106.u256 # Handbook of Applied Cryptography p610
