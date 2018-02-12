# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import algorithm

proc initArray*[N: static[int], T](value: T): array[N, T] {.noInit.}=
  result.fill(value)

proc `$`*[N:static[int]](a: array[N, byte]): string =
  $(cast[array[N, char]](a))

proc `&`*[N1, N2: static[int], T](
    a: array[N1, T],
    b: array[N2, T]
    ): array[N1 + N2, T] =
  ## Array concatenation
  result[0 ..< N1] = a
  result[N1 ..< N2] = b