# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

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
