# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import ttmath

proc isEven*(a: UInt256): bool =
  (a and 1.u256) == 0.u256

proc isOdd*(a: UInt256): bool =
  (a and 1.u256) != 0.u256