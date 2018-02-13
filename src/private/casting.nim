# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import ttmath, keccak_tiny, nimsha2

# We can't use Nim cast :/ to avoid copy

proc toUint256*[T: Hash[256]|array[32, byte|char]](hash: T): UInt256 =
  copyMem(addr result, unsafeAddr hash, 32)

proc toByteArray*(num: UInt256): array[32, byte] =
  copyMem(addr result, unsafeAddr num, 32)