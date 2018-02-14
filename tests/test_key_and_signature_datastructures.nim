# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import  ../src/eth_keys,
        ./config

import  unittest

suite "Test key and signature data structure":
  test "Signing from private key object":

    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSG)

      check: signature.v == person.raw_sig.v
      check: signature.r == person.raw_sig.r.u256
      check: signature.s == person.raw_sig.s.u256