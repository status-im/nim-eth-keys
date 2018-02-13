# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import  ../src/eth_keys,
        ./config

import  unittest, keccak_tiny

let
  MSG = "message"
  MSGHASH = keccak256(MSG)

suite "Test key and signature datastructures":
  test "Signing fromprivate key object":

    for person in [alice, bob, eve]:
      let signature = person.privkey.sign_msg(MSG)

      check: verify_msg_hash(person.privkey.public_key, MSGHASH, signature)