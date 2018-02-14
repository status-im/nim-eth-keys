# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

import  ../src/eth_keys,
        ./config

import unittest

suite "Testing private -> public key conversion":
  test "Known private to known public keys (test data from Ethereum eth-keys)":
    for person in [alice, bob, eve]:
      let privkey = initPrivateKey(person.privkey)

      let computed_pubkey = privkey.public_key.serialize

      check: computed_pubkey == "04" & person.pubkey # Serialization prefixes uncompressed public keys with 04