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

  test "Signing from private key object (ported from official eth-keys)":
    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSG)

      check: verify_msg(pk.public_key, MSG, signature)

  test "Hash signing from private key object":

    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSG)

      check: signature.v == person.raw_sig.v
      check: signature.r == person.raw_sig.r.u256
      check: signature.s == person.raw_sig.s.u256

  test "Hash signing from private key object (ported from official eth-keys)":
    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSGHASH)

      check: verify_msg(pk.public_key, MSGHASH, signature)

  test "Recover public key from message":
    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSG)

        recovered_pubkey = recover_pubkey_from_msg(MSG, signature)

      check: pk.public_key == recovered_pubkey

  test "Recover public key from message hash":
    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSGHASH)

        recovered_pubkey = recover_pubkey_from_msg(MSGHASH, signature)

      check: pk.public_key == recovered_pubkey