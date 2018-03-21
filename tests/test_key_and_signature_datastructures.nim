# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import  ../src/eth_keys, ../src/private/conversion_bytes,
        ./config

import  unittest

suite "Test key and signature data structure":
  test "Signing from private key object":
    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSG)

      check: signature.Fv == person.raw_sig.v
      check: signature.Fr == hexToByteArrayBE[32](person.raw_sig.r)
      check: signature.Fs == hexToByteArrayBE[32](person.raw_sig.s)

  test "Signing from private key object (ported from official eth-keys)":
    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSG)

      check: verify_msg(pk.Fpublic_key, MSG, signature)

  test "Hash signing from private key object":

    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSG)

      check: signature.Fv == person.raw_sig.v
      check: signature.Fr == hexToByteArrayBE[32](person.raw_sig.r)
      check: signature.Fs == hexToByteArrayBE[32](person.raw_sig.s)

  test "Hash signing from private key object (ported from official eth-keys)":
    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSGHASH)

      check: verify_msg(pk.Fpublic_key, MSGHASH, signature)

  test "Recover public key from message":
    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSG)

        recovered_pubkey = recover_pubkey_from_msg(MSG, signature)

      check: pk.Fpublic_key == recovered_pubkey

  test "Recover public key from message hash":
    for person in [alice, bob, eve]:
      let
        pk = initPrivateKey(person.privkey)
        signature = pk.sign_msg(MSGHASH)

        recovered_pubkey = recover_pubkey_from_msg(MSGHASH, signature)

      check: pk.Fpublic_key == recovered_pubkey
