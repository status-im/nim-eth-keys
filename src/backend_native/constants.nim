# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# SECPK1N

import ttmath

let
  # TODO: Compile-Time Evaluation of those contants
  # cf: https://en.bitcoin.it/wiki/Secp256k1
  SECPK1_P* = "115792089237316195423570985008687907853269984665640564039457584007908834671663".u256
  SECPK1_N* = "115792089237316195423570985008687907852837564279074904382605163141518161494337".u256
  SECPK1_A* = 0.u256
  SECPK1_B* = 7.u256
  SECPK1_Gx* = "55066263022277343669578718895168534326250603453777594175500187360389116729240".u256
  SECPK1_Gy* = "32670510020758816978083085130507043184471273380659243275938904335757337482424".u256
  SECPK1_G* = [SECPK1_Gx, SECPK1_Gy]
