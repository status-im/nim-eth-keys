# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# In Nim this must be in a separate files from datatypes to avoid recursive dependencies
# between datatypes <-> ecdsa

# Note: for now only a native pure Nim backend is supported
# In the future alternative, proven crypto backend will be added like libsecpk1

import  ./datatypes, ./private/conversion_bytes

import keccak_tiny

when defined(backend_native):
  import ./backend_native/ecdsa
  export ecdsa.serialize
else:
  import ./backend_libsecp256k1/libsecp256k1
  export libsecp256k1.serialize
  export libsecp256k1.`$`
  export libsecp256k1.parsePublicKey

# ################################
# Initialization

proc initPrivateKey*(hexString: string): PrivateKey {.noInit.} =
  hexToByteArrayBE(hexString, result.Fraw_key)
  result.Fpublic_key = private_key_to_public_key(result)

proc initPublicKey*(hexString: string): PublicKey {.noInit.} =
  var b: array[65, byte]
  hexToByteArrayBE(hexString, b, 1, 64)
  b[0] = 0x4 # Uncompressed. See docs for secp256k1_ec_pubkey_parse
  result = parsePublicKey(b)

# ################################
# Public key/signature interface

proc recover_pubkey_from_msg*(message_hash: Hash[256], sig: Signature): PublicKey {.inline.} =
  ecdsa_recover(message_hash, sig)

proc recover_pubkey_from_msg*(message: string, sig: Signature): PublicKey {.inline.} =
  let message_hash = keccak_256(message)
  ecdsa_recover(message_hash, sig)

proc verify_msg*(key: PublicKey, message_hash: Hash[256], sig: Signature): bool {.inline.} =
  key == ecdsa_recover(message_hash, sig)

proc verify_msg*(key: PublicKey, message: string, sig: Signature): bool {.inline.} =
  let message_hash = keccak_256(message)
  key == ecdsa_recover(message_hash, sig)

# # ################################
# # Private key interface

proc sign_msg*(key: PrivateKey, message: string): Signature {.inline.} =
  let message_hash = keccak_256(message)
  ecdsa_sign(key, message_hash)

proc sign_msg*(key: PrivateKey, message_hash: Hash[256]): Signature {.inline.} =
  ecdsa_sign(key, message_hash)

proc `$`*(key: PrivateKey): string {.inline.} =
  key.Fraw_key.toHex()
