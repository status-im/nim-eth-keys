# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

# In Nim this must be in a separate files from datatypes to avoid recursive dependencies
# between datatypes <-> ecdsa

# Note: for now only a native pure Nim backend is supported
# In the future alternative, proven crypto backend will be added like libsecpk1

import  ./datatypes

import keccak_tiny

when defined(backend_native):
  import ./backend_native/ecdsa
else:
  import ./backend_libsecp256k1/libsecp256k1
  export libsecp256k1.serialize

# ################################
# Initialization

proc initPrivateKey*(hexString: string): PrivateKey {.noInit.}=
  result.raw_key = hexToByteArrayBE[32](hexString)
  result.public_key = private_key_to_public_key(result)

# ################################
# Public key/signature interface

proc recover_pubkey_from_msg*(message_hash: Hash[256], sig: Signature): PublicKey {.inline.}=
  ecdsa_recover(message_hash, sig)

proc recover_pubkey_from_msg*(message: string, sig: Signature): PublicKey {.inline.}=
  let message_hash = keccak_256(message)
  ecdsa_recover(message_hash, sig)

proc verify_msg*(key: PublicKey, message_hash: Hash[256], sig: Signature): bool {.inline.}=
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
