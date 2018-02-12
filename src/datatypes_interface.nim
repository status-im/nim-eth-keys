# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

# In Nim this must be in a separate files from datatypes to avoid recursive dependencies
# between datatypes <-> ecdsa

# Note: for now only a native pure Nim backend is supported
# In the future alternative, proven crypto backend will be added like libsecpk1

import ./backends/ecdsa, ./datatypes
import ./private/hex
import keccak_tiny

# ################################
# Initialization
proc initPublicKey*(bytes: array[64, byte]): PublicKey =
  result.raw_key = bytes

proc initPrivateKey*(bytes: array[32, byte]): PrivateKey =
  result.raw_key = bytes
  result.public_key = private_key_to_public_key(result)

proc initPublicKey*(hexString: string): PublicKey =
  result.raw_key = hexToByteArray[64](hexString)

proc initPrivateKey*(hexString: string): PrivateKey =
  result.raw_key = hexToByteArray[32](hexString)
  result.public_key = private_key_to_public_key(result)

# ################################
# Public key interface
proc pubKey_recover_from_msg_hash*(message_hash: Hash[256], sig: Signature): PublicKey {.inline.}=
  ecdsa_raw_recover(message_hash, sig)

proc pubKey_recover_from_msg*(message: string, sig: Signature): PublicKey {.inline.}=
  let message_hash = keccak_256(message)
  result = pubKey_recover_from_msg_hash(message_hash, sig)

proc pubKey_verify_msg_hash*(key: PublicKey, message_hash: Hash[256], sig: Signature): bool {.inline.}=
  key == ecdsa_raw_recover(message_hash, sig)

proc pubKey_verify_msg*(key: PublicKey, message: string, sig: Signature): bool {.inline.} =
  let message_hash = keccak_256(message)
  key == ecdsa_raw_recover(message_hash, sig)

# ################################
# Private key interface
proc privKey_sign_msg_hash*(key: PrivateKey, message_hash: Hash[256]): Signature {.inline.}=
  ecdsa_raw_sign(message_hash, key)

proc privKey_sign_msg*(key: PrivateKey, message: string): Signature {.inline.} =
  let message_hash = keccak_256(message)
  ecdsa_raw_sign(message_hash, key)

# ################################
# Signature interface is a duplicate of the public key interface