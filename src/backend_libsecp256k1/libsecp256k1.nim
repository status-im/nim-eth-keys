# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ../datatypes
import secp256k1, keccak_tiny

const SECP256K1_CONTEXT_ALL = SECP256K1_CONTEXT_VERIFY or SECP256K1_CONTEXT_SIGN

let ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL)

{.experimental.}
proc `=destroy`(ctx: ptr secp256k1_context) =
  if not ctx.isNil:
    ctx.secp256k1_context_destroy

type
  Serialized_PubKey = ByteArrayBE[65]

proc asPtrPubKey(key: PublicKey): ptr secp256k1_pubkey =
  cast[ptr secp256k1_pubkey](unsafeAddr key.raw_key)

proc asPtrCuchar(key: PrivateKey): ptr cuchar =
  cast[ptr cuchar](unsafeAddr key.raw_key)

proc asPtrCuchar(key: Serialized_PubKey): ptr cuchar =
  cast[ptr cuchar](unsafeAddr key)

proc asPtrCuchar(msg_hash: Hash[256]): ptr cuchar =
  cast[ptr cuchar](unsafeAddr msg_hash)

proc asPtrRecoverableSignature(sig: Signature): ptr secp256k1_ecdsa_recoverable_signature =
  cast[ptr secp256k1_ecdsa_recoverable_signature](unsafeAddr sig)

proc private_key_to_public_key*(key: PrivateKey): PublicKey {.noInit.}=
  ## Generates a public key from the private key
  let success:bool = bool secp256k1_ec_pubkey_create(
    ctx,
    result.asPtrPubKey,
    key.asPtrCuchar
  )

  if not success:
    raise newException(ValueError, "Private key is invalid")

proc serialize*(key: PublicKey): string =
  ## Exports a publicKey to a hex string
  var
    tmp{.noInit.}: Serialized_PubKey
    tmp_len: csize = 65

  # Proc always return 1
  discard secp256k1_ec_pubkey_serialize(
    ctx,
    tmp.asPtrCuchar,
    addr tmp_len,
    key.asPtrPubKey,
    SECP256K1_EC_UNCOMPRESSED
  )

  assert tmp_len == 65 # header 0x04 (uncompressed) + 128 hex char

  result = tmp.toHex

proc parsePublicKey*(data: openarray[byte]): PublicKey =
  ## Parse a variable-length public key into the PublicKey object
  if secp256k1_ec_pubkey_parse(ctx, result.asPtrPubKey, cast[ptr cuchar](unsafeAddr data[0]), data.len.csize) != 1:
    raise newException(Exception, "Could not parse public key")

proc ecdsa_sign*(key: PrivateKey, msg_hash: Hash[256]): Signature {.noInit.}=
  ## Sign a message with a recoverable signature
  ## Input:
  ##   - A message encoded with keccak_256
  ## Output:
  ##   - A recoverable signature

  let success: bool = bool secp256k1_ecdsa_sign_recoverable(
    ctx,
    result.asPtrRecoverableSignature,
    msg_hash.asPtrCuchar,
    key.asPtrCuchar,
    nil, # Nonce function, default is RFC6979 (HMAC-SHA256)
    nil  # Arbitrary data for the nonce function
  )

  if not success:
    raise newException(ValueError, "The nonce generation function failed, or the private key was invalid.")

proc ecdsa_recover*(msg_hash: Hash[256], sig: Signature): PublicKey =
  ## Recover the Public Key from the message hash and the signature

  let success: bool = bool secp256k1_ecdsa_recover(
    ctx,
    result.asPtrPubKey,
    sig.asPtrRecoverableSignature,
    msg_hash.asPtrCuchar
  )

  if not success:
    raise newException(ValueError, "Failed to recover public key. Is the signature correct?")
