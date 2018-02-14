import ../datatypes
import secp256k1

const SECP256K1_CONTEXT_ALL = SECP256K1_CONTEXT_VERIFY or SECP256K1_CONTEXT_SIGN

let ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL)

{.experimental.}
proc `=destroy`(ctx: ptr secp256k1_context) =
  if not ctx.isNil:
    ctx.secp256k1_context_destroy

type Serialized_PubKey = ByteArrayBE[65]
  # header 0x04 (uncompressed) + 128 hex char

proc asPtrPubKey(key: PublicKey): ptr secp256k1_pubkey =
  cast[ptr secp256k1_pubkey](unsafeAddr key.raw_key)

proc asPtrCuchar(key: PrivateKey): ptr cuchar =
  cast[ptr cuchar](unsafeAddr key.raw_key)

proc asPtrCuchar(key: Serialized_PubKey): ptr cuchar =
  cast[ptr cuchar](unsafeAddr key)

proc private_key_to_public_key*(key: PrivateKey): PublicKey {.noInit.}=

  let valid:bool = bool secp256k1_ec_pubkey_create(
    ctx,
    result.asPtrPubKey,
    key.asPtrCuchar
  )

  if not valid:
    raise newException(ValueError, "Private key is invalid")

proc serialize*(key: PublicKey): string =

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
