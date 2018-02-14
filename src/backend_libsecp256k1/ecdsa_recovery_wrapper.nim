# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

# To delete when available in nim-libsecp256k1
# https://github.com/status-im/nim-secp256k1


{.deadCodeElim: on.}

import secp256k1

when defined(windows):
  const Lib = "secp256k1.dll"
elif defined(macosx):
  const Lib = "libsecp256k1(|.0).dylib"
else:
  const Lib = "libsecp256k1.so(|.0)"

when defined(static_secp256k1):
  {.pragma: secp, importc, cdecl.}
else:
  {.pragma: secp, dynlib: Lib, importc, cdecl.}

type
  secp256k1_ecdsa_recoverable_signature* = object
    ## Opaque data structured that holds a parsed ECDSA signature,
    ## supporting pubkey recovery.
    ## The exact representation of data inside is implementation defined and not
    ## guaranteed to be portable between different platforms or versions. It is
    ## however guaranteed to be 65 bytes in size, and can be safely copied/moved.
    ## If you need to convert to a format suitable for storage or transmission, use
    ## the secp256k1_ecdsa_signature_serialize_* and
    ## secp256k1_ecdsa_signature_parse_* functions.
    ## Furthermore, it is guaranteed that identical signatures (including their
    ## recoverability) will have identical representation, so they can be
    ## memcmp'ed.
    data*: array[65, uint8]

proc secp256k1_ecdsa_sign_recoverable*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_recoverable_signature;
  msg32: ptr cuchar;
  seckey: ptr cuchar;
  noncefp: secp256k1_nonce_function;
  ndata: pointer): cint {.secp.}
  ##  Create a recoverable ECDSA signature.
  ##
  ##  Returns: 1: signature created
  ##           0: the nonce generation function failed, or the private key was invalid.
  ##  Args:    ctx:    pointer to a context object, initialized for signing (cannot be NULL)
  ##  Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
  ##  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
  ##           seckey: pointer to a 32-byte secret key (cannot be NULL)
  ##           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
  ##           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
  ##

proc secp256k1_ecdsa_recover*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey;
  sig: ptr secp256k1_ecdsa_recoverable_signature;
  msg32: ptr cuchar): cint {.secp.}
  ##  Recover an ECDSA public key from a signature.
  ##
  ##  Returns: 1: public key successfully recovered (which guarantees a correct signature).
  ##           0: otherwise.
  ##  Args:    ctx:        pointer to a context object, initialized for verification (cannot be NULL)
  ##  Out:     pubkey:     pointer to the recovered public key (cannot be NULL)
  ##  In:      sig:        pointer to initialized signature that supports pubkey recovery (cannot be NULL)
  ##           msg32:      the 32-byte message hash assumed to be signed (cannot be NULL)
  ##

proc secp256k1_ecdsa_recoverable_signature_serialize_compact*(
  ctx: ptr secp256k1_context;
  output64: ptr cuchar;
  recid: ptr cint;
  sig: ptr secp256k1_ecdsa_recoverable_signature): cint {.secp.}
  #  Serialize an ECDSA signature in compact format (64 bytes + recovery id).
  #
  #  Returns: 1
  #  Args: ctx:      a secp256k1 context object
  #  Out:  output64: a pointer to a 64-byte array of the compact signature (cannot be NULL)
  #        recid:    a pointer to an integer to hold the recovery id (can be NULL).
  #  In:   sig:      a pointer to an initialized signature object (cannot be NULL)
  #