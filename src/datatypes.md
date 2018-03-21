
# Secp256k1 Implementation details (MIT License)

Details on the secp256k1 implementation.
The Nim datatype is:

```Nim
type
  Scalar256 = distinct array[32, byte]
    # Secp256k1 makes the signature an opaque "implementation dependant". See details in datatypes.md
    # We hide the information too as the native backend might choose a different r,s representation.

  Signature* {.packed.}= object
    Fr*: Scalar256
    Fs*: Scalar256
    Fv*: range[0.byte .. 1.byte] # This should be 27..28 as per Ethereum but it's 0..1 in eth-keys ...
```

## Conversion to and from uint256 <-> byte array
https://github.com/bitcoin-core/secp256k1/blob/0b7024185045a49a1a6a4c5615bf31c94f63d9c4/src/scalar_low_impl.h#L47-L61

```C
static void secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
    const int base = 0x100 % EXHAUSTIVE_TEST_ORDER;
    int i;
    *r = 0;
    for (i = 0; i < 32; i++) {
       *r = ((*r * base) + b32[i]) % EXHAUSTIVE_TEST_ORDER;
    }
    /* just deny overflow, it basically always happens */
    if (overflow) *overflow = 0;
}

static void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar* a) {
    memset(bin, 0, 32);
    bin[28] = *a >> 24; bin[29] = *a >> 16; bin[30] = *a >> 8; bin[31] = *a;
}
```

## Loading, saving, parsing, serializing the signature
https://github.com/bitcoin-core/secp256k1/blob/0b7024185045a49a1a6a4c5615bf31c94f63d9c4/src/modules/recovery/main_impl.h#L12-L72

```C
static void secp256k1_ecdsa_recoverable_signature_load(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, int* recid, const secp256k1_ecdsa_recoverable_signature* sig) {
    (void)ctx;
    if (sizeof(secp256k1_scalar) == 32) {
        /* When the secp256k1_scalar type is exactly 32 byte, use its
         * representation inside secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
    *recid = sig->data[64];
}

static void secp256k1_ecdsa_recoverable_signature_save(secp256k1_ecdsa_recoverable_signature* sig, const secp256k1_scalar* r, const secp256k1_scalar* s, int recid) {
    if (sizeof(secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        secp256k1_scalar_get_b32(&sig->data[0], r);
        secp256k1_scalar_get_b32(&sig->data[32], s);
    }
    sig->data[64] = recid;
}

int secp256k1_ecdsa_recoverable_signature_parse_compact(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature* sig, const unsigned char *input64, int recid) {
    secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    (void)ctx;
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);
    ARG_CHECK(recid >= 0 && recid <= 3);

    secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        secp256k1_ecdsa_recoverable_signature_save(sig, &r, &s, recid);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int secp256k1_ecdsa_recoverable_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, int *recid, const secp256k1_ecdsa_recoverable_signature* sig) {
    secp256k1_scalar r, s;

    (void)ctx;
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(recid != NULL);

    secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, recid, sig);
    secp256k1_scalar_get_b32(&output64[0], &r);
    secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}
```
