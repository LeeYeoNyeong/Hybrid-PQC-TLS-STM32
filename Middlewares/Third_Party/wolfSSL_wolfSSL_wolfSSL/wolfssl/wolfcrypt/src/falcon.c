/* falcon.c
 *
 * wolfSSL Falcon verify-only implementation for STM32F439 (embedded).
 * Uses NIST/PQClean Falcon-512 reference code in falcon_ref/ directory.
 * No liboqs dependency — verification only (no sign/keygen).
 *
 * Supports:
 *   Level 1 = Falcon-512  (logn=9, n=512)
 *   Level 5 = Falcon-1024 (logn=10, n=1024)
 *
 * Copyright (C) 2025 — embedded PQC TLS project
 * SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(HAVE_FALCON)

#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* PQClean Falcon reference (verify-only) */
#include "falcon_ref/inner.h"

/* ------------------------------------------------------------------ */
/* Falcon parameter constants                                          */
/* ------------------------------------------------------------------ */

/* Nonce length (bytes) — same for all Falcon variants */
#define FALCON_NONCE_SIZE   40

/* Signature header byte = format | logn */
#define FALCON_SIG_COMPRESSED  0x20u   /* variable-length compressed format */
#define FALCON_SIG_PADDED      0x30u   /* fixed-length padded format (OQS TLS) */

/* Logn values */
#define FALCON_LOGN_512   9
#define FALCON_LOGN_1024  10

/* Public key sizes (1-byte header + polynomial coefficients) */
#define FALCON512_PK_SIZE    897    /* 1 + 512*14/8 */
#define FALCON1024_PK_SIZE  1793    /* 1 + 1024*14/8 */

/* Signature data array size (max polynomial elements) */
#define FALCON_MAX_N  1024

/* verify_raw tmp buffer: 2*n bytes */
#define FALCON512_TMP_SZ   1024   /* 2 * 512 */
#define FALCON1024_TMP_SZ  2048   /* 2 * 1024 */

/* ------------------------------------------------------------------ */
/* Helper: extract logn from key level                                 */
/* ------------------------------------------------------------------ */
static int falcon_logn(byte level) {
    if (level == 1) return FALCON_LOGN_512;
    if (level == 5) return FALCON_LOGN_1024;
    return -1;
}

static word32 falcon_pubkey_size(byte level) {
    if (level == 1) return FALCON512_PK_SIZE;
    if (level == 5) return FALCON1024_PK_SIZE;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Basic key management                                                 */
/* ------------------------------------------------------------------ */

int wc_falcon_init(falcon_key *key) {
    return wc_falcon_init_ex(key, NULL, INVALID_DEVID);
}

int wc_falcon_init_ex(falcon_key *key, void *heap, int devId) {
    if (key == NULL) return BAD_FUNC_ARG;
    (void)heap;
    (void)devId;
    XMEMSET(key, 0, sizeof(*key));
    return 0;
}

void wc_falcon_free(falcon_key *key) {
    if (key == NULL) return;
    ForceZero(key, sizeof(*key));
}

int wc_falcon_set_level(falcon_key *key, byte level) {
    if (key == NULL) return BAD_FUNC_ARG;
    if (level != 1 && level != 5) return BAD_FUNC_ARG;
    key->level = level;
    return 0;
}

int wc_falcon_get_level(falcon_key *key, byte *level) {
    if (key == NULL || level == NULL) return BAD_FUNC_ARG;
    *level = key->level;
    return 0;
}

int wc_falcon_size(falcon_key *key) {
    if (key == NULL) return BAD_FUNC_ARG;
    return (int)falcon_pubkey_size(key->level);
}

int wc_falcon_pub_size(falcon_key *key) {
    return wc_falcon_size(key);
}

int wc_falcon_priv_size(falcon_key *key) {
    (void)key;
    return NOT_COMPILED_IN;   /* sign not supported */
}

int wc_falcon_sig_size(falcon_key *key) {
    if (key == NULL) return BAD_FUNC_ARG;
    if (key->level == 1) return FALCON_LEVEL1_SIG_SIZE;
    if (key->level == 5) return FALCON_LEVEL5_SIG_SIZE;
    return BAD_FUNC_ARG;
}

int wc_falcon_check_key(falcon_key *key) {
    if (key == NULL) return BAD_FUNC_ARG;
    if (!key->pubKeySet) return BAD_FUNC_ARG;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public key import                                                    */
/* ------------------------------------------------------------------ */

int wc_falcon_import_public(const byte *in, word32 inLen, falcon_key *key) {
    word32 expected;

    if (in == NULL || key == NULL) return BAD_FUNC_ARG;
    if (key->level != 1 && key->level != 5) return BAD_FUNC_ARG;

    expected = falcon_pubkey_size(key->level);
    if (inLen < expected) return BUFFER_E;

    XMEMCPY(key->p, in, expected);
    key->pubKeySet = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* DER public key decode                                               */
/* (Called by wolfSSL ASN parsing; try raw first, then DER wrapper)   */
/* ------------------------------------------------------------------ */

int wc_Falcon_PublicKeyDecode(const byte *input, word32 *inOutIdx,
                               falcon_key *key, word32 inSz) {
    int ret;
    word32 idx;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    idx = *inOutIdx;

    /* Attempt 1: treat as raw Falcon public key (first byte = logn) */
    if (idx < inSz) {
        byte hdr = input[idx];
        if (hdr == FALCON_LOGN_512 || hdr == FALCON_LOGN_1024) {
            byte lvl = (hdr == FALCON_LOGN_512) ? 1 : 5;
            if (key->level == 0) key->level = lvl;  /* auto-detect level */
            ret = wc_falcon_import_public(input + idx, inSz - idx, key);
            if (ret == 0) {
                *inOutIdx = idx + falcon_pubkey_size(key->level);
                return 0;
            }
        }
    }

    /* Attempt 2: SubjectPublicKeyInfo DER wrapping
     * Format: SEQUENCE { AlgId { OID } BIT STRING { 0x00 [raw key] } }
     * wolfSSL's ASN parsing often strips SEQUENCE+AlgId before calling us,
     * leaving just the BIT STRING content. Try to skip a leading 0x00 byte.
     */
    if (idx < inSz && input[idx] == 0x00) {
        idx++;  /* skip unused-bits byte of BIT STRING */
    }
    if (idx < inSz) {
        byte hdr = input[idx];
        if (hdr == FALCON_LOGN_512 || hdr == FALCON_LOGN_1024) {
            byte lvl = (hdr == FALCON_LOGN_512) ? 1 : 5;
            if (key->level == 0) key->level = lvl;
            ret = wc_falcon_import_public(input + idx, inSz - idx, key);
            if (ret == 0) {
                *inOutIdx = idx + falcon_pubkey_size(key->level);
                return 0;
            }
        }
    }

    return ASN_PARSE_E;
}

/* ------------------------------------------------------------------ */
/* wc_falcon_verify_msg                                                */
/*                                                                     */
/* sig[]    : Falcon signature (compressed or padded OQS format)       */
/* sigLen   : length of sig in bytes                                   */
/* msg[]    : TLS sigData (transcript data to verify)                  */
/* msgLen   : length of msg                                            */
/* res      : output — 1 = valid, 0 = invalid                         */
/* key      : falcon_key with pubKeySet = 1                            */
/* ------------------------------------------------------------------ */

int wc_falcon_verify_msg(const byte *sig, word32 sigLen,
                          const byte *msg, word32 msgLen,
                          int *res, falcon_key *key) {
    int logn, n;
    int ret = SIG_VERIFY_E;
    byte sig_hdr, pk_hdr;
    const byte *nonce, *comp_sig;
    word32 comp_sig_len;

    /* Heap-allocated working buffers — too large for tlsPerf 20KB stack
     * (~8.5KB total would corrupt adjacent FreeRTOS task list nodes during
     * Falcon CertVerify on STM32F4 + FreeRTOS). */
    uint16_t *h_ntt = NULL;
    uint16_t *c0    = NULL;
    int16_t  *s2    = NULL;
    byte     *tmp   = NULL;

    inner_shake256_context sc;
    size_t decoded;

    *res = 0;

    /* ---- validate parameters ---- */
    if (sig == NULL || msg == NULL || res == NULL || key == NULL)
        return BAD_FUNC_ARG;
    if (!key->pubKeySet)
        return BAD_FUNC_ARG;
    if (sigLen < 1 + FALCON_NONCE_SIZE + 1)   /* minimum: hdr + nonce + 1 byte sig */
        return BUFFER_E;

    /* ---- parse signature header ---- */
    sig_hdr = sig[0];
    if ((sig_hdr & 0xF0u) == FALCON_SIG_COMPRESSED) {
        logn = (int)(sig_hdr & 0x0Fu);
    } else if ((sig_hdr & 0xF0u) == FALCON_SIG_PADDED) {
        logn = (int)(sig_hdr & 0x0Fu);
    } else {
        return SIG_VERIFY_E;
    }

    if (logn != FALCON_LOGN_512 && logn != FALCON_LOGN_1024)
        return SIG_VERIFY_E;

    /* key level must match signature logn */
    if (falcon_logn(key->level) != logn)
        return SIG_VERIFY_E;

    n = 1 << logn;

    /* ---- allocate working buffers ---- */
    h_ntt = (uint16_t *)XMALLOC(FALCON_MAX_N * sizeof(uint16_t), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    c0    = (uint16_t *)XMALLOC(FALCON_MAX_N * sizeof(uint16_t), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    s2    = (int16_t  *)XMALLOC(FALCON_MAX_N * sizeof(int16_t),  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    tmp   = (byte     *)XMALLOC(FALCON1024_TMP_SZ,               NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (h_ntt == NULL || c0 == NULL || s2 == NULL || tmp == NULL) {
        ret = MEMORY_E;
        goto cleanup;
    }

    /* ---- locate nonce and compressed signature ---- */
    nonce    = sig + 1;
    comp_sig = sig + 1 + FALCON_NONCE_SIZE;
    comp_sig_len = sigLen - 1 - FALCON_NONCE_SIZE;

    /* ---- decode public key h -> NTT+Montgomery form ---- */
    pk_hdr = key->p[0];
    if ((int)(pk_hdr) != logn) {
        ret = SIG_VERIFY_E;
        goto cleanup;
    }

    decoded = PQCLEAN_FALCON512_CLEAN_modq_decode(
                  h_ntt, (unsigned)logn,
                  key->p + 1,                   /* skip 1-byte header */
                  (size_t)(falcon_pubkey_size(key->level) - 1));
    if (decoded == 0) {
        ret = SIG_VERIFY_E;
        goto cleanup;
    }

    PQCLEAN_FALCON512_CLEAN_to_ntt_monty(h_ntt, (unsigned)logn);

    /* ---- decode signature polynomial s2 ---- */
    decoded = PQCLEAN_FALCON512_CLEAN_comp_decode(
                  s2, (unsigned)logn,
                  comp_sig, (size_t)comp_sig_len);
    if (decoded == 0) {
        ret = SIG_VERIFY_E;
        goto cleanup;
    }

    /* ---- hash nonce || msg to get polynomial c0 ---- */
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, FALCON_NONCE_SIZE);
    inner_shake256_inject(&sc, msg, (size_t)msgLen);
    inner_shake256_flip(&sc);

    if (sc.buf == NULL) {
        inner_shake256_ctx_release(&sc);
        ret = MEMORY_E;
        goto cleanup;
    }

    PQCLEAN_FALCON512_CLEAN_hash_to_point_vartime(&sc, c0, (unsigned)logn);
    inner_shake256_ctx_release(&sc);

    /* ---- algebraic verification ---- */
    if (PQCLEAN_FALCON512_CLEAN_verify_raw(
            c0, s2, h_ntt, (unsigned)logn, tmp) == 1) {
        *res = 1;
    }
    ret = 0;

cleanup:
    if (h_ntt) XFREE(h_ntt, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (c0)    XFREE(c0,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (s2)    XFREE(s2,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp)   XFREE(tmp,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Signing — not implemented (verify-only build)                       */
/* ------------------------------------------------------------------ */

int wc_falcon_sign_msg(const byte *in, word32 inLen, byte *out, word32 *outLen,
                        falcon_key *key, WC_RNG *rng) {
    (void)in; (void)inLen; (void)out; (void)outLen; (void)key; (void)rng;
    return NOT_COMPILED_IN;
}

/* ------------------------------------------------------------------ */
/* Key export / import private — not implemented                       */
/* ------------------------------------------------------------------ */

int wc_falcon_import_private_only(const byte *priv, word32 privSz,
                                   falcon_key *key) {
    (void)priv; (void)privSz; (void)key;
    return NOT_COMPILED_IN;
}

int wc_falcon_import_private_key(const byte *priv, word32 privSz,
                                  const byte *pub, word32 pubSz,
                                  falcon_key *key) {
    (void)priv; (void)privSz; (void)pub; (void)pubSz; (void)key;
    return NOT_COMPILED_IN;
}

int wc_falcon_export_public(falcon_key *key, byte *out, word32 *outLen) {
    word32 sz;
    if (key == NULL || out == NULL || outLen == NULL) return BAD_FUNC_ARG;
    if (!key->pubKeySet) return BAD_FUNC_ARG;
    sz = falcon_pubkey_size(key->level);
    if (*outLen < sz) { *outLen = sz; return BUFFER_E; }
    XMEMCPY(out, key->p, sz);
    *outLen = sz;
    return 0;
}

int wc_falcon_export_private_only(falcon_key *key, byte *out, word32 *outLen) {
    (void)key; (void)out; (void)outLen;
    return NOT_COMPILED_IN;
}

int wc_falcon_export_private(falcon_key *key, byte *out, word32 *outLen) {
    (void)key; (void)out; (void)outLen;
    return NOT_COMPILED_IN;
}

int wc_falcon_export_key(falcon_key *key, byte *priv, word32 *privSz,
                          byte *pub, word32 *pubSz) {
    (void)key; (void)priv; (void)privSz; (void)pub; (void)pubSz;
    return NOT_COMPILED_IN;
}

/* ------------------------------------------------------------------ */
/* DER encoding — not implemented (server role only needs decode)      */
/* ------------------------------------------------------------------ */

int wc_Falcon_PrivateKeyDecode(const byte *input, word32 *inOutIdx,
                                falcon_key *key, word32 inSz) {
    (void)input; (void)inOutIdx; (void)key; (void)inSz;
    return NOT_COMPILED_IN;
}

int wc_Falcon_KeyToDer(falcon_key *key, byte *output, word32 inLen) {
    (void)key; (void)output; (void)inLen;
    return NOT_COMPILED_IN;
}

int wc_Falcon_PrivateKeyToDer(falcon_key *key, byte *output, word32 inLen) {
    (void)key; (void)output; (void)inLen;
    return NOT_COMPILED_IN;
}

int wc_Falcon_PublicKeyToDer(falcon_key *key, byte *output, word32 inLen,
                              int withAlg) {
    (void)key; (void)output; (void)inLen; (void)withAlg;
    return NOT_COMPILED_IN;
}

#endif /* HAVE_FALCON */
