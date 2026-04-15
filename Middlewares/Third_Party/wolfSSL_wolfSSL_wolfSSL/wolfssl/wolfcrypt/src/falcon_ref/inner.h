/*
 * inner.h — wolfSSL-compatible Falcon inner header (verify-only)
 *
 * Replaces the fips202.h + fpr.h dependencies with wolfSSL SHAKE256.
 * FFT / signing functions are declared but not implemented (not needed).
 *
 * Based on PQClean Falcon-512 inner.h:
 *   Copyright (c) 2017-2019 Falcon Project (MIT License)
 */

#ifndef FALCON_INNER_H__
#define FALCON_INNER_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* wolfSSL headers */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/types.h>

/* ------------------------------------------------------------------ */
/* FPR stub — only the type is needed; no FFT functions used in verify */
/* ------------------------------------------------------------------ */
typedef double fpr;

/* set_fpu_cw() — no-op on ARM */
static inline unsigned set_fpu_cw(unsigned x) { return x; }

/* ------------------------------------------------------------------ */
/* SHAKE256 compatibility layer using wolfSSL                          */
/* ------------------------------------------------------------------ */

/*
 * Pre-allocated output buffer.  Falcon-1024 hash_to_point_vartime()
 * needs at most ~3500 bytes in expectation; 4096 bytes is safe.
 * Memory is heap-allocated at finalize() and freed at release().
 */
#define FALCON_SHAKE256_BUF_SZ 4096

typedef struct {
    wc_Shake wc;
    byte    *buf;   /* heap-allocated output buffer (NULL until flip) */
    word32   pos;   /* read position within buf */
} inner_shake256_context;

static inline void falcon_shake256_init(inner_shake256_context *sc) {
    wc_InitShake256(&sc->wc, NULL, INVALID_DEVID);
    sc->buf = NULL;
    sc->pos = 0;
}

static inline void falcon_shake256_absorb(inner_shake256_context *sc,
                                          const uint8_t *in, size_t len) {
    wc_Shake256_Update(&sc->wc, (const byte *)in, (word32)len);
}

static inline void falcon_shake256_finalize(inner_shake256_context *sc) {
    sc->buf = (byte *)XMALLOC(FALCON_SHAKE256_BUF_SZ, NULL,
                               DYNAMIC_TYPE_TMP_BUFFER);
    if (sc->buf != NULL) {
        wc_Shake256_Final(&sc->wc, sc->buf, FALCON_SHAKE256_BUF_SZ);
    }
    sc->pos = 0;
}

static inline void falcon_shake256_squeeze(uint8_t *out, size_t len,
                                           inner_shake256_context *sc) {
    if (sc->buf != NULL &&
        sc->pos + (word32)len <= (word32)FALCON_SHAKE256_BUF_SZ) {
        XMEMCPY(out, sc->buf + sc->pos, len);
        sc->pos += (word32)len;
    }
    /* If buffer is exhausted or NULL: zeros remain (error path) */
}

static inline void falcon_shake256_release(inner_shake256_context *sc) {
    if (sc->buf != NULL) {
        XFREE(sc->buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        sc->buf = NULL;
    }
}

/* Map PQClean API macros to our implementation */
#define inner_shake256_init(sc)               falcon_shake256_init(sc)
#define inner_shake256_inject(sc, in, len)    falcon_shake256_absorb(sc, (const uint8_t *)(in), len)
#define inner_shake256_flip(sc)               falcon_shake256_finalize(sc)
#define inner_shake256_extract(sc, out, len)  falcon_shake256_squeeze((uint8_t *)(out), len, sc)
#define inner_shake256_ctx_release(sc)        falcon_shake256_release(sc)

/* ------------------------------------------------------------------ */
/* Codec functions (codec.c)                                           */
/* ------------------------------------------------------------------ */

size_t PQCLEAN_FALCON512_CLEAN_modq_encode(void *out, size_t max_out_len,
        const uint16_t *x, unsigned logn);
size_t PQCLEAN_FALCON512_CLEAN_trim_i16_encode(void *out, size_t max_out_len,
        const int16_t *x, unsigned logn, unsigned bits);
size_t PQCLEAN_FALCON512_CLEAN_trim_i8_encode(void *out, size_t max_out_len,
        const int8_t *x, unsigned logn, unsigned bits);
size_t PQCLEAN_FALCON512_CLEAN_comp_encode(void *out, size_t max_out_len,
        const int16_t *x, unsigned logn);

size_t PQCLEAN_FALCON512_CLEAN_modq_decode(uint16_t *x, unsigned logn,
        const void *in, size_t max_in_len);
size_t PQCLEAN_FALCON512_CLEAN_trim_i16_decode(int16_t *x, unsigned logn,
        unsigned bits, const void *in, size_t max_in_len);
size_t PQCLEAN_FALCON512_CLEAN_trim_i8_decode(int8_t *x, unsigned logn,
        unsigned bits, const void *in, size_t max_in_len);
size_t PQCLEAN_FALCON512_CLEAN_comp_decode(int16_t *x, unsigned logn,
        const void *in, size_t max_in_len);

extern const uint8_t PQCLEAN_FALCON512_CLEAN_max_fg_bits[];
extern const uint8_t PQCLEAN_FALCON512_CLEAN_max_FG_bits[];
extern const uint8_t PQCLEAN_FALCON512_CLEAN_max_sig_bits[];

/* ------------------------------------------------------------------ */
/* Common support functions (common.c)                                 */
/* ------------------------------------------------------------------ */

void PQCLEAN_FALCON512_CLEAN_hash_to_point_vartime(
        inner_shake256_context *sc, uint16_t *x, unsigned logn);

void PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(
        inner_shake256_context *sc, uint16_t *x, unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCON512_CLEAN_is_short(const int16_t *s1, const int16_t *s2,
        unsigned logn);

int PQCLEAN_FALCON512_CLEAN_is_short_half(uint32_t sqn, const int16_t *s2,
        unsigned logn);

/* ------------------------------------------------------------------ */
/* Verification functions (vrfy.c)                                     */
/* ------------------------------------------------------------------ */

void PQCLEAN_FALCON512_CLEAN_to_ntt_monty(uint16_t *h, unsigned logn);

int PQCLEAN_FALCON512_CLEAN_verify_raw(const uint16_t *c0, const int16_t *s2,
        const uint16_t *h, unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCON512_CLEAN_compute_public(uint16_t *h,
        const int8_t *f, const int8_t *g, unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCON512_CLEAN_complete_private(int8_t *G,
        const int8_t *f, const int8_t *g, const int8_t *F,
        unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCON512_CLEAN_is_invertible(const int16_t *s2,
        unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCON512_CLEAN_count_nttzero(const int16_t *sig,
        unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCON512_CLEAN_verify_recover(uint16_t *h,
        const uint16_t *c0, const int16_t *s1, const int16_t *s2,
        unsigned logn, uint8_t *tmp);

/* ------------------------------------------------------------------ */
/* FFT / signing — declarations only, not compiled (no fpr.h needed)  */
/* ------------------------------------------------------------------ */

/* (signing functions omitted: FFT, keygen, expand_privkey, sign_tree) */

#endif /* FALCON_INNER_H__ */
