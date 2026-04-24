/* sphincs.c
 *
 * wolfSSL SPHINCS+-SHAKE verify-only implementation for STM32F439.
 * Supports 6 SHAKE simple variants (no SHA2, no liboqs):
 *   fast-L1  = SPHINCS+-SHAKE-128f-simple
 *   fast-L3  = SPHINCS+-SHAKE-192f-simple
 *   fast-L5  = SPHINCS+-SHAKE-256f-simple
 *   small-L1 = SPHINCS+-SHAKE-128s-simple
 *   small-L3 = SPHINCS+-SHAKE-192s-simple
 *   small-L5 = SPHINCS+-SHAKE-256s-simple
 *
 * Algorithm ported from PQClean (MIT License).
 * Hash via wolfSSL wc_Shake256_*.
 * Sign/keygen not implemented (client verify-only).
 *
 * Copyright (C) 2025 — embedded PQC TLS project
 * SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if defined(HAVE_SPHINCS)

#include <wolfssl/wolfcrypt/sphincs.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/types.h>
#include <string.h>

/* Yield to FreeRTOS scheduler inside long SPHINCS+ verify loops so that
 * the LwIP tcpip_thread (same priority) can process incoming TCP packets.
 * Without this, the 3.2-second verify monopolises the CPU and the server's
 * CertificateVerify/Finished frames are lost from the DMA RX buffer. */
#ifdef FREERTOS
    #include "FreeRTOS.h"
    #include "task.h"
    #define SPX_YIELD() taskYIELD()
#else
    #define SPX_YIELD() do {} while (0)
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* ------------------------------------------------------------------ */
/* SPHINCS+ SHAKE simple parameter sets                                */
/* ------------------------------------------------------------------ */

typedef struct {
    int n;           /* hash output size (bytes) */
    int h;           /* total hypertree height */
    int d;           /* number of tree layers */
    int fors_h;      /* FORS tree height */
    int fors_k;      /* number of FORS trees */
    int wots_len;    /* WOTS+ key length = 2n + 3 */
    int pk_bytes;    /* public key = 2*n */
    int sig_bytes;   /* total signature bytes */
} spx_params_t;

#define WOTS_W     16
#define WOTS_LOGW   4

/* Table indexed by variant:
 * 0 = fast-L1 (128f), 1 = fast-L3 (192f), 2 = fast-L5 (256f)
 * 3 = small-L1 (128s), 4 = small-L3 (192s), 5 = small-L5 (256s) */
static const spx_params_t spx_table[6] = {
    /* n   h    d  fh  fk  wl  pk   sig */
    { 16,  66, 22,  6, 33, 35,  32, 17088 }, /* fast-L1 */
    { 24,  66, 22,  8, 33, 51,  48, 35664 }, /* fast-L3 */
    { 32,  68, 17,  9, 35, 67,  64, 49856 }, /* fast-L5 */
    { 16,  63,  7, 12, 14, 35,  32,  7856 }, /* small-L1 */
    { 24,  63,  7, 14, 17, 51,  48, 16224 }, /* small-L3 */
    { 32,  64,  8, 14, 22, 67,  64, 29792 }, /* small-L5 */
};

static int spx_variant_index(byte level, byte optim) {
    /* optim: FAST_VARIANT=1, SMALL_VARIANT=2 */
    int base = (optim == SMALL_VARIANT) ? 3 : 0;
    if (level == 1) return base + 0;
    if (level == 3) return base + 1;
    if (level == 5) return base + 2;
    return -1;
}

/* ------------------------------------------------------------------ */
/* Address format (SHAKE offsets — PQClean shake_offsets.h)           */
/* addr is uint32_t[8] = 32 bytes, accessed as bytes                  */
/* ------------------------------------------------------------------ */

#define SPX_OFFSET_LAYER      3   /* 1 byte: layer number */
#define SPX_OFFSET_TREE       8   /* 8 bytes BE: tree index */
#define SPX_OFFSET_TYPE      19   /* 1 byte: address type */
#define SPX_OFFSET_KP_ADDR2  20   /* 1 byte: keypair address high byte (PQClean) */
#define SPX_OFFSET_KP_ADDR1  23   /* 1 byte: keypair address low byte */
#define SPX_OFFSET_CHAIN_ADDR 27  /* 1 byte: chain address */
#define SPX_OFFSET_HASH_ADDR  31  /* 1 byte: hash address */
#define SPX_OFFSET_TREE_HGT   27  /* 1 byte: tree height (alias of CHAIN) */
#define SPX_OFFSET_TREE_INDEX 28  /* 4 bytes BE: tree index in Merkle */

#define SPX_ADDR_TYPE_WOTS      0
#define SPX_ADDR_TYPE_WOTSPK    1
#define SPX_ADDR_TYPE_HASHTREE  2
#define SPX_ADDR_TYPE_FORSTREE  3
#define SPX_ADDR_TYPE_FORSPK    4
#define SPX_ADDR_TYPE_WOTSPRF   5
#define SPX_ADDR_TYPE_FORSPRF   6

typedef word32 spx_addr_t[8];

/* Write big-endian uint32 to 4 bytes */
static void spx_u32_to_bytes(byte *out, word32 val) {
    out[0] = (byte)(val >> 24);
    out[1] = (byte)(val >> 16);
    out[2] = (byte)(val >>  8);
    out[3] = (byte)(val);
}

/* Write big-endian uint64 to 8 bytes */
static void spx_u64_to_bytes(byte *out, word64 val) {
    spx_u32_to_bytes(out,     (word32)(val >> 32));
    spx_u32_to_bytes(out + 4, (word32)(val));
}

/* Read big-endian uint64 from `inlen` bytes */
static word64 spx_bytes_to_u64(const byte *in, int inlen) {
    word64 v = 0;
    int i;
    for (i = 0; i < inlen; i++)
        v = (v << 8) | in[i];
    return v;
}

static void spx_set_layer(spx_addr_t addr, word32 layer) {
    ((byte *)addr)[SPX_OFFSET_LAYER] = (byte)layer;
}
static void spx_set_tree(spx_addr_t addr, word64 tree) {
    spx_u64_to_bytes(&((byte *)addr)[SPX_OFFSET_TREE], tree);
}
static void spx_set_type(spx_addr_t addr, word32 type) {
    ((byte *)addr)[SPX_OFFSET_TYPE] = (byte)type;
}
static void spx_set_keypair(spx_addr_t addr, word32 kp) {
    /* Full 4-byte BE write to bytes 20-23: byte22=kp>>8, byte23=kp&0xFF
     * (matches liboqs/NIST-ref addr[5]=htobe32(kp)) */
    spx_u32_to_bytes(&((byte *)addr)[20], kp);
}
static void spx_set_chain(spx_addr_t addr, word32 chain) {
    ((byte *)addr)[SPX_OFFSET_CHAIN_ADDR] = (byte)chain;
}
static void spx_set_hash(spx_addr_t addr, word32 hash) {
    ((byte *)addr)[SPX_OFFSET_HASH_ADDR] = (byte)hash;
}
static void spx_set_tree_height(spx_addr_t addr, word32 h) {
    ((byte *)addr)[SPX_OFFSET_TREE_HGT] = (byte)h;
}
static void spx_set_tree_index(spx_addr_t addr, word32 idx) {
    spx_u32_to_bytes(&((byte *)addr)[SPX_OFFSET_TREE_INDEX], idx);
}

/* Copy layer+tree fields (bytes 0..15) */
static void spx_copy_subtree(spx_addr_t dst, const spx_addr_t src) {
    XMEMCPY(dst, src, SPX_OFFSET_TREE + 8); /* 16 bytes */
}

/* Copy layer+tree+keypair */
static void spx_copy_keypair(spx_addr_t dst, const spx_addr_t src) {
    XMEMCPY(dst, src, SPX_OFFSET_TREE + 8);
    /* Copy full 4-byte keypair word (bytes 20-23) */
    XMEMCPY(&((byte *)dst)[20], &((const byte *)src)[20], 4);
}

/* ------------------------------------------------------------------ */
/* thash: SHAKE256(pub_seed[n] || addr[32] || inputs[inblocks*n]) → n */
/* ------------------------------------------------------------------ */

static int spx_thash(byte *out, const byte *in, int inblocks,
                     const byte *pk_seed, int n, const spx_addr_t addr)
{
    wc_Shake sh;
    int ret = wc_InitShake256(&sh, NULL, INVALID_DEVID);
    if (ret != 0) return ret;
    wc_Shake256_Update(&sh, pk_seed, (word32)n);
    wc_Shake256_Update(&sh, (const byte *)addr, 32);
    wc_Shake256_Update(&sh, in, (word32)(inblocks * n));
    ret = wc_Shake256_Final(&sh, out, (word32)n);
    wc_Shake256_Free(&sh);
    return ret;
}

/* ------------------------------------------------------------------ */
/* hash_message: SHAKE256(R[n] || pk[2n] || msg) → dgst_bytes         */
/* Outputs: fors_msg (first fors_msg_bytes), tree (BE), leaf_idx      */
/* ------------------------------------------------------------------ */

static int spx_hash_message(byte *fors_msg, word64 *tree, word32 *leaf_idx,
                            const byte *R, const byte *pk,
                            const byte *msg, word32 msgLen,
                            const spx_params_t *p)
{
    int tree_height = p->h / p->d;
    int tree_bits   = tree_height * (p->d - 1);
    int tree_bytes  = (tree_bits + 7) / 8;
    int leaf_bits   = tree_height;
    int leaf_bytes  = (leaf_bits + 7) / 8;
    int fors_msg_bytes = (p->fors_k * p->fors_h + 7) / 8;
    int dgst_bytes  = fors_msg_bytes + tree_bytes + leaf_bytes;

    byte buf[64]; /* 64 bytes is enough for all variants */
    wc_Shake sh;
    int ret;
    word64 tree_mask, leaf_mask;

    if (dgst_bytes > (int)sizeof(buf)) return BUFFER_E;

    ret = wc_InitShake256(&sh, NULL, INVALID_DEVID);
    if (ret != 0) return ret;
    wc_Shake256_Update(&sh, R,   (word32)p->n);
    wc_Shake256_Update(&sh, pk,  (word32)(2 * p->n));
    wc_Shake256_Update(&sh, msg, msgLen);
    ret = wc_Shake256_Final(&sh, buf, (word32)dgst_bytes);
    wc_Shake256_Free(&sh);
    if (ret != 0) return ret;

    XMEMCPY(fors_msg, buf, fors_msg_bytes);

    *tree = spx_bytes_to_u64(buf + fors_msg_bytes, tree_bytes);
    tree_mask = (tree_bits < 64) ? (((word64)1 << tree_bits) - 1) : (~(word64)0);
    *tree &= tree_mask;

    *leaf_idx = (word32)spx_bytes_to_u64(buf + fors_msg_bytes + tree_bytes, leaf_bytes);
    leaf_mask = (leaf_bits < 32) ? (((word32)1 << leaf_bits) - 1) : ~(word32)0;
    *leaf_idx &= leaf_mask;

    return 0;
}

/* ------------------------------------------------------------------ */
/* WOTS+ functions                                                     */
/* ------------------------------------------------------------------ */

/* base_w: interpret `input` as 4-bit (w=16) chunks, MSB first within byte */
static void spx_base_w(word32 *out, int out_len, const byte *input) {
    int bits = 0, in = 0, consumed;
    byte total = 0;
    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) { total = input[in++]; bits = 8; }
        bits -= WOTS_LOGW;
        out[consumed] = (total >> bits) & (WOTS_W - 1);
    }
}

/* gen_chain: apply thash `steps` times starting at position `start` */
static int spx_gen_chain(byte *out, const byte *in, int start, int steps,
                         const byte *pk_seed, int n, spx_addr_t addr)
{
    int i, ret;
    XMEMCPY(out, in, (size_t)n);
    for (i = start; i < start + steps && i < WOTS_W; i++) {
        spx_set_hash(addr, (word32)i);
        ret = spx_thash(out, out, 1, pk_seed, n, addr);
        if (ret != 0) return ret;
    }
    return 0;
}

/* chain_lengths: derive per-coefficient chain positions from n-byte message */
static void spx_chain_lengths(word32 *lengths, const byte *msg, int n) {
    int i;
    unsigned int csum = 0;
    byte csum_bytes[2]; /* ceil(len2*logw/8) = ceil(3*4/8) = 2 bytes */
    word32 csum_w[3];
    int len1 = 2 * n;  /* number of base_w message coefficients */

    spx_base_w(lengths, len1, msg);

    for (i = 0; i < len1; i++)
        csum += (WOTS_W - 1) - lengths[i];

    /* Shift: (8 - (len2*logw % 8)) % 8 = (8 - 12%8) % 8 = 4 */
    csum <<= 4;
    /* Store big-endian in 2 bytes */
    csum_bytes[0] = (byte)(csum >> 8);
    csum_bytes[1] = (byte)(csum);
    spx_base_w(csum_w, 3, csum_bytes);

    lengths[len1 + 0] = csum_w[0];
    lengths[len1 + 1] = csum_w[1];
    lengths[len1 + 2] = csum_w[2];
}

/* wots_pk_from_sig: compute WOTS+ public key from signature and message */
static int spx_wots_pk_from_sig(byte *pk, const byte *sig, const byte *msg,
                                 const byte *pk_seed, int n, int wots_len,
                                 spx_addr_t addr)
{
    word32 *lengths = (word32 *)XMALLOC((size_t)(wots_len * sizeof(word32)),
                                         NULL, DYNAMIC_TYPE_TMP_BUFFER);
    int i, ret = 0;
    if (lengths == NULL) return MEMORY_E;

    spx_chain_lengths(lengths, msg, n);

    for (i = 0; i < wots_len; i++) {
        spx_set_chain(addr, (word32)i);
        ret = spx_gen_chain(pk + i * n, sig + i * n,
                            (int)lengths[i], WOTS_W - 1 - (int)lengths[i],
                            pk_seed, n, addr);
        if (ret != 0) break;
    }

    XFREE(lengths, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* ------------------------------------------------------------------ */
/* compute_root: walk Merkle auth path to derive tree root             */
/* leaf_idx: leaf index within this subtree (0-based)                 */
/* idx_offset: base index of this subtree within its layer            */
/* ------------------------------------------------------------------ */

static int spx_compute_root(byte *root, const byte *leaf,
                             word32 leaf_idx, word32 idx_offset,
                             const byte *auth_path, int tree_height,
                             const byte *pk_seed, int n,
                             spx_addr_t addr)
{
    int i, ret;
    byte buffer[64]; /* 2 * n, max n=32 → 64 bytes */

    if (leaf_idx & 1) {
        XMEMCPY(buffer + n, leaf, (size_t)n);
        XMEMCPY(buffer,     auth_path, (size_t)n);
    } else {
        XMEMCPY(buffer,     leaf, (size_t)n);
        XMEMCPY(buffer + n, auth_path, (size_t)n);
    }
    auth_path += n;

    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx   >>= 1;
        idx_offset >>= 1;
        spx_set_tree_height(addr, (word32)(i + 1));
        spx_set_tree_index(addr, leaf_idx + idx_offset);

        if (leaf_idx & 1) {
            ret = spx_thash(buffer + n, buffer, 2, pk_seed, n, addr);
            if (ret != 0) return ret;
            XMEMCPY(buffer, auth_path, (size_t)n);
        } else {
            ret = spx_thash(buffer, buffer, 2, pk_seed, n, addr);
            if (ret != 0) return ret;
            XMEMCPY(buffer + n, auth_path, (size_t)n);
        }
        auth_path += n;
    }

    leaf_idx   >>= 1;
    idx_offset >>= 1;
    spx_set_tree_height(addr, (word32)tree_height);
    spx_set_tree_index(addr, leaf_idx + idx_offset);
    return spx_thash(root, buffer, 2, pk_seed, n, addr);
}

/* ------------------------------------------------------------------ */
/* FORS: pk from signature                                             */
/* ------------------------------------------------------------------ */

/* message_to_indices: extract k a-bit indices from fors_msg (LSB first) */
static void spx_message_to_indices(word32 *indices, const byte *m,
                                   int k, int a)
{
    int i, j, offset = 0;
    for (i = 0; i < k; i++) {
        indices[i] = 0;
        for (j = 0; j < a; j++) {
            indices[i] ^= (word32)(((m[offset >> 3] >> (offset & 7)) & 1) << j);
            offset++;
        }
    }
}

static int spx_fors_pk_from_sig(byte *pk, const byte *sig,
                                 const byte *fors_msg,
                                 const byte *pk_seed, int n,
                                 const spx_params_t *p,
                                 spx_addr_t fors_addr)
{
    int i, ret = 0;
    word32 idx_offset;
    byte leaf[32]; /* n ≤ 32 */

    word32 *indices = (word32 *)XMALLOC((size_t)(p->fors_k * sizeof(word32)),
                                         NULL, DYNAMIC_TYPE_TMP_BUFFER);
    byte   *roots   = (byte *)XMALLOC((size_t)(p->fors_k * n),
                                       NULL, DYNAMIC_TYPE_TMP_BUFFER);
    spx_addr_t fors_tree_addr;
    spx_addr_t fors_pk_addr;

    if (indices == NULL || roots == NULL) {
        XFREE(indices, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(roots,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    XMEMSET(fors_tree_addr, 0, sizeof(fors_tree_addr));
    XMEMSET(fors_pk_addr,   0, sizeof(fors_pk_addr));
    spx_copy_keypair(fors_tree_addr, fors_addr);
    spx_copy_keypair(fors_pk_addr,   fors_addr);
    spx_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    spx_set_type(fors_pk_addr,   SPX_ADDR_TYPE_FORSPK);

    spx_message_to_indices(indices, fors_msg, p->fors_k, p->fors_h);

    for (i = 0; i < p->fors_k && ret == 0; i++) {
        idx_offset = (word32)(i * (1 << p->fors_h));

        spx_set_tree_height(fors_tree_addr, 0);
        spx_set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Hash secret to get leaf */
        ret = spx_thash(leaf, sig, 1, pk_seed, n, fors_tree_addr);
        sig += n;
        if (ret != 0) break;

        /* Walk auth path to get FORS tree root */
        ret = spx_compute_root(roots + i * n, leaf, indices[i], idx_offset,
                               sig, p->fors_h, pk_seed, n, fors_tree_addr);
        sig += n * p->fors_h;
        SPX_YIELD();  /* allow LwIP to drain ETH DMA RX between FORS trees */
    }

    if (ret == 0) {
        /* Hash all k roots to get FORS PK */
        ret = spx_thash(pk, roots, p->fors_k, pk_seed, n, fors_pk_addr);
    }

    XFREE(indices, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(roots,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Top-level SPHINCS+ SHAKE simple verification                       */
/* ------------------------------------------------------------------ */

static int spx_shake_verify(const byte *sig, word32 sigLen,
                            const byte *msg, word32 msgLen,
                            const byte *pk,  word32 pkLen,
                            const spx_params_t *p)
{
    int tree_height, ret = 0, i;
    word64 tree;
    word32 idx_leaf;
    const byte *pk_seed, *pk_root, *R, *fors_sig, *ht_sig;
    byte *fors_msg;
    byte root[32], leaf[32];  /* max n=32 */

    spx_addr_t wots_addr,  tree_addr, wots_pk_addr;
    byte       *wots_pk;

    if (sigLen != (word32)p->sig_bytes) return SIG_VERIFY_E;
    if (pkLen  != (word32)p->pk_bytes)  return SIG_VERIFY_E;

    pk_seed = pk;
    pk_root = pk + p->n;
    R       = sig;

    fors_msg = (byte *)XMALLOC((size_t)((p->fors_k * p->fors_h + 7) / 8),
                                NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wots_pk  = (byte *)XMALLOC((size_t)(p->wots_len * p->n),
                                NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (fors_msg == NULL || wots_pk == NULL) {
        XFREE(fors_msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(wots_pk,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    /* Hash message → fors_msg, tree, leaf_idx */
    ret = spx_hash_message(fors_msg, &tree, &idx_leaf,
                           R, pk, msg, msgLen, p);
    if (ret != 0) goto cleanup;

    sig += p->n;  /* skip R */

    /* Setup addresses */
    XMEMSET(wots_addr,    0, sizeof(wots_addr));
    XMEMSET(tree_addr,    0, sizeof(tree_addr));
    XMEMSET(wots_pk_addr, 0, sizeof(wots_pk_addr));
    spx_set_type(wots_addr,    SPX_ADDR_TYPE_WOTS);
    spx_set_type(tree_addr,    SPX_ADDR_TYPE_HASHTREE);
    spx_set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Copy initial tree/keypair to wots_addr for FORS PK computation */
    spx_set_tree(wots_addr, tree);
    spx_set_keypair(wots_addr, idx_leaf);

    /* FORS: compute PK from signature */
    fors_sig = sig;
    ret = spx_fors_pk_from_sig(root, fors_sig, fors_msg,
                               pk_seed, p->n, p, wots_addr);
    if (ret != 0) goto cleanup;

    sig += (size_t)(p->fors_k * (1 + p->fors_h) * p->n);

    /* HT verify: d layers of XMSS */
    tree_height = p->h / p->d;
    ht_sig = sig;

    for (i = 0; i < p->d && ret == 0; i++) {
        spx_set_layer(tree_addr, (word32)i);
        spx_set_tree(tree_addr, tree);

        spx_copy_subtree(wots_addr, tree_addr);
        spx_set_keypair(wots_addr, idx_leaf);
        spx_copy_keypair(wots_pk_addr, wots_addr);

        /* Compute WOTS+ PK from signature */
        ret = spx_wots_pk_from_sig(wots_pk, ht_sig, root,
                                   pk_seed, p->n, p->wots_len, wots_addr);
        ht_sig += p->wots_len * p->n;
        if (ret != 0) break;

        /* Compress WOTS+ PK to tree leaf */
        ret = spx_thash(leaf, wots_pk, p->wots_len,
                        pk_seed, p->n, wots_pk_addr);
        if (ret != 0) break;

        /* Walk auth path to get this layer's root */
        ret = spx_compute_root(root, leaf, idx_leaf, 0,
                               ht_sig, tree_height,
                               pk_seed, p->n, tree_addr);
        ht_sig += tree_height * p->n;

        /* Next layer: leaf is current tree's index in parent tree */
        idx_leaf = (word32)(tree & (word32)((1 << tree_height) - 1));
        tree   >>= (word64)tree_height;
        SPX_YIELD();  /* allow LwIP to process TCP packets between HT layers */
    }

    if (ret == 0) {
        if (XMEMCMP(root, pk_root, (size_t)p->n) != 0)
            ret = SIG_VERIFY_E;
    }

cleanup:
    XFREE(fors_msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(wots_pk,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* ------------------------------------------------------------------ */
/* wolfSSL API implementation                                          */
/* ------------------------------------------------------------------ */

int wc_sphincs_init(sphincs_key *key) {
    if (key == NULL) return BAD_FUNC_ARG;
    XMEMSET(key, 0, sizeof(*key));
    return 0;
}

void wc_sphincs_free(sphincs_key *key) {
    if (key == NULL) return;
    ForceZero(key, sizeof(*key));
}

int wc_sphincs_set_level_and_optim(sphincs_key *key, byte level, byte optim) {
    if (key == NULL) return BAD_FUNC_ARG;
    if (level != 1 && level != 3 && level != 5) return BAD_FUNC_ARG;
    if (optim != FAST_VARIANT && optim != SMALL_VARIANT) return BAD_FUNC_ARG;
    key->level = level;
    key->optim = optim;
    return 0;
}

int wc_sphincs_get_level_and_optim(sphincs_key *key, byte *level, byte *optim) {
    if (key == NULL || level == NULL || optim == NULL) return BAD_FUNC_ARG;
    *level = key->level;
    *optim = key->optim;
    return 0;
}

static const spx_params_t *spx_get_params(const sphincs_key *key) {
    int idx = spx_variant_index(key->level, key->optim);
    if (idx < 0 || idx >= 6) return NULL;
    return &spx_table[idx];
}

int wc_sphincs_import_public(const byte *in, word32 inLen, sphincs_key *key) {
    const spx_params_t *p;
    if (in == NULL || key == NULL) return BAD_FUNC_ARG;
    p = spx_get_params(key);
    if (p == NULL) return BAD_FUNC_ARG;
    if (inLen < (word32)p->pk_bytes) return BUFFER_E;
    XMEMCPY(key->p, in, (size_t)p->pk_bytes);
    key->pubKeySet = 1;
    return 0;
}

int wc_Sphincs_PublicKeyDecode(const byte *input, word32 *inOutIdx,
                               sphincs_key *key, word32 inSz)
{
    const spx_params_t *p;
    word32 idx;
    int ret;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    p = spx_get_params(key);
    if (p == NULL) return BAD_FUNC_ARG;

    idx = *inOutIdx;

    /* Try raw public key (2*n bytes) */
    if (inSz - idx >= (word32)p->pk_bytes) {
        ret = wc_sphincs_import_public(input + idx, inSz - idx, key);
        if (ret == 0) {
            *inOutIdx = idx + (word32)p->pk_bytes;
            return 0;
        }
    }

    /* Try DER BIT STRING: skip leading 0x00 unused-bits byte */
    if (idx < inSz && input[idx] == 0x00) {
        idx++;
        if (inSz - idx >= (word32)p->pk_bytes) {
            ret = wc_sphincs_import_public(input + idx, inSz - idx, key);
            if (ret == 0) {
                *inOutIdx = idx + (word32)p->pk_bytes;
                return 0;
            }
        }
    }

    return ASN_PARSE_E;
}

int wc_sphincs_check_key(sphincs_key *key) {
    if (key == NULL) return BAD_FUNC_ARG;
    if (!key->pubKeySet) return BAD_FUNC_ARG;
    return 0;
}

int wc_sphincs_pub_size(sphincs_key *key) {
    const spx_params_t *p;
    if (key == NULL) return BAD_FUNC_ARG;
    p = spx_get_params(key);
    if (p == NULL) return BAD_FUNC_ARG;
    return p->pk_bytes;
}

int wc_sphincs_size(sphincs_key *key) {
    return wc_sphincs_pub_size(key);
}

int wc_sphincs_sig_size(sphincs_key *key) {
    const spx_params_t *p;
    if (key == NULL) return BAD_FUNC_ARG;
    p = spx_get_params(key);
    if (p == NULL) return BAD_FUNC_ARG;
    return p->sig_bytes;
}

int wc_sphincs_priv_size(sphincs_key *key) {
    (void)key;
    return NOT_COMPILED_IN;
}

/* ------------------------------------------------------------------ */
/* Core verify function                                                */
/* ------------------------------------------------------------------ */

int wc_sphincs_verify_msg(const byte *sig, word32 sigLen,
                          const byte *msg, word32 msgLen,
                          int *res, sphincs_key *key)
{
    const spx_params_t *p;
    int ret;

    *res = 0;
    if (sig == NULL || msg == NULL || res == NULL || key == NULL)
        return BAD_FUNC_ARG;
    if (!key->pubKeySet)
        return BAD_FUNC_ARG;

    p = spx_get_params(key);
    if (p == NULL) return BAD_FUNC_ARG;

    ret = spx_shake_verify(sig, sigLen, msg, msgLen,
                           key->p, (word32)p->pk_bytes, p);
    if (ret == 0) *res = 1;
    else if (ret == SIG_VERIFY_E) { *res = 0; ret = 0; }

    return ret;
}

/* ------------------------------------------------------------------ */
/* Signing / private key — not implemented                             */
/* ------------------------------------------------------------------ */

int wc_sphincs_sign_msg(const byte *in, word32 inLen, byte *out, word32 *outLen,
                        sphincs_key *key, WC_RNG *rng) {
    (void)in; (void)inLen; (void)out; (void)outLen; (void)key; (void)rng;
    return NOT_COMPILED_IN;
}

int wc_sphincs_import_private_only(const byte *priv, word32 privSz,
                                   sphincs_key *key) {
    (void)priv; (void)privSz; (void)key;
    return NOT_COMPILED_IN;
}

int wc_sphincs_import_private_key(const byte *priv, word32 privSz,
                                  const byte *pub, word32 pubSz,
                                  sphincs_key *key) {
    (void)priv; (void)privSz; (void)pub; (void)pubSz; (void)key;
    return NOT_COMPILED_IN;
}

int wc_sphincs_export_public(sphincs_key *key, byte *out, word32 *outLen) {
    const spx_params_t *p;
    if (key == NULL || out == NULL || outLen == NULL) return BAD_FUNC_ARG;
    if (!key->pubKeySet) return BAD_FUNC_ARG;
    p = spx_get_params(key);
    if (p == NULL) return BAD_FUNC_ARG;
    if (*outLen < (word32)p->pk_bytes) { *outLen = (word32)p->pk_bytes; return BUFFER_E; }
    XMEMCPY(out, key->p, (size_t)p->pk_bytes);
    *outLen = (word32)p->pk_bytes;
    return 0;
}

int wc_sphincs_export_private_only(sphincs_key *key, byte *out, word32 *outLen) {
    (void)key; (void)out; (void)outLen; return NOT_COMPILED_IN;
}
int wc_sphincs_export_private(sphincs_key *key, byte *out, word32 *outLen) {
    (void)key; (void)out; (void)outLen; return NOT_COMPILED_IN;
}
int wc_sphincs_export_key(sphincs_key *key, byte *priv, word32 *privSz,
                          byte *pub, word32 *pubSz) {
    (void)key; (void)priv; (void)privSz; (void)pub; (void)pubSz;
    return NOT_COMPILED_IN;
}

int wc_Sphincs_PrivateKeyDecode(const byte *input, word32 *inOutIdx,
                                sphincs_key *key, word32 inSz) {
    (void)input; (void)inOutIdx; (void)key; (void)inSz;
    return NOT_COMPILED_IN;
}
int wc_Sphincs_KeyToDer(sphincs_key *key, byte *output, word32 inLen) {
    (void)key; (void)output; (void)inLen; return NOT_COMPILED_IN;
}
int wc_Sphincs_PrivateKeyToDer(sphincs_key *key, byte *output, word32 inLen) {
    (void)key; (void)output; (void)inLen; return NOT_COMPILED_IN;
}
int wc_Sphincs_PublicKeyToDer(sphincs_key *key, byte *output, word32 inLen,
                              int withAlg) {
    (void)key; (void)output; (void)inLen; (void)withAlg;
    return NOT_COMPILED_IN;
}

#endif /* HAVE_SPHINCS */
