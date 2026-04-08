/**
 * cert_bench.c
 * Certificate benchmark task for STM32F439ZI
 *
 * Measures three things independently of TLS handshake:
 *  1. Cert chain TCP transmission time (raw bytes, not TLS)
 *  2. ECDSA signature verify time   (P-256 / P-384 / P-521)
 *  3. ML-DSA signature verify time  (ML-DSA44 / ML-DSA65 / ML-DSA87)
 *
 * Desktop counterpart: cert_data_server.py (port 12345)
 * Orchestration:       measure_cert_bench.sh
 *
 * UART output lines (parsed by measure_cert_bench.sh):
 *   [certbench] recv  name=<S>  size=<N>  time=<T> ms
 *   [certbench] ecdsa <curve>   keygen=<T> ms  sign=<T> ms  verify=<T> ms
 *   [certbench] mldsa <level>   keygen=<T> ms  sign=<T> ms  verify=<T> ms
 *   [certbench] DONE
 */

#include "cert_bench.h"
#include "tls_client.h"  /* TLS_SERVER_IP, TLS_SERVER_PORT */
#include "main.h"
#include "cmsis_os.h"

#include <stdio.h>
#include <string.h>

#include "lwip/sockets.h"
#include "lwip/netif.h"
#include "lwip/dhcp.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <math.h>

extern struct netif gnetif;

/* Access root CA certs embedded in tls_client.c */
void tls_get_scenario_ca(const char *name,
                          const char **ca,     unsigned int *ca_sz,
                          const char **ca_alt, unsigned int *ca_alt_sz);

/* ─── Configuration ────────────────────────────────────────────── */
#define CERT_DATA_PORT   12345   /* cert_data_server.py listens here */
#define N_ECDSA_VERIFY   100
#define N_ECDSA_SIGN     100
#define N_MLDSA_VERIFY   100
#define N_MLDSA_SIGN     100
#define N_CHAIN_VERIFY   10
#define RECV_TIMEOUT_SEC 10

/* ─── Statistics helper ─────────────────────────────────────────── */
static void compute_stats(const uint32_t *ms, int n,
                           float *mean, float *sd, float *ci95)
{
    float sum = 0.0f;
    for (int i = 0; i < n; i++) sum += (float)ms[i];
    *mean = sum / (float)n;
    float var = 0.0f;
    for (int i = 0; i < n; i++) {
        float d = (float)ms[i] - *mean;
        var += d * d;
    }
    *sd   = (n > 1) ? sqrtf(var / (float)(n - 1)) : 0.0f;
    *ci95 = 1.96f * (*sd) / sqrtf((float)n);
}

/* ─── Cert list for Phase 1 transmission timing ────────────────
 *  label : printed in output
 *  dl[3] : cert_data_server GET names to download (NULL = end)
 *
 *  For scenarios that send multiple chains (RELATED, DUAL) all
 *  named chains are downloaded sequentially and size/time are
 *  accumulated into a single result line.
 * ─────────────────────────────────────────────────────────────── */
typedef struct {
    const char *label;
    const char *dl[3];
} CertEntry;

static const CertEntry g_certs[] = {
    { "ECDSA_L1",     { "ECDSA_L1",    NULL,        NULL         } },
    { "ECDSA_L3",     { "ECDSA_L3",    NULL,        NULL         } },
    { "ECDSA_L5",     { "ECDSA_L5",    NULL,        NULL         } },
    { "MLDSA_L1",     { "MLDSA_L1",    NULL,        NULL         } },
    { "MLDSA_L3",     { "MLDSA_L3",    NULL,        NULL         } },
    { "MLDSA_L5",     { "MLDSA_L5",    NULL,        NULL         } },
    { "CHAMELEON_L1", { "CHAMELEON_L1",NULL,        NULL         } },
    { "CHAMELEON_L3", { "CHAMELEON_L3",NULL,        NULL         } },
    { "CHAMELEON_L5", { "CHAMELEON_L5",NULL,        NULL         } },
    { "CATALYST_L1",  { "CATALYST_L1", NULL,        NULL         } },
    { "CATALYST_L3",  { "CATALYST_L3", NULL,        NULL         } },
    { "CATALYST_L5",  { "CATALYST_L5", NULL,        NULL         } },
    { "COMPOSITE_L1", { "COMPOSITE_L1",NULL,        NULL         } },
    { "COMPOSITE_L3", { "COMPOSITE_L3",NULL,        NULL         } },
    { "COMPOSITE_L5", { "COMPOSITE_L5",NULL,        NULL         } },
    /* RELATED: ECDSA chain + MLDSA chain (4 certs total)
     *   ECDSA_Lx = [Server ECDSA Cert + ICA ECDSA Cert]
     *   MLDSA_Lx = [Server ML-DSA Cert(Related) + ICA ML-DSA Cert] */
    { "RELATED_L1",   { "ECDSA_L1",    "MLDSA_L1",  NULL         } },
    { "RELATED_L3",   { "ECDSA_L3",    "MLDSA_L3",  NULL         } },
    { "RELATED_L5",   { "ECDSA_L5",    "MLDSA_L5",  NULL         } },
    /* DUAL: ECDSA chain + MLDSA chain (4 certs total)
     *   ECDSA_Lx = [Server ECDSA Cert + ICA ECDSA Cert]
     *   MLDSA_Lx = [Server ML-DSA Cert + ICA ML-DSA Cert] */
    { "DUAL_L1",      { "ECDSA_L1",    "MLDSA_L1",  NULL         } },
    { "DUAL_L3",      { "ECDSA_L3",    "MLDSA_L3",  NULL         } },
    { "DUAL_L5",      { "ECDSA_L5",    "MLDSA_L5",  NULL         } },
};
#define CERT_COUNT  (sizeof(g_certs) / sizeof(g_certs[0]))

/* ================================================================
 * Phase 1: Cert transmission timing
 * ================================================================ */

/*
 * Download one named chain from cert_data_server.
 * Returns received byte count (0 on error).
 * *elapsed_ms is incremented by actual TCP receive time only.
 */
static uint32_t recv_one_chain(const char *name, struct sockaddr_in *addr,
                                uint32_t *elapsed_ms)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    struct timeval tv = { .tv_sec = RECV_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)addr, sizeof(*addr)) != 0) {
        close(fd); return 0;
    }

    char req[64];
    int rlen = snprintf(req, sizeof(req), "GET %s\n", name);
    send(fd, req, rlen, 0);

    uint8_t lenbuf[4];
    if (recv(fd, lenbuf, 4, MSG_WAITALL) != 4) { close(fd); return 0; }
    uint32_t total = ((uint32_t)lenbuf[0] << 24) | ((uint32_t)lenbuf[1] << 16)
                   | ((uint32_t)lenbuf[2] <<  8) |  (uint32_t)lenbuf[3];
    if (total == 0) { close(fd); return 0; }

    uint8_t *buf = (uint8_t *)pvPortMalloc(total);
    if (!buf) { close(fd); return 0; }

    uint32_t t0 = HAL_GetTick();
    uint32_t received = 0;
    while (received < total) {
        int n = recv(fd, buf + received, total - received, 0);
        if (n <= 0) break;
        received += (uint32_t)n;
    }
    *elapsed_ms += HAL_GetTick() - t0;

    vPortFree(buf);
    close(fd);
    return (received == total) ? total : 0;
}

static void phase_recv(void)
{
    printf("\n[certbench] === Phase 1: Cert Transmission Timing ===\n");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(CERT_DATA_PORT);
    inet_aton(TLS_SERVER_IP, &addr.sin_addr);

    for (size_t i = 0; i < CERT_COUNT; i++) {
        const CertEntry *e = &g_certs[i];
        uint32_t total_size = 0;
        uint32_t elapsed_ms = 0;
        int failed = 0;

        for (int k = 0; k < 3 && e->dl[k] != NULL; k++) {
            uint32_t sz = recv_one_chain(e->dl[k], &addr, &elapsed_ms);
            if (sz == 0) { failed = 1; break; }
            total_size += sz;
            osDelay(50);
        }

        if (failed)
            printf("[certbench] recv %-12s: download failed\n", e->label);
        else
            printf("[certbench] recv  name=%-12s  size=%-6lu  time=%lu ms\n",
                   e->label, (unsigned long)total_size, (unsigned long)elapsed_ms);

        osDelay(50);
    }
}

/* ================================================================
 * Phase 2: ECDSA benchmark
 * ================================================================ */
typedef struct {
    const char *name;
    int         key_sz;   /* bytes: 32/48/66 */
} EccCurve;

static const EccCurve g_ecc_curves[] = {
    { "p256", 32 },
    { "p384", 48 },
    { "p521", 66 },
};

static void bench_ecdsa_one(const EccCurve *c)
{
    ecc_key  key;
    WC_RNG   rng;
    byte     sig[150];
    word32   sigSz;
    byte     hash[32];
    int      res, ret;

    wc_InitRng(&rng);
    wc_ecc_init(&key);

    /* Key generation */
    uint32_t t0 = HAL_GetTick();
    ret = wc_ecc_make_key(&rng, c->key_sz, &key);
    uint32_t keygen_ms = HAL_GetTick() - t0;
    if (ret != 0) {
        printf("[certbench] ecdsa %s: keygen failed ret=%d\n", c->name, ret);
        goto cleanup;
    }

    /* Sign once to get a valid signature */
    memset(hash, 0xAB, sizeof(hash));
    sigSz = sizeof(sig);
    ret = wc_ecc_sign_hash(hash, 32, sig, &sigSz, &rng, &key);
    if (ret != 0) {
        printf("[certbench] ecdsa %s: sign failed ret=%d\n", c->name, ret);
        goto cleanup;
    }

    /* Sign N times — per-iteration timing */
    int sign_errors = 0;
    word32 last_sz = sigSz;
    uint32_t sign_ms[N_ECDSA_SIGN];
    for (int i = 0; i < N_ECDSA_SIGN; i++) {
        word32 sz = sizeof(sig);
        uint32_t ti = HAL_GetTick();
        ret = wc_ecc_sign_hash(hash, 32, sig, &sz, &rng, &key);
        sign_ms[i] = HAL_GetTick() - ti;
        if (ret != 0) sign_errors++;
        else last_sz = sz;
    }

    /* Verify N times — per-iteration timing */
    int verify_errors = 0;
    uint32_t verify_ms[N_ECDSA_VERIFY];
    for (int i = 0; i < N_ECDSA_VERIFY; i++) {
        uint32_t ti = HAL_GetTick();
        ret = wc_ecc_verify_hash(sig, last_sz, hash, 32, &res, &key);
        verify_ms[i] = HAL_GetTick() - ti;
        if (ret != 0 || res != 1) verify_errors++;
    }

    float sm, ss, sci, vm, vs, vci;
    compute_stats(sign_ms,   N_ECDSA_SIGN,   &sm, &ss, &sci);
    compute_stats(verify_ms, N_ECDSA_VERIFY, &vm, &vs, &vci);

    printf("[certbench] ecdsa %-4s  keygen=%4lu ms"
           "  sign=%6.2f sd=%.2f 95ci=%.2f ms (N=%d,err=%d)"
           "  verify=%6.2f sd=%.2f 95ci=%.2f ms (N=%d,err=%d)\n",
           c->name, (unsigned long)keygen_ms,
           sm, ss, sci, N_ECDSA_SIGN,   sign_errors,
           vm, vs, vci, N_ECDSA_VERIFY, verify_errors);

cleanup:
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
}

static void phase_ecdsa(void)
{
    printf("\n[certbench] === Phase 2: ECDSA Benchmark ===\n");
    for (size_t i = 0; i < sizeof(g_ecc_curves) / sizeof(g_ecc_curves[0]); i++) {
        bench_ecdsa_one(&g_ecc_curves[i]);
    }
}

/* ================================================================
 * Phase 3: ML-DSA benchmark
 * ================================================================ */
typedef struct {
    const char *name;
    int         level;    /* 2=ML-DSA-44, 3=ML-DSA-65, 5=ML-DSA-87 */
    word32      sig_size; /* max sig bytes */
} MlDsaLevel;

static const MlDsaLevel g_mldsa_levels[] = {
    { "44", 2, DILITHIUM_LEVEL2_SIG_SIZE },
    { "65", 3, DILITHIUM_LEVEL3_SIG_SIZE },
    { "87", 5, DILITHIUM_LEVEL5_SIG_SIZE },
};

static void bench_mldsa_one(const MlDsaLevel *lv)
{
    dilithium_key *key;
    WC_RNG         rng;
    byte          *sig;
    word32         sigSz, actualSz;
    byte           msg[32];
    int            ret, res;

    key = (dilithium_key *)pvPortMalloc(sizeof(dilithium_key));
    sig = (byte *)pvPortMalloc(lv->sig_size);
    if (!key || !sig) {
        printf("[certbench] mldsa %s: heap alloc failed\n", lv->name);
        vPortFree(key);
        vPortFree(sig);
        return;
    }

    wc_InitRng(&rng);
    wc_dilithium_init(key);
    wc_dilithium_set_level(key, (byte)lv->level);

    /* Key generation */
    uint32_t t0 = HAL_GetTick();
    ret = wc_dilithium_make_key(key, &rng);
    uint32_t keygen_ms = HAL_GetTick() - t0;
    if (ret != 0) {
        printf("[certbench] mldsa %s: keygen failed ret=%d\n", lv->name, ret);
        goto cleanup;
    }

    /* Sign once to get valid signature */
    memset(msg, 0xCD, sizeof(msg));
    actualSz = lv->sig_size;
    ret = wc_dilithium_sign_msg(msg, sizeof(msg), sig, &actualSz, key, &rng);
    if (ret != 0) {
        printf("[certbench] mldsa %s: initial sign failed ret=%d\n", lv->name, ret);
        goto cleanup;
    }
    sigSz = actualSz;

    /* Sign N times — per-iteration timing */
    int sign_errors = 0;
    uint32_t *sign_ms = (uint32_t *)pvPortMalloc(N_MLDSA_SIGN * sizeof(uint32_t));
    if (!sign_ms) {
        printf("[certbench] mldsa %s: heap alloc failed (sign_ms)\n", lv->name);
        goto cleanup;
    }
    for (int i = 0; i < N_MLDSA_SIGN; i++) {
        actualSz = lv->sig_size;
        uint32_t ti = HAL_GetTick();
        ret = wc_dilithium_sign_msg(msg, sizeof(msg), sig, &actualSz, key, &rng);
        sign_ms[i] = HAL_GetTick() - ti;
        if (ret != 0) sign_errors++;
    }

    /* Verify N times — per-iteration timing */
    int verify_errors = 0;
    uint32_t *verify_ms = (uint32_t *)pvPortMalloc(N_MLDSA_VERIFY * sizeof(uint32_t));
    if (!verify_ms) {
        printf("[certbench] mldsa %s: heap alloc failed (verify_ms)\n", lv->name);
        vPortFree(sign_ms);
        goto cleanup;
    }
    for (int i = 0; i < N_MLDSA_VERIFY; i++) {
        uint32_t ti = HAL_GetTick();
        ret = wc_dilithium_verify_msg(sig, sigSz, msg, sizeof(msg), &res, key);
        verify_ms[i] = HAL_GetTick() - ti;
        if (ret != 0 || res != 1) verify_errors++;
    }

    float sm, ss, sci, vm, vs, vci;
    compute_stats(sign_ms,   N_MLDSA_SIGN,   &sm, &ss, &sci);
    compute_stats(verify_ms, N_MLDSA_VERIFY, &vm, &vs, &vci);
    vPortFree(sign_ms);
    vPortFree(verify_ms);

    printf("[certbench] mldsa %-2s  keygen=%5lu ms"
           "  sign=%7.2f sd=%.2f 95ci=%.2f ms (N=%d,err=%d)"
           "  verify=%7.2f sd=%.2f 95ci=%.2f ms (N=%d,err=%d)\n",
           lv->name, (unsigned long)keygen_ms,
           sm, ss, sci, N_MLDSA_SIGN,   sign_errors,
           vm, vs, vci, N_MLDSA_VERIFY, verify_errors);

cleanup:
    wc_dilithium_free(key);
    vPortFree(key);
    vPortFree(sig);
    wc_FreeRng(&rng);
}

static void phase_mldsa(void)
{
    printf("\n[certbench] === Phase 3: ML-DSA Benchmark ===\n");
    for (size_t i = 0; i < sizeof(g_mldsa_levels) / sizeof(g_mldsa_levels[0]); i++) {
        bench_mldsa_one(&g_mldsa_levels[i]);
    }
}

/* ================================================================
 * Phase 4: Full Certificate Chain Verification Timing
 *
 * Performs step-by-step chain validation (root CA → each intermediate → leaf)
 * using wolfSSL CertManager.  For dual-chain scenarios (CHAMELEON, RELATED)
 * both trust paths are verified and timed together.
 *
 * Scenario kinds:
 *   KIND_STD   – 2-cert PEM chain (ECDSA, MLDSA, CATALYST)
 *   KIND_CHAM  – 3-cert PEM: leaf + ECDSA ICA + PQ ICA (CHAMELEON)
 *               Chain A: Classic Root CA → Classic ICA → leaf (ECDSA)
 *               Chain B: PQ Root CA → PQ ICA (ML-DSA)
 *               Chain C: DCD ML-DSA sig (leaf DCD extension parsed,
 *                        Delta TBS reconstructed, verified with PQ ICA key)
 *   KIND_COMP  – 2-cert DER chain (COMPOSITE)
 *   KIND_REL   – ECDSA chain + MLDSA chain (RELATED)
 *   KIND_DUAL  – ECDSA chain + MLDSA chain (DUAL)
 * ================================================================ */

/* ================================================================
 * Chameleon DCD (Delta Certificate Descriptor) ML-DSA verification
 *
 * DCD extension OID: 2.16.840.1.114027.80.6.1
 * DCD SEQUENCE fields:
 *   0x02       INTEGER  – delta serial (tag+len+value)
 *   0xa0 [0]   sigAlgId content (AlgorithmIdentifier SEQUENCE)
 *   0xa1 [1]   issuer Name content
 *   0xa2 [2]   validity content
 *   0xa3 [3]   subject Name content
 *   0x30       SEQUENCE – SubjectPublicKeyInfo (delta cert's ML-DSA SPKI)
 *   0xa4 [4]   extensions content (optional)
 *   0x03       BIT STRING – ML-DSA signature over Delta TBSCertificate
 * ================================================================ */

/* DCD extension OID TLV: 2.16.840.1.114027.80.6.1 */
static const uint8_t kDcdOid[] = {
    0x06, 0x0a,
    0x60, 0x86, 0x48, 0x01, 0x86, 0xfa, 0x6b, 0x50, 0x06, 0x01
};

/* Decode DER length at data[*ppos], advance *ppos */
static uint32_t bench_asn_len(const uint8_t *data, uint32_t *ppos)
{
    uint8_t b = data[(*ppos)++];
    if (!(b & 0x80)) return b;
    int ll = b & 0x7F;
    uint32_t len = 0;
    while (ll--) len = (len << 8) | data[(*ppos)++];
    return len;
}

/* Write DER length at out[], return bytes written */
static int bench_write_len(uint8_t *out, uint32_t len)
{
    if (len < 128) {
        out[0] = (uint8_t)len;
        return 1;
    } else if (len < 256) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    } else {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)(len & 0xFF);
        return 3;
    }
}

/*
 * Extract raw public key bytes from SubjectPublicKeyInfo DER.
 * SPKI: SEQUENCE { SEQUENCE{AlgId} BIT STRING{0x00 + raw_key} }
 * Sets *key_ptr (pointer into spki buffer) and *key_sz.
 * Returns 0 on success.
 */
static int bench_spki_raw_key(const uint8_t *spki, uint32_t spki_sz,
                               const uint8_t **key_ptr, uint32_t *key_sz)
{
    uint32_t pos = 0;
    if (pos >= spki_sz || spki[pos] != 0x30) return -1;
    pos++;
    bench_asn_len(spki, &pos);          /* skip outer SEQUENCE length */
    if (pos >= spki_sz || spki[pos] != 0x30) return -1;
    pos++;
    uint32_t alg_len = bench_asn_len(spki, &pos);
    pos += alg_len;                     /* skip AlgorithmIdentifier content */
    if (pos >= spki_sz || spki[pos] != 0x03) return -1;
    pos++;
    uint32_t bs_len = bench_asn_len(spki, &pos);
    if (bs_len < 2) return -1;
    pos++;                              /* skip 0x00 unused-bits byte */
    bs_len--;
    *key_ptr = spki + pos;
    *key_sz  = bs_len;
    return 0;
}

/*
 * Chameleon DCD verification context.
 * Prepared once before the timing loop; freed after.
 * leaf_der is kept allocated because sig points into it.
 */
typedef struct {
    dilithium_key *dkey;       /* PQ ICA ML-DSA public key (imported)    */
    uint8_t       *tbs;        /* Reconstructed Delta TBSCertificate      */
    uint32_t       tbs_len;
    const uint8_t *sig;        /* ML-DSA signature bytes (in leaf_der)    */
    uint32_t       sig_len;
    uint8_t       *leaf_der;   /* leaf cert DER (kept for sig pointer)    */
    int            ok;          /* 1 if prepared successfully              */
} ChamDcdCtx;

static void cham_dcd_free(ChamDcdCtx *ctx)
{
    if (!ctx) return;
    if (ctx->dkey) {
        wc_dilithium_free(ctx->dkey);
        vPortFree(ctx->dkey);
        ctx->dkey = NULL;
    }
    if (ctx->tbs)      { vPortFree(ctx->tbs);      ctx->tbs      = NULL; }
    if (ctx->leaf_der) { vPortFree(ctx->leaf_der);  ctx->leaf_der = NULL; }
    ctx->ok = 0;
}

/*
 * Prepare ChamDcdCtx:
 *   1. Convert leaf PEM to DER, scan for DCD OID
 *   2. Parse DCD fields, reconstruct Delta TBSCertificate
 *   3. Convert PQ ICA PEM to DER, extract SPKI, import ML-DSA public key
 *
 * leaf_pem/leaf_pem_sz : Chameleon leaf cert PEM (cert[0] = p1[0])
 * pq_ica_pem/pq_ica_sz : PQ ICA cert PEM         (cert[2] = p1[2])
 * mldsa_level          : 2 (mldsa44), 3 (mldsa65), or 5 (mldsa87)
 */
static int cham_dcd_prep(ChamDcdCtx *ctx,
                          const uint8_t *leaf_pem, uint32_t leaf_pem_sz,
                          const uint8_t *pq_ica_pem, uint32_t pq_ica_sz,
                          int mldsa_level)
{
    memset(ctx, 0, sizeof(*ctx));

    const uint32_t LEAF_DER_MAX = 8192;
    const uint32_t ICA_DER_MAX  = 10240;  /* ML-DSA-87 ICA DER ~8 KB */
    const uint32_t TBS_MAX      = 4096;

    ctx->leaf_der = (uint8_t *)pvPortMalloc(LEAF_DER_MAX);
    ctx->tbs      = (uint8_t *)pvPortMalloc(TBS_MAX);
    ctx->dkey     = (dilithium_key *)pvPortMalloc(sizeof(dilithium_key));
    if (!ctx->leaf_der || !ctx->tbs || !ctx->dkey) {
        printf("[certbench] cham_dcd_prep: heap alloc failed\n");
        cham_dcd_free(ctx); return -1;
    }

    /* Step 1: Leaf PEM → DER */
    int leaf_der_sz = wc_CertPemToDer(leaf_pem, (int)leaf_pem_sz,
                                       ctx->leaf_der, (int)LEAF_DER_MAX,
                                       CERT_TYPE);
    if (leaf_der_sz <= 0) {
        printf("[certbench] cham_dcd_prep: leaf PEM→DER err=%d\n", leaf_der_sz);
        cham_dcd_free(ctx); return -1;
    }

    /* Step 2: Find DCD OID in leaf DER */
    const uint8_t *found = NULL;
    for (uint32_t si = 0;
         si + (uint32_t)sizeof(kDcdOid) <= (uint32_t)leaf_der_sz; si++) {
        if (memcmp(ctx->leaf_der + si, kDcdOid, sizeof(kDcdOid)) == 0) {
            found = ctx->leaf_der + si + sizeof(kDcdOid);
            break;
        }
    }
    if (!found) {
        printf("[certbench] cham_dcd_prep: DCD OID not found\n");
        cham_dcd_free(ctx); return -1;
    }

    /* After OID: OCTET STRING { SEQUENCE { DCD content } } */
    const uint8_t *p = found;
    if (*p != 0x04) {
        printf("[certbench] cham_dcd_prep: expected OCTET STRING (0x04) got 0x%02x\n", *p);
        cham_dcd_free(ctx); return -1;
    }
    uint32_t pos = 1;
    bench_asn_len(p, &pos);   /* skip OCTET STRING length */
    p += pos;                  /* p → DCD SEQUENCE */
    if (*p != 0x30) {
        printf("[certbench] cham_dcd_prep: expected DCD SEQUENCE (0x30) got 0x%02x\n", *p);
        cham_dcd_free(ctx); return -1;
    }
    p++; pos = 0;
    uint32_t dcd_len = bench_asn_len(p, &pos);
    p += pos;
    const uint8_t *dcdContent    = p;
    uint32_t       dcdContentLen = dcd_len;

    /* Step 3: Parse DCD fields */
    const uint8_t *serial_start    = NULL; uint32_t serial_total    = 0;
    const uint8_t *sigalg_content  = NULL; uint32_t sigalg_len      = 0;
    const uint8_t *issuer_content  = NULL; uint32_t issuer_len      = 0;
    const uint8_t *validity_content= NULL; uint32_t validity_len    = 0;
    const uint8_t *subject_content = NULL; uint32_t subject_len     = 0;
    const uint8_t *spki_start      = NULL; uint32_t spki_total      = 0;
    const uint8_t *ext_content     = NULL; uint32_t ext_len         = 0;
    const uint8_t *sigval_content  = NULL; uint32_t sigval_len      = 0;
    int spki_seen = 0;

    uint32_t fp = 0;
    while (fp < dcdContentLen) {
        const uint8_t *fStart   = dcdContent + fp;
        uint8_t        ftag     = dcdContent[fp++];
        uint32_t       flen     = bench_asn_len(dcdContent, &fp);
        const uint8_t *fcontent = dcdContent + fp;

        switch (ftag) {
            case 0x02: /* INTEGER – delta serial (incl. tag+len) */
                serial_start = fStart;
                serial_total = (uint32_t)(fcontent + flen - fStart);
                break;
            case 0xa0: sigalg_content  = fcontent; sigalg_len    = flen; break;
            case 0xa1: issuer_content  = fcontent; issuer_len    = flen; break;
            case 0xa2: validity_content= fcontent; validity_len  = flen; break;
            case 0xa3: subject_content = fcontent; subject_len   = flen; break;
            case 0x30: /* first SEQUENCE = SubjectPublicKeyInfo */
                if (!spki_seen) {
                    spki_start = fStart;
                    spki_total = (uint32_t)(fcontent + flen - fStart);
                    spki_seen  = 1;
                }
                break;
            case 0xa4: ext_content     = fcontent; ext_len       = flen; break;
            case 0x03: sigval_content  = fcontent; sigval_len    = flen; break;
            default: break;
        }
        fp += flen;
    }

    if (!sigval_content || !spki_start || !issuer_content || !serial_start) {
        printf("[certbench] cham_dcd_prep: DCD missing required fields\n");
        cham_dcd_free(ctx); return -1;
    }
    if (sigval_len < 2) {
        printf("[certbench] cham_dcd_prep: DCD sig too short (%lu)\n",
               (unsigned long)sigval_len);
        cham_dcd_free(ctx); return -1;
    }

    /* Store sig (into leaf_der – kept allocated) */
    ctx->sig     = sigval_content + 1;   /* skip 0x00 unused-bits byte */
    ctx->sig_len = sigval_len - 1;

    /* Step 4: Reconstruct Delta TBSCertificate */
    static const uint8_t kVersionV3[] = {0xa0, 0x03, 0x02, 0x01, 0x02};
    uint32_t ext_wrap_sz = 0;
    if (ext_content && ext_len > 0) {
        int lsz = ext_len < 128 ? 1 : ext_len < 256 ? 2 : 3;
        ext_wrap_sz = 1u + (uint32_t)lsz + ext_len;
    }
    uint32_t tbs_content_sz =
        (uint32_t)sizeof(kVersionV3) + serial_total  + sigalg_len
        + issuer_len + validity_len   + subject_len   + spki_total + ext_wrap_sz;
    int      hdr_sz   = 1 + (tbs_content_sz < 128 ? 1 : tbs_content_sz < 256 ? 2 : 3);
    uint32_t tbs_total = (uint32_t)hdr_sz + tbs_content_sz;

    if (tbs_total > TBS_MAX) {
        printf("[certbench] cham_dcd_prep: TBS too large (%lu)\n",
               (unsigned long)tbs_total);
        cham_dcd_free(ctx); return -1;
    }

    uint32_t i = 0;
    ctx->tbs[i++] = 0x30;
    i += (uint32_t)bench_write_len(ctx->tbs + i, tbs_content_sz);
    memcpy(ctx->tbs + i, kVersionV3, sizeof(kVersionV3));  i += sizeof(kVersionV3);
    memcpy(ctx->tbs + i, serial_start, serial_total);       i += serial_total;
    memcpy(ctx->tbs + i, sigalg_content, sigalg_len);       i += sigalg_len;
    memcpy(ctx->tbs + i, issuer_content, issuer_len);       i += issuer_len;
    if (validity_content && validity_len > 0) {
        memcpy(ctx->tbs + i, validity_content, validity_len); i += validity_len;
    }
    if (subject_content && subject_len > 0) {
        memcpy(ctx->tbs + i, subject_content, subject_len); i += subject_len;
    }
    memcpy(ctx->tbs + i, spki_start, spki_total); i += spki_total;
    if (ext_content && ext_len > 0) {
        ctx->tbs[i++] = 0xa3;
        i += (uint32_t)bench_write_len(ctx->tbs + i, ext_len);
        memcpy(ctx->tbs + i, ext_content, ext_len); i += ext_len;
    }
    ctx->tbs_len = i;

    /* Step 5: PQ ICA PEM → DER → SPKI → raw key → import dilithium_key */
    uint8_t *ica_der  = (uint8_t *)pvPortMalloc(ICA_DER_MAX);
    uint8_t *spki_buf = (uint8_t *)pvPortMalloc(3072);  /* ML-DSA-87 SPKI ~2622 B */
    if (!ica_der || !spki_buf) {
        printf("[certbench] cham_dcd_prep: heap alloc failed (ica/spki)\n");
        vPortFree(ica_der); vPortFree(spki_buf);
        cham_dcd_free(ctx); return -1;
    }

    int ica_der_sz = wc_CertPemToDer(pq_ica_pem, (int)pq_ica_sz,
                                      ica_der, (int)ICA_DER_MAX, CERT_TYPE);
    if (ica_der_sz <= 0) {
        printf("[certbench] cham_dcd_prep: PQ ICA PEM→DER err=%d\n", ica_der_sz);
        vPortFree(ica_der); vPortFree(spki_buf);
        cham_dcd_free(ctx); return -1;
    }

    word32 spki_sz = 3072;
    int ret = wc_GetSubjectPubKeyInfoDerFromCert(ica_der, (word32)ica_der_sz,
                                                  spki_buf, &spki_sz);
    vPortFree(ica_der);   /* no longer needed */
    if (ret != 0) {
        printf("[certbench] cham_dcd_prep: GetSubjectPubKeyInfoDer err=%d\n", ret);
        vPortFree(spki_buf);
        cham_dcd_free(ctx); return -1;
    }

    const uint8_t *rawKey = NULL; uint32_t rawKeySz = 0;
    if (bench_spki_raw_key(spki_buf, spki_sz, &rawKey, &rawKeySz) != 0) {
        printf("[certbench] cham_dcd_prep: bench_spki_raw_key failed\n");
        vPortFree(spki_buf);
        cham_dcd_free(ctx); return -1;
    }

    wc_dilithium_init(ctx->dkey);
    wc_dilithium_set_level(ctx->dkey, (byte)mldsa_level);
    ret = wc_dilithium_import_public(rawKey, rawKeySz, ctx->dkey);
    vPortFree(spki_buf);  /* no longer needed */
    if (ret != 0) {
        printf("[certbench] cham_dcd_prep: import_public err=%d\n", ret);
        cham_dcd_free(ctx); return -1;
    }

    ctx->ok = 1;
    printf("[certbench] cham_dcd_prep: OK tbs=%lu sig=%lu level=%d\n",
           (unsigned long)ctx->tbs_len, (unsigned long)ctx->sig_len,
           mldsa_level);
    return 0;
}

typedef enum { KIND_STD, KIND_CHAM, KIND_COMP, KIND_REL, KIND_DUAL } ChainKind;

typedef struct {
    const char *name;        /* output label + tls_get_scenario_ca key */
    ChainKind   kind;
    const char *dl1;         /* primary cert_data_server GET name */
    const char *dl2;         /* KIND_REL/DUAL: MLDSA chain;  else NULL */
    const char *dl3;         /* KIND_REL: MLDSA related cert; else NULL */
    int         mldsa_level; /* KIND_CHAM only: 2=mldsa44, 3=mldsa65, 5=mldsa87 */
} ChainEntry;

static const ChainEntry g_chain_entries[] = {
    /* DUAL/RELATED first: access fresh heap before other scenarios fragment it */
    { "DUAL_L1",      KIND_DUAL, "ECDSA_L1",    "MLDSA_L1", NULL,  0 },
    { "DUAL_L3",      KIND_DUAL, "ECDSA_L3",    "MLDSA_L3", NULL,  0 },
    { "DUAL_L5",      KIND_DUAL, "ECDSA_L5",    "MLDSA_L5", NULL,  0 },
    /* RELATED: MLDSA_Lx leaf IS the Related cert (signed by PQ ICA in MLDSA_Lx[1]) */
    { "RELATED_L1",   KIND_REL,  "ECDSA_L1",    "MLDSA_L1", NULL,  0 },
    { "RELATED_L3",   KIND_REL,  "ECDSA_L3",    "MLDSA_L3", NULL,  0 },
    { "RELATED_L5",   KIND_REL,  "ECDSA_L5",    "MLDSA_L5", NULL,  0 },
    { "ECDSA_L1",     KIND_STD,  "ECDSA_L1",    NULL,       NULL,  0 },
    { "ECDSA_L3",     KIND_STD,  "ECDSA_L3",    NULL,       NULL,  0 },
    { "ECDSA_L5",     KIND_STD,  "ECDSA_L5",    NULL,       NULL,  0 },
    { "MLDSA_L1",     KIND_STD,  "MLDSA_L1",    NULL,       NULL,  0 },
    { "MLDSA_L3",     KIND_STD,  "MLDSA_L3",    NULL,       NULL,  0 },
    { "MLDSA_L5",     KIND_STD,  "MLDSA_L5",    NULL,       NULL,  0 },
    /* CHAMELEON: 3-cert PEM chain: leaf(ECDSA+DCD) + Classic ICA + PQ ICA
     *   Chain A: Classic Root CA → Classic ICA (p1[1]) → leaf (p1[0])
     *   Chain B: PQ Root CA → PQ ICA (p1[2])
     *   Chain C: DCD – parse DCD from leaf, reconstruct Delta TBS,
     *            verify ML-DSA sig using PQ ICA public key          */
    { "CHAMELEON_L1", KIND_CHAM, "CHAMELEON_L1",NULL,       NULL,  2 },
    { "CHAMELEON_L3", KIND_CHAM, "CHAMELEON_L3",NULL,       NULL,  3 },
    { "CHAMELEON_L5", KIND_CHAM, "CHAMELEON_L5",NULL,       NULL,  5 },
    { "CATALYST_L1",  KIND_STD,  "CATALYST_L1", NULL,       NULL,  0 },
    { "CATALYST_L3",  KIND_STD,  "CATALYST_L3", NULL,       NULL,  0 },
    { "CATALYST_L5",  KIND_STD,  "CATALYST_L5", NULL,       NULL,  0 },
    { "COMPOSITE_L1", KIND_STD,  "COMPOSITE_L1",NULL,       NULL,  0 },
    { "COMPOSITE_L3", KIND_STD,  "COMPOSITE_L3",NULL,       NULL,  0 },
    { "COMPOSITE_L5", KIND_STD,  "COMPOSITE_L5",NULL,       NULL,  0 },
};
#define CHAIN_ENTRY_COUNT (sizeof(g_chain_entries)/sizeof(g_chain_entries[0]))

/* --- Split DER chain into individual SEQUENCE blocks --- */
static int split_der_certs(const uint8_t *buf, uint32_t sz,
                             const uint8_t **parts, uint32_t *sizes, int max_n)
{
    int n = 0;
    const uint8_t *p = buf, *end = buf + sz;
    while (n < max_n && p < end && p[0] == 0x30) {
        const uint8_t *start = p++;
        if (p >= end) break;
        uint32_t clen;
        if (*p & 0x80) {
            int ll = (*p++) & 0x7F;
            if (p + ll > end) break;
            clen = 0;
            while (ll--) clen = (clen << 8) | *p++;
        } else {
            clen = *p++;
        }
        uint32_t total = (uint32_t)(p - start) + clen;
        if (start + total > end) break;
        parts[n] = start; sizes[n] = total; n++;
        p = start + total;
    }
    return n;
}

/* --- Split PEM buffer into individual cert blocks (up to max_n) --- */
static int split_pem_certs(const uint8_t *buf, uint32_t sz,
                             const uint8_t **parts, uint32_t *sizes, int max_n)
{
    static const char B[] = "-----BEGIN CERTIFICATE-----";
    static const char E[] = "-----END CERTIFICATE-----";
    const size_t bl = sizeof(B)-1, el = sizeof(E)-1;
    int n = 0;
    const uint8_t *p = buf, *end = buf + sz;
    while (n < max_n && p + bl <= end) {
        const uint8_t *bp = NULL;
        for (const uint8_t *q = p; q + bl <= end; q++)
            if (memcmp(q, B, bl) == 0) { bp = q; break; }
        if (!bp) break;
        const uint8_t *ep = NULL;
        for (const uint8_t *q = bp + bl; q + el <= end; q++)
            if (memcmp(q, E, el) == 0) { ep = q + el; break; }
        if (!ep) break;
        while (ep < end && (*ep == '\n' || *ep == '\r')) ep++;
        parts[n] = bp; sizes[n] = (uint32_t)(ep - bp); n++;
        p = ep;
    }
    return n;
}

/*
 * Connect to cert_data_server, download one cert chain, return heap buffer.
 * Returns NULL on failure.  Caller must vPortFree().
 */
static uint8_t *download_chain(const char *name, uint32_t *out_size)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(CERT_DATA_PORT);
    inet_aton(TLS_SERVER_IP, &addr.sin_addr);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct timeval tv = { .tv_sec = RECV_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd); return NULL;
    }

    char req[64];
    int rlen = snprintf(req, sizeof(req), "GET %s\n", name);
    send(fd, req, rlen, 0);

    uint8_t lenbuf[4];
    if (recv(fd, lenbuf, 4, MSG_WAITALL) != 4) { close(fd); return NULL; }
    uint32_t total = ((uint32_t)lenbuf[0] << 24) | ((uint32_t)lenbuf[1] << 16)
                   | ((uint32_t)lenbuf[2] <<  8) |  (uint32_t)lenbuf[3];
    if (total == 0) { close(fd); return NULL; }

    uint8_t *buf = (uint8_t *)pvPortMalloc(total + 1);
    if (!buf) { close(fd); return NULL; }

    uint32_t received = 0;
    while (received < total) {
        int n = recv(fd, buf + received, total - received, 0);
        if (n <= 0) break;
        received += (uint32_t)n;
    }
    close(fd);

    if (received != total) { vPortFree(buf); return NULL; }
    buf[total] = '\0';
    *out_size = total;
    return buf;
}

/*
 * Fixed timestamp for cert date validation.
 * Certs issued 2026-02-06, valid until 2036-02-04.
 * 2026-04-03 00:00:00 UTC ≈ 1775174400
 */
static time_t bench_time_cb(time_t *t)
{
    time_t ts = (time_t)1775174400UL;
    if (t) *t = ts;
    return ts;
}

/*
 * Step-by-step chain verification:
 *   1. Create CM, load root_ca as trust anchor
 *   2. For each interm[i]: verify against CM, then load as CA
 *   3. Verify leaf against CM (which now includes all intermediates)
 * Returns number of verification errors (0 = all OK).
 */
static int chain_verify_step(
    const uint8_t *root_ca,    uint32_t root_ca_sz,
    const uint8_t **interm,    uint32_t *interm_sz, int n_interm, int interm_ft,
    const uint8_t  *leaf,      uint32_t  leaf_sz,                 int leaf_ft)
{
    WOLFSSL_CERT_MANAGER *cm = wolfSSL_CertManagerNew();
    if (!cm) return 1;
    int errs = 0;

    wolfSSL_CertManagerLoadCABuffer(cm,
        (const unsigned char *)root_ca, (long)root_ca_sz, WOLFSSL_FILETYPE_PEM);

    for (int i = 0; i < n_interm; i++) {
        if (wolfSSL_CertManagerVerifyBuffer(cm,
                interm[i], (long)interm_sz[i], interm_ft) != WOLFSSL_SUCCESS)
            errs++;
        wolfSSL_CertManagerLoadCABuffer(cm,
            interm[i], (long)interm_sz[i], interm_ft);
    }

    if (wolfSSL_CertManagerVerifyBuffer(cm,
            leaf, (long)leaf_sz, leaf_ft) != WOLFSSL_SUCCESS)
        errs++;

    wolfSSL_CertManagerFree(cm);
    return errs;
}

static void phase_chain_verify(void)
{
    printf("\n[certbench] === Phase 4: Cert Chain Verification ===\n");

    wolfSSL_Init();
    wc_SetTimeCb(bench_time_cb);

    for (size_t idx = 0; idx < CHAIN_ENTRY_COUNT; idx++) {
        const ChainEntry *e = &g_chain_entries[idx];

        /* Get root CA(s) */
        const char   *ca1 = NULL, *ca2 = NULL;
        unsigned int  ca1_sz = 0,  ca2_sz = 0;
        tls_get_scenario_ca(e->name, &ca1, &ca1_sz, &ca2, &ca2_sz);
        if (!ca1) {
            printf("[certbench] chain %-12s  no CA\n", e->name);
            continue;
        }

        /* Download cert buffers (not timed) */
        uint32_t sz1 = 0, sz2 = 0, sz3 = 0;
        uint8_t *buf1 = download_chain(e->dl1, &sz1);
        uint8_t *buf2 = e->dl2 ? download_chain(e->dl2, &sz2) : NULL;
        uint8_t *buf3 = e->dl3 ? download_chain(e->dl3, &sz3) : NULL;

        if (!buf1 || (e->dl2 && !buf2) || (e->dl3 && !buf3)) {
            printf("[certbench] chain %-12s  download failed\n", e->name);
            if (buf1) vPortFree(buf1);
            if (buf2) vPortFree(buf2);
            if (buf3) vPortFree(buf3);
            continue;
        }

        /* Split cert buffers */
        const uint8_t *p1[3]; uint32_t s1[3]; int n1 = 0;
        const uint8_t *p2[3]; uint32_t s2[3]; int n2 = 0;
        const uint8_t *p3[2]; uint32_t s3[2]; (void)p3; (void)s3;

        if (e->kind == KIND_COMP)
            n1 = split_der_certs(buf1, sz1, p1, s1, 3);
        else
            n1 = split_pem_certs(buf1, sz1, p1, s1, 3);

        if (buf2) n2 = split_pem_certs(buf2, sz2, p2, s2, 3);
        if (buf3) split_pem_certs(buf3, sz3, p3, s3, 2);

        /* Validate we got enough certs */
        int ok = 1;
        if (e->kind == KIND_CHAM && n1 < 3)
            { printf("[certbench] chain %-12s  split failed cham (n=%d)\n", e->name, n1); ok = 0; }
        else if ((e->kind == KIND_REL || e->kind == KIND_DUAL) && (n1 < 2 || n2 < 2))
            { printf("[certbench] chain %-12s  split failed (n1=%d n2=%d)\n",
                     e->name, n1, n2); ok = 0; }
        else if (e->kind != KIND_REL && e->kind != KIND_DUAL && e->kind != KIND_CHAM && n1 < 2)
            { printf("[certbench] chain %-12s  split failed (n=%d)\n", e->name, n1); ok = 0; }
        if (!ok) { vPortFree(buf1); if (buf2) vPortFree(buf2); if (buf3) vPortFree(buf3); continue; }

        /* KIND_CHAM: prepare DCD context before timing loop
         * (DER conversion, DCD parsing, Delta TBS reconstruction, key import) */
        ChamDcdCtx cham_dcd;
        memset(&cham_dcd, 0, sizeof(cham_dcd));
        if (e->kind == KIND_CHAM) {
            cham_dcd_prep(&cham_dcd,
                          p1[0], s1[0],   /* Chameleon leaf cert PEM */
                          p1[2], s1[2],   /* PQ ICA cert PEM         */
                          e->mldsa_level);
        }

        /* Time N iterations — per-iteration */
        int errs = 0;
        uint32_t iter_ms[N_CHAIN_VERIFY];

        for (int rep = 0; rep < N_CHAIN_VERIFY; rep++) {
            uint32_t t0 = HAL_GetTick();

            if (e->kind == KIND_STD) {
                /*
                 * Standard 2-cert PEM chain:
                 *   root CA → ICA (p1[1]) → leaf (p1[0])
                 */
                errs += chain_verify_step(
                    (const uint8_t *)ca1, ca1_sz,
                    &p1[1], &s1[1], 1, WOLFSSL_FILETYPE_PEM,
                    p1[0], s1[0], WOLFSSL_FILETYPE_PEM);
            }
            else if (e->kind == KIND_CHAM) {
                /*
                 * Chameleon: three verification steps (no diagnostics in loop).
                 * Chain A: Classic Root CA → Classic ICA (p1[1]) → leaf (p1[0])
                 * Chain B: PQ Root CA → PQ ICA (p1[2])
                 * Chain C: DCD ML-DSA sig over reconstructed Delta TBSCertificate
                 */
                const uint8_t *ca_parts[2]; uint32_t ca_sizes[2];
                int n_ca = split_pem_certs((const uint8_t *)ca1, ca1_sz,
                                           ca_parts, ca_sizes, 2);

                errs += chain_verify_step(
                    ca_parts[0], ca_sizes[0],
                    &p1[1], &s1[1], 1, WOLFSSL_FILETYPE_PEM,
                    p1[0], s1[0], WOLFSSL_FILETYPE_PEM);

                if (n_ca >= 2) {
                    errs += chain_verify_step(
                        ca_parts[1], ca_sizes[1],
                        NULL, NULL, 0, WOLFSSL_FILETYPE_PEM,
                        p1[2], s1[2], WOLFSSL_FILETYPE_PEM);
                }

                if (cham_dcd.ok) {
                    int res = 0;
                    int dret = wc_dilithium_verify_ctx_msg(
                            cham_dcd.sig, cham_dcd.sig_len,
                            NULL, 0,
                            cham_dcd.tbs, cham_dcd.tbs_len,
                            &res, cham_dcd.dkey);
                    if (dret != 0 || res != 1) errs++;
                } else {
                    errs++;
                }
            }
            else if (e->kind == KIND_COMP) {
                /*
                 * 2-cert DER chain (Composite):
                 *   root CA → ICA (p1[1] DER) → leaf (p1[0] DER)
                 */
                errs += chain_verify_step(
                    (const uint8_t *)ca1, ca1_sz,
                    &p1[1], &s1[1], 1, WOLFSSL_FILETYPE_ASN1,
                    p1[0], s1[0], WOLFSSL_FILETYPE_ASN1);
            }
            else if (e->kind == KIND_REL) {
                /*
                 * Related Certificate: two independent trust chains.
                 * MLDSA_Lx leaf (p2[0]) IS the Related cert (Server ML-DSA Cert).
                 *
                 * Chain A (ECDSA): ca1 → ICA ECDSA (p1[1]) → Server ECDSA (p1[0])
                 * Chain B (ML-DSA): ca2 → ICA ML-DSA (p2[1]) → Server ML-DSA/Related (p2[0])
                 *
                 * Note: the RelatedCertificate extension hash-binding check
                 * (Server ECDSA cert hash in Server ML-DSA cert extension) is
                 * performed at the TLS layer (tls_client.c), not here.
                 */
                errs += chain_verify_step(
                    (const uint8_t *)ca1, ca1_sz,
                    &p1[1], &s1[1], 1, WOLFSSL_FILETYPE_PEM,
                    p1[0], s1[0], WOLFSSL_FILETYPE_PEM);

                errs += chain_verify_step(
                    (const uint8_t *)ca2, ca2_sz,
                    &p2[1], &s2[1], 1, WOLFSSL_FILETYPE_PEM,
                    p2[0], s2[0], WOLFSSL_FILETYPE_PEM);
            }
            else if (e->kind == KIND_DUAL) {
                /*
                 * Dual Certificate: two independent complete chains.
                 *
                 * Chain A (ECDSA): ca1 → ECDSA ICA (p1[1]) → ECDSA leaf (p1[0])
                 * Chain B (MLDSA): ca2 → MLDSA ICA (p2[1]) → MLDSA leaf (p2[0])
                 */
                errs += chain_verify_step(
                    (const uint8_t *)ca1, ca1_sz,
                    &p1[1], &s1[1], 1, WOLFSSL_FILETYPE_PEM,
                    p1[0], s1[0], WOLFSSL_FILETYPE_PEM);

                errs += chain_verify_step(
                    (const uint8_t *)ca2, ca2_sz,
                    &p2[1], &s2[1], 1, WOLFSSL_FILETYPE_PEM,
                    p2[0], s2[0], WOLFSSL_FILETYPE_PEM);
            }
            iter_ms[rep] = HAL_GetTick() - t0;
        }

        float cm, cs, cci;
        compute_stats(iter_ms, N_CHAIN_VERIFY, &cm, &cs, &cci);
        printf("[certbench] chain %-12s  n=%d  mean=%6.1f  sd=%.1f  95ci=%.1f ms  err=%d\n",
               e->name, N_CHAIN_VERIFY, cm, cs, cci, errs);

        /* KIND_CHAM: release DCD context */
        if (e->kind == KIND_CHAM)
            cham_dcd_free(&cham_dcd);

        vPortFree(buf1);
        if (buf2) vPortFree(buf2);
        if (buf3) vPortFree(buf3);
        osDelay(50);
    }
}

/* ================================================================
 * FreeRTOS task entry point
 * ================================================================ */
void cert_bench_task(void *argument)
{
    (void)argument;

    /* Wait for DHCP */
    printf("[certbench] Waiting for DHCP...\n");
    while (gnetif.ip_addr.addr == 0) {
        osDelay(500);
    }
    printf("[certbench] DHCP ready: %lu.%lu.%lu.%lu\n",
           (gnetif.ip_addr.addr >>  0) & 0xFF,
           (gnetif.ip_addr.addr >>  8) & 0xFF,
           (gnetif.ip_addr.addr >> 16) & 0xFF,
           (gnetif.ip_addr.addr >> 24) & 0xFF);

    osDelay(1000); /* let desktop server start */

    printf("\n[certbench] ==========================================\n");
    printf("[certbench]  Certificate Benchmark (STM32 @ 168 MHz)\n");
    printf("[certbench]  Heap free=%lu  min_ever=%lu\n",
           (unsigned long)xPortGetFreeHeapSize(),
           (unsigned long)xPortGetMinimumEverFreeHeapSize());
    printf("[certbench] ==========================================\n");

    phase_recv();
    phase_ecdsa();
    phase_mldsa();
    phase_chain_verify();

    printf("\n[certbench] ==========================================\n");
    printf("[certbench] Heap free=%lu  min_ever=%lu\n",
           (unsigned long)xPortGetFreeHeapSize(),
           (unsigned long)xPortGetMinimumEverFreeHeapSize());
    printf("[certbench] DONE\n");
    printf("[certbench] ==========================================\n");

    for (;;) osDelay(10000);
}
